#!/usr/bin/env python3
"""
btccore.py - the Bitcoin and cryptography core of paperwallet.py and paperseed.py.

Everything that decides which private key, mnemonic, address or encrypted key
ends up on paper is in this file, and nothing else is: no PDF, no graphics, no
translations, no file output. Besides the Python standard library it uses
only what Debian ships: libsecp256k1 (Bitcoin Core's elliptic curve library,
through ctypes), python3-mnemonic (the BIP39 reference implementation) and
pycryptodome (AES for BIP38). Base58, bech32 and BIP32 are written out here.
Audit this file first.

  1. Network kill switch   sockets and name resolution disabled at import
  2. Networks              mainnet / testnet / signet parameters
  3. Entropy -> secrets    /dev/random or user entropy, SHA-256, range check
  4. Keys and addresses    secp256k1, hash160, base58check, bech32; WIF
                           (compressed), P2WPKH, P2PKH (BIP38 only)
  5. BIP38                 non-EC-multiplied encryption, scrypt + AES-256
  6. BIP39 / BIP32         mnemonics, seeds, derivation paths, xpubs, SeedQR
  7. Vanity search         key = k0 + i, searched on public points only

Error messages are plain English, marked with N_() so that the user
interface can translate them when it prints them; this module never
prints anything and never sees a translation.
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import mmap
import os
import random
import signal
import socket
import string
import unicodedata


def N_(message):
    """Mark a message for translation without translating it here."""
    return message


# =============================================================================
# 1. Network kill switch. Installed before importing third-party libraries,
#    so that nothing in this process can open a socket.
# =============================================================================


def _network_disabled(*_args, **_kwargs):
    raise RuntimeError("network access is disabled in this program")


class _NoSocket(socket.socket):
    # Still a class, so modules that subclass socket.socket keep importing.
    def __init__(self, *args, **kwargs):
        _network_disabled()


def disable_network():
    """Make socket creation and name resolution raise for the whole process."""
    socket.socket = _NoSocket
    for name in ("create_connection", "getaddrinfo", "gethostbyname",
                 "gethostbyname_ex", "socketpair", "fromfd"):
        if hasattr(socket, name):
            setattr(socket, name, _network_disabled)


disable_network()

try:
    from Cryptodome.Cipher import AES  # noqa: E402  (Debian's python3-pycryptodome)
    from Cryptodome.Hash import RIPEMD160  # noqa: E402
except ModuleNotFoundError:
    from Crypto.Cipher import AES  # noqa: E402  (pycryptodome from pip)
    from Crypto.Hash import RIPEMD160  # noqa: E402
from mnemonic import Mnemonic  # noqa: E402  (python3-mnemonic)

# =============================================================================
# 2. Networks
# =============================================================================

# Version bytes and prefixes. xpub/zpub are BIP32 / SLIP-132 versions (on the
# test networks tpub and vpub).
NETWORKS = {
    "main": {"wif": 0x80, "p2pkh": 0x00, "bech32": "bc", "xpub": "0488b21e", "zpub": "04b24746"},
    "test": {"wif": 0xEF, "p2pkh": 0x6F, "bech32": "tb", "xpub": "043587cf", "zpub": "045f1cf6"},
}
# --network choice -> parameters. testnet and signet share keys and
# addresses (tb1q..., WIF starting with c); only the coins differ.
NETWORK_NAMES = {"main": "main", "testnet": "test", "signet": "test"}
NETWORK_NAME = "main"
NETWORK = NETWORKS["main"]


def set_network(name):
    global NETWORK, NETWORK_NAME
    NETWORK_NAME, NETWORK = name, NETWORKS[NETWORK_NAMES[name]]


def is_test_network():
    return NETWORK_NAME != "main"


def address_prefix():
    """'bc1q' on mainnet, 'tb1q' on testnet and signet."""
    return NETWORK["bech32"] + "1q"


# =============================================================================
# 3. Entropy -> secrets
# =============================================================================

# Order of the secp256k1 group: a private key k is valid iff 1 <= k < N.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

ENTROPY_BYTES = 32


def read_system_random(n=ENTROPY_BYTES):
    """Read exactly n bytes from /dev/random (blocks until the pool is ready)."""
    out = bytearray()
    fd = os.open("/dev/random", os.O_RDONLY)
    try:
        while len(out) < n:
            chunk = os.read(fd, n - len(out))
            if not chunk:
                raise OSError(N_("short read from /dev/random"))
            out += chunk
    finally:
        os.close(fd)
    return out


def is_valid_secret(secret):
    """True if the 32-byte big-endian integer is a valid secp256k1 private key."""
    if len(secret) != 32:
        return False
    k = int.from_bytes(secret, "big")
    return 1 <= k < SECP256K1_N


def secret_from_entropy(entropy):
    """SHA-256 the entropy and check that the digest is a valid secp256k1 scalar."""
    secret = hashlib.sha256(bytes(entropy)).digest()
    if not is_valid_secret(secret):
        raise ValueError(N_("SHA-256 of the entropy is not a valid secp256k1 private key"))
    return secret


def wipe(buf):
    """Best-effort zeroing of a mutable buffer (Python cannot wipe immutable bytes)."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


# Separators ignored when recognising dice rolls, coin flips, digits or hex.
ENTROPY_SEPARATORS = set(" \t\r\n,;:-_./|")


def hex_digits(data):
    """The hex digits of the input if, separators and an optional 0x apart,
    it consists only of hexadecimal digits (e.g. 16-sided dice); else None."""
    try:
        text = bytes(data).decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if text[:2].lower() == "0x":
        text = text[2:]
    digits = "".join(ch for ch in text if ch not in ENTROPY_SEPARATORS).lower()
    if digits and all(ch in string.hexdigits for ch in digits):
        return digits
    return None


def normalize_entropy(data):
    """Bytes actually hashed: an all-hex input is taken as a hexadecimal number
    (case, separators and line breaks do not matter; an odd number of digits
    gets a leading 0), anything else is used as is. Returns (bytes, digits)
    where digits is the hex string, or None if the input was not hex."""
    digits = hex_digits(data)
    if digits is None:
        return bytearray(data), None
    return bytearray(bytes.fromhex(digits.rjust(len(digits) + len(digits) % 2, "0"))), digits


def wallet_entropy(entropy, index):
    """Entropy of the index-th wallet (0-based): the user entropy itself for the
    first one, the entropy followed by the 4-byte big-endian index otherwise."""
    return bytes(entropy) if index == 0 else bytes(entropy) + index.to_bytes(4, "big")


def derive_secrets(entropy, count=1):
    """count private keys. With user entropy (already normalised, see
    normalize_entropy) key i is SHA-256(wallet_entropy(entropy, i)); without,
    each key is SHA-256 of 32 fresh bytes from /dev/random."""
    if entropy:
        return [secret_from_entropy(wallet_entropy(entropy, i)) for i in range(count)]
    secrets = []
    while len(secrets) < count:  # an invalid digest has probability ~2^-128: retry
        raw = read_system_random()
        try:
            secret = hashlib.sha256(bytes(raw)).digest()
        finally:
            wipe(raw)
        if is_valid_secret(secret):
            secrets.append(secret)
    return secrets


# =============================================================================
# 4. Keys and addresses
# =============================================================================

# --- secp256k1: libsecp256k1 through ctypes --------------------------------
# A public key is handled as libsecp256k1's opaque 64-byte secp256k1_pubkey
# and turned into SEC bytes (33 compressed, 65 uncompressed) only when needed.

SECP256K1_LIBRARIES = ("libsecp256k1.so.6", "libsecp256k1.so.5", "libsecp256k1.so.2",
                       "libsecp256k1.so.1", "libsecp256k1.so.0", "libsecp256k1.so")
SECP256K1_CONTEXT = 0x0301  # sign | verify: needed by libsecp256k1 < 0.2, ignored later
SECP256K1_EC_COMPRESSED = 0x0102
SECP256K1_EC_UNCOMPRESSED = 0x0002


def _load_secp256k1():
    lib = None
    for name in SECP256K1_LIBRARIES:
        try:
            lib = ctypes.CDLL(name)
            break
        except OSError:
            continue
    else:  # not Debian: let ctypes search (it may run ldconfig)
        name = ctypes.util.find_library("secp256k1")
        try:
            lib = ctypes.CDLL(name) if name else None
        except OSError:
            pass
    if lib is None:
        raise ModuleNotFoundError(N_("libsecp256k1 not found"), name="libsecp256k1")
    vp, cp, size = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t
    for function, argtypes in (("context_create", [ctypes.c_uint]),
                               ("context_randomize", [vp, cp]),
                               ("ec_pubkey_create", [vp, cp, cp]),
                               ("ec_pubkey_parse", [vp, cp, cp, size]),
                               ("ec_pubkey_serialize", [vp, cp, ctypes.POINTER(size), cp, ctypes.c_uint]),
                               ("ec_pubkey_combine", [vp, cp, ctypes.POINTER(cp), size])):
        f = getattr(lib, "secp256k1_" + function)
        f.argtypes, f.restype = argtypes, (vp if function == "context_create" else ctypes.c_int)
    ctx = lib.secp256k1_context_create(SECP256K1_CONTEXT)
    # Blinding against side channels (fresh randomness, not key material).
    if not ctx or lib.secp256k1_context_randomize(ctx, os.urandom(32)) != 1:
        raise RuntimeError(N_("libsecp256k1 initialisation failed"))
    return lib, ctx


_SECP, _CTX = _load_secp256k1()


def _pubkey_create(secret):
    out = ctypes.create_string_buffer(64)
    if not is_valid_secret(secret) or _SECP.secp256k1_ec_pubkey_create(_CTX, out, bytes(secret)) != 1:
        raise ValueError(N_("invalid private key"))
    return out.raw


def _pubkey_parse(sec):
    out = ctypes.create_string_buffer(64)
    if _SECP.secp256k1_ec_pubkey_parse(_CTX, out, sec, len(sec)) != 1:
        raise ValueError(N_("invalid public key"))
    return out.raw


def _pubkey_serialize(pub, compressed=True):
    out, size = ctypes.create_string_buffer(65), ctypes.c_size_t(65)
    flags = SECP256K1_EC_COMPRESSED if compressed else SECP256K1_EC_UNCOMPRESSED
    _SECP.secp256k1_ec_pubkey_serialize(_CTX, out, ctypes.byref(size), pub, flags)
    return out.raw[:size.value]


def _pubkey_combine(a, b):
    """Point addition a + b (fails only if the sum is the point at infinity)."""
    out = ctypes.create_string_buffer(64)
    if _SECP.secp256k1_ec_pubkey_combine(_CTX, out, (ctypes.c_char_p * 2)(a, b), 2) != 1:
        raise ValueError(N_("invalid public key"))
    return out.raw


def _point_walk(pub_sec, start, step):
    """Compressed SEC bytes of P + start*G, P + (start+step)*G, ... for the
    public key P = pub_sec: the hot loop of the vanity search, which reuses
    its buffers instead of allocating them at every step."""
    point = _pubkey_parse(pub_sec)
    if start:
        point = _pubkey_combine(point, _pubkey_create(start.to_bytes(32, "big")))
    cur, nxt = ctypes.create_string_buffer(point, 64), ctypes.create_string_buffer(64)
    step_point = ctypes.create_string_buffer(_pubkey_create(step.to_bytes(32, "big")), 64)
    cp = ctypes.c_char_p
    cur_args = (cp * 2)(ctypes.cast(cur, cp), ctypes.cast(step_point, cp))  # cur + step -> nxt
    nxt_args = (cp * 2)(ctypes.cast(nxt, cp), ctypes.cast(step_point, cp))  # nxt + step -> cur
    out, size = ctypes.create_string_buffer(33), ctypes.c_size_t(33)
    serialize, combine = _SECP.secp256k1_ec_pubkey_serialize, _SECP.secp256k1_ec_pubkey_combine
    while True:
        size.value = 33
        serialize(_CTX, out, ctypes.byref(size), cur, SECP256K1_EC_COMPRESSED)
        yield out.raw
        if combine(_CTX, nxt, cur_args, 2) != 1:
            raise ValueError(N_("invalid public key"))
        cur, nxt, cur_args, nxt_args = nxt, cur, nxt_args, cur_args


def public_key(secret, compressed=True):
    """SEC-encoded public key k*G of a 32-byte secret."""
    return _pubkey_serialize(_pubkey_create(secret), compressed)


# --- hashes and encodings ---------------------------------------------------

def _sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _ripemd160_hashlib(data):
    return hashlib.new("ripemd160", data).digest()


def _ripemd160_pycryptodome(data):
    return RIPEMD160.new(data).digest()


try:  # OpenSSL 3 offers RIPEMD-160 only with its legacy provider
    hashlib.new("ripemd160")
    _ripemd160 = _ripemd160_hashlib
except ValueError:
    _ripemd160 = _ripemd160_pycryptodome


def hash160(data):
    return _ripemd160(hashlib.sha256(data).digest())


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(payload):
    data = bytes(payload) + _sha256d(bytes(payload))[:4]
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = BASE58_ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def base58check_decode(text):
    """Payload of a base58check string; raises ValueError if malformed."""
    n = 0
    for ch in text:
        if ch not in BASE58_ALPHABET:
            raise ValueError(N_("invalid base58 character"))
        n = n * 58 + BASE58_ALPHABET.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    data = b"\0" * (len(text) - len(text.lstrip("1"))) + body
    if len(data) < 4 or _sha256d(data[:-4])[:4] != data[-4:]:
        raise ValueError(N_("invalid base58 checksum"))
    return data[:-4]


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= BECH32_GENERATOR[i] if (top >> i) & 1 else 0
    return chk


def segwit_v0_address(program):
    """BIP173 bech32 address of a version 0 witness program (20 bytes: P2WPKH)."""
    hrp = NETWORK["bech32"]
    acc, bits, data = 0, 0, [0]  # witness version 0, then the program in 5-bit groups
    for byte in program:
        acc, bits = acc << 8 | byte, bits + 8
        while bits >= 5:
            bits -= 5
            data.append(acc >> bits & 31)
    if bits:
        data.append(acc << (5 - bits) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [polymod >> 5 * (5 - i) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


# --- keys and addresses -----------------------------------------------------

def wif_compressed(secret):
    """WIF with the 'compressed public key' suffix (mainnet: K or L, test networks: c)."""
    if not is_valid_secret(secret):
        raise ValueError(N_("invalid private key"))
    return base58check_encode(bytes([NETWORK["wif"]]) + bytes(secret) + b"\x01")


def secret_from_wif(wif):
    """(secret, compressed) of a WIF of the current network; raises ValueError."""
    raw = base58check_decode(wif)
    if raw[:1] != bytes([NETWORK["wif"]]) or len(raw) not in (33, 34) or (len(raw) == 34 and raw[33] != 1):
        raise ValueError(N_("not a WIF private key of this network"))
    secret = raw[1:33]
    if not is_valid_secret(secret):
        raise ValueError(N_("invalid private key"))
    return secret, len(raw) == 34


def p2wpkh_address(secret):
    """Native SegWit v0 address (bc1q..., tb1q... on test networks) of the compressed public key."""
    return segwit_v0_address(hash160(public_key(secret, True)))


def p2pkh_address(secret, compressed=True):
    """Legacy address, needed only for the BIP38 address hash."""
    return base58check_encode(bytes([NETWORK["p2pkh"]]) + hash160(public_key(secret, compressed)))


# =============================================================================
# 5. BIP38 (non EC-multiplied mode)
# =============================================================================

# BIP38 (non EC-multiplied) constants.
BIP38_PREFIX = b"\x01\x42"
BIP38_FLAG_COMPRESSED = 0xE0
BIP38_FLAG_UNCOMPRESSED = 0xC0
BIP38_SCRYPT = dict(n=16384, r=8, p=8, dklen=64, maxmem=64 * 1024 * 1024)


def _bip38_passphrase(password):
    # BIP38 mandates Unicode NFC normalisation before UTF-8 encoding.
    return unicodedata.normalize("NFC", password).encode("utf-8")


def _bip38_address_hash(secret, compressed):
    # BIP38 hashes the legacy P2PKH address (that is what every BIP38
    # implementation checks), even though the wallet is used as P2WPKH.
    addr = p2pkh_address(secret, compressed).encode("ascii")
    return hashlib.sha256(hashlib.sha256(addr).digest()).digest()[:4]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def bip38_encrypt(secret, password, compressed=True):
    """Encrypt a private key with a password; returns a '6P...' string."""
    if not is_valid_secret(secret):
        raise ValueError(N_("invalid private key"))
    addresshash = _bip38_address_hash(secret, compressed)
    derived = hashlib.scrypt(_bip38_passphrase(password), salt=addresshash, **BIP38_SCRYPT)
    half1, half2 = derived[:32], derived[32:]
    # AES-256-ECB over two independent 16-byte blocks, exactly as in BIP38.
    encrypted = AES.new(half2, AES.MODE_ECB).encrypt(_xor(secret, half1))
    flag = BIP38_FLAG_COMPRESSED if compressed else BIP38_FLAG_UNCOMPRESSED
    return base58check_encode(BIP38_PREFIX + bytes([flag]) + addresshash + encrypted)


def is_bip38(text):
    """True if text is a well-formed non-EC-multiplied BIP38 key. Only the
    password can tell whether it belongs to a given address."""
    try:
        raw = base58check_decode(text)
    except ValueError:
        return False
    return (len(raw) == 39 and raw[:2] == BIP38_PREFIX
            and raw[2] in (BIP38_FLAG_COMPRESSED, BIP38_FLAG_UNCOMPRESSED))


def bip38_decrypt(encrypted_key, password):
    """Decrypt a '6P...' key; returns (secret, compressed). Raises on a wrong password."""
    raw = base58check_decode(encrypted_key)
    if len(raw) != 39 or raw[:2] != BIP38_PREFIX:
        raise ValueError(N_("not a non-EC-multiplied BIP38 key"))
    flag = raw[2]
    if flag not in (BIP38_FLAG_COMPRESSED, BIP38_FLAG_UNCOMPRESSED):
        raise ValueError(N_("unsupported BIP38 flag byte"))
    compressed = flag == BIP38_FLAG_COMPRESSED
    addresshash, encrypted = raw[3:7], raw[7:39]
    derived = hashlib.scrypt(_bip38_passphrase(password), salt=addresshash, **BIP38_SCRYPT)
    half1, half2 = derived[:32], derived[32:]
    secret = _xor(AES.new(half2, AES.MODE_ECB).decrypt(encrypted), half1)
    if not is_valid_secret(secret) or _bip38_address_hash(secret, compressed) != addresshash:
        raise ValueError(N_("wrong password (BIP38 address hash mismatch)"))
    return secret, compressed


# =============================================================================
# 6. BIP39 mnemonics and BIP32 derivation
# =============================================================================

HARDENED = 0x80000000
BIP39_ENTROPY = {12: 16, 24: 32}  # words -> bytes of entropy
PAPER_PATH_LEVELS = 4  # random hardened levels of a --gift path: 4 x 31 = 124 bits
GIFT_PURPOSE = 184  # unassigned BIP43 purpose: a tree no wallet scans and no account key reaches
BIP39 = Mnemonic("english")


def mnemonic_from_secret(secret, words=24):
    """BIP39 mnemonic whose entropy is the first 16 (12 words) or all 32 bytes
    (24 words) of a secret from derive_secrets()."""
    return BIP39.to_mnemonic(bytes(secret[:BIP39_ENTROPY[words]]))


def check_mnemonic(mnemonic):
    """Normalised mnemonic (lower case, single spaces); raises if a word or
    the checksum is wrong."""
    words = " ".join(unicodedata.normalize("NFKD", mnemonic).lower().split())
    if len(words.split()) not in BIP39_ENTROPY or not BIP39.check(words):
        raise ValueError(N_("invalid BIP39 mnemonic (unknown word, wrong length or checksum)"))
    return words


def mnemonic_entropy(mnemonic):
    """The entropy bytes a mnemonic encodes."""
    return bytes(BIP39.to_entropy(check_mnemonic(mnemonic)))


class HDKey:
    """A BIP32 extended private key."""
    __slots__ = ("secret", "chain_code", "depth", "parent_fingerprint", "child_number")

    def __init__(self, secret, chain_code, depth=0, parent_fingerprint=b"\0" * 4, child_number=0):
        if not is_valid_secret(secret):
            raise ValueError(N_("invalid BIP32 key (probability 2^-127: use another index)"))
        self.secret, self.chain_code = bytes(secret), bytes(chain_code)
        self.depth, self.parent_fingerprint, self.child_number = depth, parent_fingerprint, child_number

    def fingerprint(self):
        return hash160(public_key(self.secret))[:4]

    def child(self, index):
        """BIP32 CKDpriv: hardened (index >= 2^31) from the private key, else from the public key."""
        data = (b"\0" + self.secret) if index >= HARDENED else public_key(self.secret)
        digest = hmac.new(self.chain_code, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        if tweak >= SECP256K1_N:
            raise ValueError(N_("invalid BIP32 key (probability 2^-127: use another index)"))
        k = (tweak + int.from_bytes(self.secret, "big")) % SECP256K1_N
        return HDKey(k.to_bytes(32, "big"), digest[32:], self.depth + 1, self.fingerprint(), index)

    def derive(self, indices):
        key = self
        for index in indices:
            key = key.child(index)
        return key


def seed_root(mnemonic, passphrase=""):
    """BIP32 root key of a mnemonic and optional BIP39 passphrase."""
    seed = Mnemonic.to_seed(check_mnemonic(mnemonic), passphrase=passphrase)
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return HDKey(digest[:32], digest[32:])


def fingerprint(root):
    """Master key fingerprint (8 hex digits), as wallets show it."""
    return root.fingerprint().hex()


def coin_type():
    return 0 if NETWORK_NAME == "main" else 1


def default_account_path():
    """BIP84 (native SegWit) account 0 of the current network."""
    return f"m/84'/{coin_type()}'/0'"


def gift_root():
    """Root of the gift tree, m/184': outside every BIP44/49/84/86 account,
    so wallets never discover its keys and an account xprv cannot derive
    them (only the master seed can)."""
    return f"m/{GIFT_PURPOSE}'"


def parse_path(path):
    """Indices of a derivation path like m/84'/0'/0' (h or ' for hardened)."""
    parts = path.strip().split("/")
    if parts[0] != "m":
        raise ValueError(N_("a derivation path starts with m/"))
    indices = []
    for part in parts[1:]:
        hardened = part[-1:] in ("'", "h", "H")
        digits = part[:-1] if hardened else part
        if not digits.isdigit() or int(digits) >= HARDENED:
            raise ValueError(N_("invalid derivation path"))
        indices.append(int(digits) + (HARDENED if hardened else 0))
    return indices


def format_path(indices):
    return "m" + "".join(f"/{i - HARDENED}'" if i >= HARDENED else f"/{i}" for i in indices)


def derived_secret(root, path):
    """Private key (32 bytes) at a derivation path."""
    secret = root.derive(parse_path(path)).secret
    if not is_valid_secret(secret):
        raise RuntimeError(N_("internal self-check failed (BIP32 derivation)"))
    return secret


def account_xpub(root, path):
    """Extended public key of an account, as zpub/vpub for BIP84 (purpose 84')
    paths and as xpub/tpub otherwise."""
    indices = parse_path(path)
    version = NETWORK["zpub"] if indices[:1] == [HARDENED + 84] else NETWORK["xpub"]
    key = root.derive(indices)
    return base58check_encode(bytes.fromhex(version) + bytes([key.depth]) + key.parent_fingerprint
                              + key.child_number.to_bytes(4, "big") + key.chain_code + public_key(key.secret))


def first_address(root, path):
    """P2WPKH address of the first receive key of an account (path/0/0)."""
    return p2wpkh_address(root.derive(parse_path(path) + [0, 0]).secret)


WALLET_PURPOSES = (44, 49, 84, 86)  # BIP44/49/84/86: the account trees wallets scan


def receive_path(account_path, index):
    """Path of the receive address number index of an account
    (account/0/index): the one any wallet restoring the seed finds."""
    if not 0 <= index < HARDENED:
        raise ValueError(N_("invalid derivation path"))
    return format_path(parse_path(account_path) + [0, index])


def is_wallet_path(path):
    """True for a path that wallets restoring a seed scan:
    m/purpose'/coin'/account'/change/index with a standard purpose."""
    indices = parse_path(path)
    return (len(indices) == 5 and all(i >= HARDENED for i in indices[:3])
            and indices[0] - HARDENED in WALLET_PURPOSES and indices[3] in (0, 1) and indices[4] < HARDENED)


def random_paper_path(account_path, rng=None):
    """account_path followed by PAPER_PATH_LEVELS random hardened indices
    (31 bits each, from the OS random source): reproducible from the seed by
    whoever has the path, unguessable by whoever has only the seed."""
    rng = rng or random.SystemRandom()
    return format_path(parse_path(account_path)
                       + [HARDENED + rng.randrange(HARDENED) for _i in range(PAPER_PATH_LEVELS)])


def seedqr_digits(mnemonic):
    """Standard SeedQR payload: the 4-digit BIP39 index of every word."""
    return "".join(f"{BIP39.wordlist.index(w):04d}" for w in check_mnemonic(mnemonic).split())


# =============================================================================
# 7. Vanity search (CPU, multi-process)
#
# Starting from the derived key k0 (public key A = k0*G) we look for the
# smallest offset i such that the address of A + i*G starts with
# "bc1q<prefix>"; the final key is k0 + i mod n. The search loop only ever
# touches public points: the private key is added back in the parent process.
# Workers are fork()ed copies sharing one anonymous mmap (no files, no sockets,
# no pickling) in which each one records its first match.
# =============================================================================

VANITY_CHECK_EVERY = 1024


def _vanity_worker(pub_sec, prefix, start, step, slots, index):
    """Test offsets start, start+step, ... and store the first match in
    slots[index]. Stops once its offset passes the best match of any worker,
    so the overall result is the smallest matching offset whatever the number
    of workers (hence reproducible with user-supplied entropy)."""
    target = 0
    for ch in prefix:
        target = target << 5 | BECH32_CHARSET.index(ch)
    shift = 32 - 5 * len(prefix)
    points = _point_walk(pub_sec, start, step)
    offset = start
    while True:
        for _i in range(VANITY_CHECK_EVERY):
            digest = hash160(next(points))
            if int.from_bytes(digest[:4], "big") >> shift == target:
                slots[index] = offset
                return
            offset += step
        found = [v for v in slots if v >= 0]
        if found and offset > min(found):
            return


def vanity_search(secret, prefix, jobs=1):
    """Return (secret + i mod n, i) for the smallest i giving bc1q<prefix> (tb1q on test networks)."""
    pub_sec = public_key(secret)
    jobs = max(1, jobs)
    shared = mmap.mmap(-1, 8 * jobs)  # anonymous, MAP_SHARED: visible to forked workers
    slots = memoryview(shared).cast("q")
    for i in range(jobs):
        slots[i] = -1
    try:
        if jobs == 1:
            _vanity_worker(pub_sec, prefix, 0, 1, slots, 0)
        else:
            _run_workers(pub_sec, prefix, jobs, slots)
        offset = min(v for v in slots if v >= 0)
    finally:
        slots.release()
        shared.close()
    k = (int.from_bytes(secret, "big") + offset) % SECP256K1_N
    found = k.to_bytes(32, "big")
    if not is_valid_secret(found) or not p2wpkh_address(found).startswith(address_prefix() + prefix):
        raise RuntimeError(N_("internal self-check failed (vanity search)"))
    return found, offset


def _run_workers(pub_sec, prefix, jobs, slots):
    pids = []
    try:
        for index in range(jobs):
            pid = os.fork()
            if pid == 0:  # child: search, then leave without running any cleanup
                code = 1
                try:
                    _vanity_worker(pub_sec, prefix, index, jobs, slots, index)
                    code = 0
                finally:
                    os._exit(code)
            pids.append(pid)
        failed = False
        while pids:
            _pid, status = os.waitpid(pids.pop(0), 0)
            failed |= os.waitstatus_to_exitcode(status) != 0
        if failed:
            raise RuntimeError(N_("vanity search worker failed"))
    finally:
        for pid in pids:  # only left on error or Ctrl-C
            try:
                os.kill(pid, signal.SIGTERM)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
