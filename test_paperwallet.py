"""
Tests for btccore.py, paperlib.py, paperwallet.py and paperseed.py.

The address is recomputed *independently* of btccore (pure-Python secp256k1,
hash160 and the BIP173 reference bech32 encoder), and BIP38 is checked against
the official test vectors and by decrypting the keys printed in the PDF.

Run with:  python -m pytest -q
"""

import ast
import hashlib
import hmac
import os
import random
import re
import shutil
import string
import subprocess
import sys
import unicodedata

import pytest
from pypdf import PdfReader

import btccore
import paperlib
import paperwallet as pw

# ---------------------------------------------------------------------------
# Independent reference implementation (does not use btccore for key math)
# ---------------------------------------------------------------------------

P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def ec_mul(k, point=G):
    result = None
    while k:
        if k & 1:
            result = ec_add(result, point)
        point = ec_add(point, point)
        k >>= 1
    return result


def hash160(data):
    try:
        rip = hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()
    except ValueError:  # OpenSSL 3 without the legacy provider
        try:
            from Cryptodome.Hash import RIPEMD160
        except ModuleNotFoundError:
            from Crypto.Hash import RIPEMD160
        rip = RIPEMD160.new(hashlib.sha256(data).digest()).digest()
    return rip


def b58check_decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    payload, check = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == check
    return payload


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def segwit_v0_address(hrp, program):
    acc, bits, data = 0, 0, [0]
    for b in program:  # 8-bit -> 5-bit groups
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[d] for d in data + checksum)


def address_from_wif(wif):
    """Recompute the bc1q (or tb1q) address from a compressed WIF, without btccore."""
    payload = b58check_decode(wif)
    assert payload[0] in (0x80, 0xEF) and len(payload) == 34 and payload[33] == 0x01
    k = int.from_bytes(payload[1:33], "big")
    x, y = ec_mul(k)
    pub = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return segwit_v0_address("bc" if payload[0] == 0x80 else "tb", hash160(pub))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# Official BIP38 vectors: "No compression, no EC multiply" is not used by this
# tool, the "Compression, no EC multiply" ones are.
BIP38_VECTORS = [
    ("TestingOneTwoThree",
     "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
     "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP"),
    ("Satoshi",
     "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
     "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"),
]


@pytest.mark.parametrize("password,encrypted,wif", BIP38_VECTORS)
def test_bip38_official_vectors(password, encrypted, wif):
    secret = b58check_decode(wif)[1:33]
    assert pw.bip38_encrypt(secret, password) == encrypted
    assert pw.bip38_decrypt(encrypted, password) == (secret, True)


def test_bip38_wrong_password():
    _, encrypted, _ = BIP38_VECTORS[0]
    with pytest.raises(ValueError):
        pw.bip38_decrypt(encrypted, "wrong password")


def test_secret_validity_bounds():
    n = pw.SECP256K1_N
    assert not pw.is_valid_secret(bytes(32))
    assert pw.is_valid_secret((1).to_bytes(32, "big"))
    assert pw.is_valid_secret((n - 1).to_bytes(32, "big"))
    assert not pw.is_valid_secret(n.to_bytes(32, "big"))
    assert not pw.is_valid_secret(b"\xff" * 32)


def test_address_recomputed_independently():
    entropy = b"some fixed test entropy"
    secret = pw.secret_from_entropy(entropy)
    assert secret == hashlib.sha256(entropy).digest()
    wif = pw.wif_compressed(secret)
    assert wif[0] in "KL"
    assert b58check_decode(wif)[1:33] == secret
    address = pw.p2wpkh_address(secret)
    assert address.startswith("bc1q") and len(address) == 42
    assert address_from_wif(wif) == address


def test_random_entropy_path(monkeypatch):
    # No entropy given -> 32 bytes from /dev/random, then SHA-256.
    monkeypatch.setattr(btccore, "read_system_random", lambda n=32: bytearray(b"\x07" * n))
    args = pw.parse_args([])
    secrets, estimate = pw.generate_secrets(args)
    assert estimate is None
    assert secrets == [hashlib.sha256(b"\x07" * 32).digest()]


def test_user_entropy_per_wallet():
    args = pw.parse_args(["--entropy-string", "dice 3 5 1 6"])
    secrets, estimate = pw.generate_secrets(args, 3)
    assert estimate is not None
    assert secrets[0] == hashlib.sha256(b"dice 3 5 1 6").digest()
    assert secrets[2] == hashlib.sha256(b"dice 3 5 1 6" + (2).to_bytes(4, "big")).digest()
    assert len(set(secrets)) == 3


def _pdf_text(path):
    """(front pages, back pages) text with all whitespace removed (keys are
    printed in groups); sheets alternate front and back pages."""
    reader = PdfReader(path)
    pages = [re.sub(r"\s+", "", page.extract_text()) for page in reader.pages]
    return ("|".join(pages[0::2]), "|".join(pages[1::2])), reader


def printed(text, data):
    """How many strips print data: each shows it once as grouped text and as
    many whole times as fit in the ring around its QR code."""
    per_side = int(pw.QR_SIZE / (0.6 * pw.RING_PT * pw.PT) + 1e-9)
    ring = max(1, (4 * per_side + 1) // (len(data) + 1))
    return text.count(data) / (1 + ring)


def test_pdf_plain(tmp_path, capsys):
    ent = tmp_path / "entropy.bin"
    ent.write_bytes(b"plain wallet entropy")
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-file", str(ent), "-o", str(out)]) == 0

    secret = hashlib.sha256(b"plain wallet entropy").digest()
    wif, address = pw.wif_compressed(secret), pw.p2wpkh_address(secret)
    (front, back), reader = _pdf_text(out)
    assert len(reader.pages) == 2
    for page in reader.pages:  # A4 portrait
        assert round(float(page.mediabox.width)) == 595 and round(float(page.mediabox.height)) == 842
    assert printed(front, address) == 2 and wif not in front  # default: 2 copies
    assert printed(back, wif) == 2
    assert address_from_wif(wif) == address
    assert (out.stat().st_mode & 0o777) == 0o600

    console = capsys.readouterr()
    assert wif not in console.out + console.err
    assert address in console.out


def test_pdf_encrypted_decrypts(tmp_path, monkeypatch, capsys):
    password = "correct horse battery staple"
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": password)
    ent = tmp_path / "entropy.bin"
    ent.write_bytes(b"encrypted wallet entropy")
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-file", str(ent), "--bip38", "-o", str(out)]) == 0

    (front, back), _ = _pdf_text(out)
    encrypted = re.findall(r"6P[1-9A-HJ-NP-Za-km-z]{56}", back)
    # Remove the 6P keys first so the WIF pattern cannot match inside them.
    wifs = re.findall(r"[KL][1-9A-HJ-NP-Za-km-z]{51}", re.sub(r"6P[1-9A-HJ-NP-Za-km-z]{56}", "|", back))
    assert len(set(wifs)) == 1 and len(set(encrypted)) == 1  # 2 copies: one plain, one BIP38
    assert printed(back, wifs[0]) == 1 and printed(back, encrypted[0]) == 1

    # Decrypt the BIP38 key read back from the PDF and recompute the address.
    secret, compressed = pw.bip38_decrypt(encrypted[0], password)
    assert compressed
    assert pw.wif_compressed(secret) == wifs[0]
    address = address_from_wif(wifs[0])
    assert printed(front, address) == 2

    console = capsys.readouterr()
    for secret_text in (wifs[0], encrypted[0], password):
        assert secret_text not in console.out + console.err


def test_password_mismatch(tmp_path, monkeypatch):
    answers = iter(["first password", "second password"])
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": next(answers))
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "x", "--bip38", "-o", str(out)]) == 1
    assert not out.exists()


def test_existing_output_gets_numbered_name(tmp_path, capsys):
    out = tmp_path / "wallet.pdf"
    out.write_bytes(b"existing")
    (tmp_path / "wallet_01.pdf").write_bytes(b"existing too")
    assert pw.main(["--lang", "en", "--entropy-string", "x", "-o", str(out)]) == 0
    assert out.read_bytes() == b"existing"
    assert (tmp_path / "wallet_01.pdf").read_bytes() == b"existing too"
    new = tmp_path / "wallet_02.pdf"
    assert new.read_bytes().startswith(b"%PDF") and (new.stat().st_mode & 0o777) == 0o600
    console = capsys.readouterr()
    assert "writing " + str(new) in console.err and "written: " + str(new) in console.out


def test_numbered_name_is_chosen_before_prompts(tmp_path, monkeypatch, capsys):
    out = tmp_path / "wallet.pdf"
    out.write_bytes(b"existing")

    def prompt(prompt=""):
        assert "wallet_01.pdf" in capsys.readouterr().err  # said before asking anything
        return "the entropy"
    monkeypatch.setattr(pw.getpass, "getpass", prompt)
    assert pw.main(["--lang", "en", "--entropy-prompt", "-o", str(out)]) == 0
    assert (tmp_path / "wallet_01.pdf").exists()


def test_name_without_extension_is_not_a_clash(tmp_path, capsys):
    assert pw.main(["--lang", "en", "--entropy-string", "x", "-o", str(tmp_path / "wallet")]) == 0
    assert "already exists" not in capsys.readouterr().err
    assert (tmp_path / "wallet.pdf").exists() and (tmp_path / "wallet.md").exists()


def test_write_outputs_skips_a_name_taken_meanwhile(tmp_path):
    out = tmp_path / "w.pdf"
    (tmp_path / "w.md").write_bytes(b"raced")  # appeared after free_output() had chosen it
    assert pw.write_outputs(str(out), b"%PDF", "# md") == [str(tmp_path / "w_01.pdf"), str(tmp_path / "w_01.md")]
    assert (tmp_path / "w.md").read_bytes() == b"raced" and not out.exists()


def test_force_overwrites(tmp_path):
    out = tmp_path / "wallet.pdf"
    out.write_bytes(b"existing")
    out.chmod(0o644)
    assert pw.main(["--entropy-string", "x", "--force", "-o", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF") and (out.stat().st_mode & 0o777) == 0o600
    assert not (tmp_path / "wallet_01.pdf").exists()


def test_network_is_disabled():
    import socket
    with pytest.raises(RuntimeError):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(RuntimeError):
        socket.socket()


# ---------------------------------------------------------------------------
# Localisation
# ---------------------------------------------------------------------------

SOURCES = ["btccore.py", "paperlib.py", "paperwallet.py", "paperseed.py"]


def _source_msgids():
    """Every literal passed to _() or N_() in the sources (what xgettext would extract)."""
    ids = set()
    for name in SOURCES:
        tree = ast.parse(open(os.path.join(os.path.dirname(pw.__file__), name), encoding="utf-8").read())
        ids |= {node.args[0].value for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("_", "N_") and node.args and isinstance(node.args[0], ast.Constant)}
    return ids


def _placeholders(text):
    return {field for _lit, field, _spec, _conv in string.Formatter().parse(text) if field}


def test_italian_catalog_matches_source():
    catalog = pw.load_po(pw.po_path("it"))
    msgids = _source_msgids()
    assert msgids - catalog.keys() == set(), "untranslated strings"
    assert catalog.keys() - msgids == set(), "obsolete entries in the .po"
    for msgid, msgstr in catalog.items():
        assert msgstr.strip(), msgid
        assert _placeholders(msgid) == _placeholders(msgstr), msgid


@pytest.mark.skipif(not shutil.which("msgfmt"), reason="msgfmt (Debian package 'gettext') not installed")
def test_po_passes_msgfmt_check():
    subprocess.run(["msgfmt", "--check", "-o", "/dev/null", pw.po_path("it")], check=True)


@pytest.mark.parametrize("env,expected", [
    ({"LANG": "it_IT.UTF-8"}, "it"),
    ({"LANG": "en_US.UTF-8"}, "en"),
    ({"LANG": "de_DE.UTF-8"}, "en"),          # unsupported -> English
    ({"LANG": "C"}, "en"),
    ({}, "en"),
    ({"LC_ALL": "it_CH.UTF-8", "LANG": "en_GB"}, "it"),
    ({"LC_MESSAGES": "it_IT@euro", "LANG": "en_US"}, "it"),
    ({"LANGUAGE": "fr:it", "LANG": "en_US"}, "it"),
    ({"LANGUAGE": "en", "LC_ALL": "it_IT.UTF-8"}, "en"),
])
def test_detect_language(env, expected):
    assert pw.detect_language(env) == expected


LANG_MARKERS = {
    "en": ("BITCOINADDRESS", "PRIVATEKEY", "address:"),
    "it": ("INDIRIZZOBITCOIN", "CHIAVEPRIVATA", "indirizzo:"),
}


@pytest.mark.parametrize("lang", pw.LANGUAGES)
def test_pdf_language_option(tmp_path, capsys, lang):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "lang test", "--lang", lang, "-o", str(out)]) == 0
    (front, back), _reader = _pdf_text(out)
    front_marker, back_marker, console_marker = LANG_MARKERS[lang]
    other = LANG_MARKERS["it" if lang == "en" else "en"]
    assert front_marker in front and other[0] not in front
    assert back_marker in back and other[1] not in back
    assert console_marker in capsys.readouterr().out


def test_default_language_follows_locale(tmp_path, monkeypatch, capsys):
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LANG", "it_IT.UTF-8")
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "locale test", "-o", str(out)]) == 0
    (front, _back), _reader = _pdf_text(out)
    assert "INDIRIZZOBITCOIN" in front
    assert "indirizzo:" in capsys.readouterr().out
    # Errors are localised too.
    assert pw.main(["--wallets", "2", "--vanity", "a,c,d", "-o", str(tmp_path / "x.pdf")]) == 1
    assert capsys.readouterr().err.splitlines()[-1].startswith("errore:")


# ---------------------------------------------------------------------------
# Entropy estimate of user input
# ---------------------------------------------------------------------------

def _dice(n, seed):
    rng = random.Random(seed)  # deterministic test data, not key material
    return " ".join(str(rng.randint(1, 6)) for _i in range(n)).encode()


@pytest.mark.parametrize("data,kind,low,high", [
    (_dice(100, 1), "dice", 256, 259),
    (_dice(99, 2), "dice", 250, 256),
    (b"0123456789abcdef" * 4, "hex", 0, 256),     # repetitive: capped by compression
    (bytes(range(32)).hex().encode(), "hex", 255, 257),
    (b"correct horse battery staple", "words", 40, 60),
    (b"Tr0ub4dor&3", "text", 0, 80),
    (b"1" * 300, "coins", 0, 120),
    (b"", "bytes", 0, 0),
])
def test_estimate_entropy(data, kind, low, high):
    estimate = pw.estimate_entropy(data)
    assert estimate.kind == kind
    assert low <= estimate.bits <= high


def test_estimate_random_bytes_not_penalised():
    data = hashlib.sha256(b"a").digest() + hashlib.sha256(b"b").digest()  # 64 random-looking bytes
    estimate = pw.estimate_entropy(data[:32])
    assert estimate.kind == "bytes" and estimate.bits == 256


def test_weak_entropy_warning(tmp_path, capsys):
    out = tmp_path / "weak.pdf"
    assert pw.main(["--lang", "en", "--entropy-string", "my secret phrase", "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "less than 256" in err and "words" in err
    assert "my secret phrase" not in err


def test_strong_entropy_no_warning(tmp_path, capsys):
    out = tmp_path / "strong.pdf"
    dice = tmp_path / "dice.txt"
    dice.write_bytes(_dice(120, 3))
    assert pw.main(["--lang", "en", "--entropy-file", str(dice), "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "less than 256" not in err
    # The final reminder still tells how much entropy was estimated (120 d6 rolls).
    assert err.splitlines()[-1].endswith("(at most ~310 bits, dice rolls)")


@pytest.mark.parametrize("data,digits", [
    (b"A3 f0 9C", "a3f09c"),
    (b"0xdeadBEEF\n", "deadbeef"),
    (b"a3:f0-9c\n12", "a3f09c12"),
    (b"3 1 6 2 5", "31625"),
    (b"hello", None),
    ("caffè".encode(), None),
])
def test_hex_digits(data, digits):
    assert pw.hex_digits(data) == digits


def test_hex_entropy_is_decoded_and_format_independent():
    hex_text = bytes(range(32)).hex()
    spaced = " ".join(hex_text.upper()[i:i + 4] for i in range(0, 64, 4)) + "\n"
    expected = hashlib.sha256(bytes(range(32))).digest()
    for text in (hex_text, spaced, "0x" + hex_text):
        secrets, estimate = pw.generate_secrets(pw.parse_args(["--entropy-string", text]))
        assert secrets == [expected]
        assert estimate.kind == "hex" and estimate.bits == 256
    # Odd number of digits: a leading zero is added before decoding.
    secrets, _estimate = pw.generate_secrets(pw.parse_args(["--entropy-string", "abc"]))
    assert secrets == [hashlib.sha256(bytes.fromhex("0abc")).digest()]


def test_hex_entropy_is_reported(tmp_path, capsys):
    out = tmp_path / "hex.pdf"
    assert pw.main(["--lang", "en", "--entropy-string", bytes(range(32)).hex(), "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "hexadecimal number: 64 digits, 32 bytes" in err
    assert "less than 256" not in err


def test_d6_rolls_decoded_as_hex_but_estimated_as_dice(tmp_path, capsys):
    # 64 rolls of a 6-sided die are valid hex digits too: decoded as hex,
    # but the warning uses the d6 estimate (~165 bits), not 4 bits per digit.
    rolls = _dice(64, 4)
    out = tmp_path / "d6.pdf"
    dice = tmp_path / "d6.txt"
    dice.write_bytes(rolls)
    assert pw.main(["--lang", "en", "--entropy-file", str(dice), "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "hexadecimal number: 64 digits" in err
    assert "less than 256" in err and "dice rolls" in err


# ---------------------------------------------------------------------------
# Several wallets per sheet
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("wallets,copies,encrypt,expected", [
    (1, 2, False, [(0, 0, 2, False), (0, 1, 2, False)]),
    (1, 2, True, [(0, 0, 2, False), (0, 1, 2, True)]),
    (1, 4, True, [(0, 0, 4, False), (0, 1, 4, False), (0, 2, 4, True), (0, 3, 4, True)]),
    (2, 1, True, [(0, 0, 1, True), (1, 0, 1, True)]),
    (3, 1, False, [(0, 0, 1, False), (1, 0, 1, False), (2, 0, 1, False)]),
])
def test_strip_plan(wallets, copies, encrypt, expected):
    assert pw.strip_plan(wallets, copies, encrypt) == expected


WIF_RE = r"[KL][1-9A-HJ-NP-Za-km-z]{51}"
BIP38_RE = r"6P[1-9A-HJ-NP-Za-km-z]{56}"
ADDR_RE = r"bc1q[02-9ac-hj-np-z]{38}"


def test_pdf_four_wallets(tmp_path, capsys):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "four wallets", "--wallets", "4", "-o", str(out)]) == 0
    (front, back), _reader = _pdf_text(out)
    addresses = re.findall(ADDR_RE, front)
    wifs = re.findall(WIF_RE, back)
    assert len(set(addresses)) == 4 and len(set(wifs)) == 4
    # Each key, recomputed independently, matches one of the printed addresses.
    assert {address_from_wif(w) for w in wifs} == set(addresses)
    console = capsys.readouterr().out
    assert all(a in console for a in addresses)
    assert not any(w in console for w in wifs)


def test_pdf_three_wallets_encrypted(tmp_path, monkeypatch):
    password = "three wallets password"
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": password)
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "three", "--wallets", "3", "--bip38", "-o", str(out)]) == 0
    (front, back), _reader = _pdf_text(out)
    addresses = set(re.findall(ADDR_RE, front))
    encrypted = re.findall(BIP38_RE, back)
    wifs = re.findall(WIF_RE, re.sub(BIP38_RE, "|", back))
    assert len(addresses) == 3
    assert len(set(wifs)) == 3 and len(set(encrypted)) == 3  # each wallet: one plain, one BIP38
    decrypted = {pw.p2wpkh_address(pw.bip38_decrypt(e, password)[0]) for e in encrypted}
    assert decrypted == addresses
    assert {address_from_wif(w) for w in wifs} == addresses


def test_pdf_copies_and_sheets(tmp_path, capsys):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--lang", "en", "--entropy-string", "copies", "--copies", "3", "-o", str(out)]) == 0
    (front, back), reader = _pdf_text(out)
    assert len(reader.pages) == 4  # 3 strips: 2 sheets, front and back each
    wif = re.findall(WIF_RE, back)
    assert len(set(wif)) == 1 and printed(back, wif[0]) == 3
    assert printed(front, address_from_wif(wif[0])) == 3
    assert "A4sheets:2" in capsys.readouterr().out.replace(" ", "")


@pytest.mark.parametrize("copies", ["0", "9"])
def test_copies_out_of_range(tmp_path, copies):
    with pytest.raises(SystemExit):
        pw.main(["--copies", copies, "-o", str(tmp_path / "wallet.pdf")])


def _folded(panel, v, g=None):
    """Height on the back side once folded, simulating the three folds one
    after the other (independent of Geometry.folded)."""
    folds = (g or pw.CARD).folds
    if panel == 4:  # fold 1: P4 up onto P3
        v = 2 * folds[1] - v
    if panel in (3, 4):  # fold 2: P3 and P4 up onto P2
        v = 2 * folds[2] - v
    if panel == 1:  # fold 3: P1 down over the stack
        v = 2 * folds[3] - v
    return v


def test_card_sizes():
    assert pw.STRIP_H == 211.5 and pw.PANEL_H[1] == pw.PANEL_H[2] == 54.0  # ID-1 card
    assert pw.CARD.width == 85.6 and pw.CARD.per_sheet == 2
    assert pw.WIDE.width == 148.0 and pw.WIDE.per_sheet == 1
    for g in (pw.CARD, pw.WIDE):  # strips and margins fit on A4
        assert g.origin_x > 10 and g.origin_y > 25


@pytest.mark.parametrize("g", [pw.CARD, pw.WIDE], ids=["card", "wide"])
def test_folding_geometry(g):
    card = (g.panel_y[2], g.panel_y[2] + g.panel_h[2])
    for panel in (1, 3, 4):  # every panel lands on P2, the inner ones a bit short of it
        ends = sorted(_folded(panel, g.panel_y[panel] + e, g) for e in (0, g.panel_h[panel]))
        assert card[0] <= ends[0] and ends[1] <= card[1]
        assert (ends[0], ends[1]) == card if panel == 1 else ends[1] - ends[0] < card[1] - card[0]


@pytest.mark.parametrize("g", [pw.CARD, pw.WIDE], ids=["card", "wide"])
@pytest.mark.parametrize("panel", [1, 2, 3])
def test_decoys_lie_exactly_over_the_key(g, panel):
    dy, flip = g.decoy_offset(panel)
    for v in (0.0, 4.0, 17.3, 36.0, g.panel_h[4]):
        local = dy + flip * v
        assert 0 <= local <= g.panel_h[panel]  # inside its own panel
        assert _folded(panel, g.panel_y[panel] + local, g) == pytest.approx(_folded(4, v, g))


def test_decoy_faces_carry_no_text(tmp_path):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--lang", "en", "--entropy-string", "decoy", "--copies", "1", "-o", str(out)]) == 0
    (front, back), _reader = _pdf_text(out)
    # The key noise is drawn as paths, not text: the decoy faces only carry
    # their label, and the only key on the back is the real one.
    # Noise on the two faces touching the key, guides on the other inner faces.
    assert back.count("securitypattern·notakey") == 1 and front.count("securitypattern·notakey") == 1
    assert "HOWTOSPEND" in back and "HOWTOSTOREIT" in back
    assert len(set(re.findall(WIF_RE, back))) == 1


# ---------------------------------------------------------------------------
# Vanity search
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [("ac", "ac"), ("BC1QXY", "xy"), (" sun ", "sun")])
def test_parse_vanity(raw, expected):
    assert pw.parse_vanity(raw) == expected


@pytest.mark.parametrize("raw", ["", "bc1q", "abo", "1ab", "toolong", "ib"])
def test_parse_vanity_rejects(raw):
    with pytest.raises(ValueError):
        pw.parse_vanity(raw)


def test_vanity_search_is_smallest_offset_and_reproducible():
    secret = hashlib.sha256(b"vanity").digest()
    one, offset_one = pw.vanity_search(secret, "q9", jobs=1)
    many, offset_many = pw.vanity_search(secret, "q9", jobs=3)
    assert (one, offset_one) == (many, offset_many)
    k0 = int.from_bytes(secret, "big")
    assert int.from_bytes(one, "big") == (k0 + offset_one) % pw.SECP256K1_N
    wif = pw.wif_compressed(one)
    assert address_from_wif(wif).startswith("bc1qq9")
    # No smaller offset gives the prefix.
    for i in range(offset_one):
        k = ((k0 + i) % pw.SECP256K1_N).to_bytes(32, "big")
        assert not pw.p2wpkh_address(k).startswith("bc1qq9")


def test_pdf_vanity_per_wallet(tmp_path):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "vanity", "--wallets", "2", "--vanity", "ac,d",
                    "--jobs", "2", "-o", str(out)]) == 0
    (front, back), _reader = _pdf_text(out)
    addresses = re.findall(ADDR_RE, front)
    assert sorted({a[:5] for a in addresses}) == ["bc1qa", "bc1qd"]
    assert any(a.startswith("bc1qac") for a in addresses)
    assert {address_from_wif(w) for w in re.findall(WIF_RE, back)} == set(addresses)


def test_vanity_prefix_count_mismatch(tmp_path):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--wallets", "3", "--vanity", "a,c", "-o", str(out)]) == 1
    assert not out.exists()


# ---------------------------------------------------------------------------
# Artwork and fonts
# ---------------------------------------------------------------------------

def _pdf_resources(path):
    """Unique image XObjects and font BaseFont names used by the PDF pages."""
    images, fonts = set(), set()
    for page in PdfReader(path).pages:
        resources = page["/Resources"]
        for ref in resources["/XObject"].values():
            if ref.get_object()["/Subtype"] == "/Image":
                images.add(ref.idnum)
        for ref in resources["/Font"].values():
            fonts.add(str(ref.get_object()["/BaseFont"]))
    return images, fonts


def test_pdf_embeds_artwork_once(tmp_path):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "art", "-o", str(out)]) == 0
    images, fonts = _pdf_resources(out)
    assert len(images) == 1  # one JPEG shared by every face that shows it
    assert "/Courier-Bold" in fonts


def test_find_font_files(tmp_path):
    (tmp_path / "a").mkdir()
    for filename in ("OpenSans-Regular.ttf", "OpenSans-Bold.ttf"):
        (tmp_path / "a" / filename).write_bytes(b"")
    assert pw.find_font_files([str(tmp_path)]) is None  # Italic missing
    (tmp_path / "OpenSans-Italic.ttf").write_bytes(b"")
    found = pw.find_font_files([str(tmp_path), "/nonexistent"])
    assert found == {pw.SANS: str(tmp_path / "a" / "OpenSans-Regular.ttf"),
                     pw.SANS_BOLD: str(tmp_path / "a" / "OpenSans-Bold.ttf"),
                     pw.SANS_ITALIC: str(tmp_path / "OpenSans-Italic.ttf")}


@pytest.mark.skipif(pw.find_font_files() is None,
                    reason="Open Sans not installed (Debian package 'fonts-open-sans')")
def test_pdf_uses_installed_open_sans(tmp_path):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "font", "-o", str(out)]) == 0
    _images, fonts = _pdf_resources(out)
    assert any("OpenSans" in f for f in fonts)


def test_pdf_falls_back_to_helvetica(tmp_path):
    # Font registration is process-wide, so run the fallback in a fresh process.
    out = tmp_path / "wallet.pdf"
    code = ("import sys, paperlib, paperwallet as pw; paperlib.FONT_DIRS = []; "
            "sys.exit(pw.main(['--lang', 'en', '--entropy-string', 'x', '-o', sys.argv[1]]))")
    result = subprocess.run([sys.executable, "-c", code, str(out)], capture_output=True, text=True,
                            cwd=os.path.dirname(pw.__file__))
    assert result.returncode == 0, result.stderr
    assert "Open Sans not found" in result.stderr
    _images, fonts = _pdf_resources(out)
    assert "/Helvetica-Bold" in fonts and not any("OpenSans" in f for f in fonts)


# ---------------------------------------------------------------------------
# Test networks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("network", ["signet", "testnet"])
def test_test_network_pdf(tmp_path, monkeypatch, capsys, network):
    password = "test network password"
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": password)
    out = tmp_path / "wallet.pdf"
    try:
        assert pw.main(["--lang", "en", "--network", network, "--entropy-string", "signet",
                        "--bip38", "--vanity", "tb1qa", "-o", str(out)]) == 0
    finally:
        pw.set_network("main")
    (front, back), _reader = _pdf_text(out)
    wif = re.findall(r"c[1-9A-HJ-NP-Za-km-z]{51}", re.sub(BIP38_RE, "|", back))
    address = address_from_wif(wif[0])  # independent recomputation, tb1q
    assert address.startswith("tb1qa") and printed(front, address) == 2
    assert not re.search(ADDR_RE, front)  # no mainnet address anywhere
    # BIP38 works on the test network too (the address hash uses its P2PKH address).
    pw.set_network(network)
    try:
        secret, _c = pw.bip38_decrypt(re.findall(BIP38_RE, back)[0], password)
        assert pw.wif_compressed(secret) == wif[0]
    finally:
        pw.set_network("main")
    mark = network.upper() + "·NOVALUE"
    assert front.count(mark) >= 8 and back.count(mark) >= 8  # every panel
    console = capsys.readouterr()
    assert "the coins have no value" in console.err and address in console.out
    assert wif[0] not in console.out + console.err


def test_short_options():
    args = pw.parse_args(["-n", "signet", "-w", "3", "--bip38"])
    assert (args.network, args.wallets, args.encrypt) == ("signet", 3, True)
    assert not pw.parse_args([]).encrypt


def test_mainnet_is_the_default(tmp_path):
    out = tmp_path / "wallet.pdf"
    assert pw.main(["--entropy-string", "main", "-o", str(out)]) == 0
    (front, back), _reader = _pdf_text(out)
    assert re.search(ADDR_RE, front) and "NOVALUE" not in front + back


# ---------------------------------------------------------------------------
# btccore: isolation of the Bitcoin and cryptography code
# ---------------------------------------------------------------------------

def test_btccore_is_isolated():
    """The audited core imports no user interface code and prints nothing."""
    tree = ast.parse(open(btccore.__file__, encoding="utf-8").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    assert imported <= {"ctypes", "hashlib", "hmac", "mmap", "os", "random", "signal", "socket", "string",
                        "unicodedata", "Crypto", "Cryptodome", "mnemonic"}
    calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not calls & {"print", "open", "_", "input"}


# ---------------------------------------------------------------------------
# BIP39 / BIP32 (official BIP84 test vector)
# ---------------------------------------------------------------------------

BIP84_MNEMONIC = "abandon " * 11 + "about"


def test_bip84_vector():
    root = btccore.seed_root(BIP84_MNEMONIC)
    assert btccore.fingerprint(root) == "73c5da0a"
    assert btccore.account_xpub(root, "m/84'/0'/0'") == (
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
    assert btccore.first_address(root, "m/84'/0'/0'") == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    # The derived private key gives the same address with the independent implementation.
    secret = btccore.derived_secret(root, "m/84'/0'/0'/0/0")
    assert address_from_wif(btccore.wif_compressed(secret)) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_bip32_vector_1():
    seed = bytes(range(16))
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    root = btccore.HDKey(digest[:32], digest[32:])
    assert btccore.fingerprint(root) == "3442193e"
    assert btccore.account_xpub(root, "m/0'") == (
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
    assert btccore.account_xpub(root, "m/0'/1/2'/2/1000000000") == (  # non-hardened steps too
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")


def test_bip39_passphrase_is_nfkd_normalised():
    # BIP39: the passphrase is NFKD-normalised, so "è" typed as one character
    # (NFC, as keyboards do) or as e + accent (NFD) gives the same seed.
    nfc, nfd = "caffè", unicodedata.normalize("NFD", "caffè")
    assert nfc != nfd
    expected = hashlib.pbkdf2_hmac("sha512", BIP84_MNEMONIC.encode(),
                                   b"mnemonic" + unicodedata.normalize("NFKD", nfc).encode(), 2048)
    digest = hmac.new(b"Bitcoin seed", expected, hashlib.sha512).digest()
    for passphrase in (nfc, nfd):
        assert btccore.seed_root(BIP84_MNEMONIC, passphrase).secret == digest[:32]


def test_wif_and_base58():
    secret = bytes(31) + b"\x01"
    assert btccore.wif_compressed(secret) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    assert btccore.secret_from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn") == (secret, True)
    assert btccore.secret_from_wif("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf") == (secret, False)
    assert btccore.p2pkh_address(secret) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert btccore.p2pkh_address(secret, False) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
    assert btccore.base58check_decode(btccore.base58check_encode(b"\0\0abc")) == b"\0\0abc"
    bad = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWo"  # last character changed
    for text in (bad, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoW0", ""):
        with pytest.raises(ValueError):
            btccore.secret_from_wif(text)
    btccore.set_network("testnet")
    try:
        with pytest.raises(ValueError):  # a mainnet WIF on a test network
            btccore.secret_from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        assert btccore.p2wpkh_address(secret) == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    finally:
        btccore.set_network("main")


def test_seedqr_and_mnemonic_checks():
    assert btccore.seedqr_digits(BIP84_MNEMONIC) == "0000" * 11 + "0003"
    assert btccore.check_mnemonic("  Abandon " * 11 + "ABOUT ") == BIP84_MNEMONIC
    for bad in ("abandon " * 12, "abandon " * 11 + "bitcoinz", "abandon about"):
        with pytest.raises(ValueError):
            btccore.check_mnemonic(bad)


def test_derivation_paths():
    h = btccore.HARDENED
    assert btccore.parse_path("m/84'/0h/0'/1/2") == [h + 84, h, h, 1, 2]
    assert btccore.format_path([h + 84, h, h, 1, 2]) == "m/84'/0'/0'/1/2"
    for bad in ("84'/0'", "m/x", "m/2147483648", "m//1"):
        with pytest.raises(ValueError):
            btccore.parse_path(bad)
    path = btccore.random_paper_path("m/84'/0'/0'")
    indices = btccore.parse_path(path)
    assert indices[:3] == [h + 84, h, h] and len(indices) == 3 + btccore.PAPER_PATH_LEVELS
    assert all(i >= h for i in indices)  # all hardened: the account xpub cannot reach them
    assert btccore.random_paper_path("m/84'/0'/0'") != path
    assert btccore.receive_path("m/84'/0'/0'", 7) == "m/84'/0'/0'/0/7"
    assert btccore.is_wallet_path("m/84'/0'/0'/0/7") and btccore.is_wallet_path("m/44'/1'/3'/1/0")
    for other in (path, "m/184'/1'/2'/3'/4'", "m/84'/0'/0'/0'/7", "m/84'/0'/0'/2/7", "m/84'/0'/0'"):
        assert not btccore.is_wallet_path(other)


# ---------------------------------------------------------------------------
# paperseed.py and paperwallet.py --seed-file
# ---------------------------------------------------------------------------

import paperseed as ps  # noqa: E402


def _seed_file(tmp_path, monkeypatch, passphrase=None, extra=()):
    if passphrase:
        monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": passphrase)
    out = tmp_path / "seed"
    args = ["--lang", "en", "--entropy-string", "seed entropy for tests", "-o", str(out)] + list(extra)
    if passphrase:
        args.append("--passphrase")
    assert ps.main(args) == 0
    return tmp_path / "seed.pdf", tmp_path / "seed.md"


def test_mnemonic_pdf_and_markdown(tmp_path, monkeypatch, capsys):
    pdf, md = _seed_file(tmp_path, monkeypatch, passphrase="a long test passphrase")
    words = btccore.mnemonic_from_secret(hashlib.sha256(b"seed entropy for tests").digest(), 24)
    (front, back), reader = _pdf_text(pdf)
    assert len(reader.pages) == 4 and (pdf.stat().st_mode & 0o777) == 0o600  # one seed per sheet
    assert all(w in back for w in words.split()) and words.split()[0] not in front
    root = btccore.seed_root(words, "a long test passphrase")
    xpub = btccore.account_xpub(root, "m/84'/0'/0'")
    assert printed(front, xpub) == 2  # watch-only key outside, on both copies
    fields = dict(paperlib.md_fields(md.read_text()))
    assert fields["mnemonic"] == words and fields["fingerprint"] == btccore.fingerprint(root)
    assert fields["account xpub"] == xpub and fields["passphrase"].startswith("yes")
    assert (md.stat().st_mode & 0o777) == 0o600
    console = capsys.readouterr()
    for secret_text in (words.split()[3], "a long test passphrase"):
        assert secret_text not in console.out + console.err
    assert "a long test passphrase" not in md.read_text()
    assert xpub in console.out


def test_mnemonic_twelve_words_on_signet(tmp_path, monkeypatch):
    try:
        _pdf, md = _seed_file(tmp_path, monkeypatch, extra=["--words", "12", "-n", "signet"])
    finally:
        pw.set_network("main")
    fields = dict(paperlib.md_fields(md.read_text()))
    assert len(fields["mnemonic"].split()) == 12 and fields["network"] == "signet"
    assert fields["account path"] == "m/84'/1'/0'" and fields["account xpub"].startswith("vpub")
    assert fields["first address"].startswith("tb1q")


def test_paper_wallets_from_seed_and_rebuild(tmp_path, monkeypatch, capsys):
    _pdf, md = _seed_file(tmp_path, monkeypatch, passphrase="a long test passphrase")
    out = tmp_path / "paper"
    assert pw.main(["--lang", "en", "--seed-file", str(md), "-w", "2", "--bip38", "-o", str(out)]) == 0
    fields = paperlib.md_fields((tmp_path / "paper.md").read_text())
    paths = [v for k, v in fields if k == "path"]
    wifs = [v for k, v in fields if k == "wif"]
    addresses = [v for k, v in fields if k == "address"]
    assert paths == ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1"]  # the account's first receive addresses
    seed = dict(paperlib.md_fields(md.read_text()))
    assert addresses[0] == seed["first address"]
    root = btccore.seed_root(seed["mnemonic"], "a long test passphrase")
    for path, wif, address in zip(paths, wifs, addresses):
        assert btccore.wif_compressed(btccore.derived_secret(root, path)) == wif
        assert address_from_wif(wif) == address
    (front, back), _reader = _pdf_text(tmp_path / "paper.pdf")
    assert all(p in front for p in paths)  # printed outside, in small type
    assert "derivationpath·seed" in front and "ORIGINOFTHISKEY" in back and "Anywalletrestoring" in back
    console = capsys.readouterr()
    assert "a long test passphrase" not in console.err and "--index 2" in console.out

    # Rebuild the second wallet from the seed and its printed path.
    again = tmp_path / "again"
    assert pw.main(["--lang", "en", "--seed-file", str(md), "--path", paths[1], "-o", str(again)]) == 0
    rebuilt = paperlib.md_fields((tmp_path / "again.md").read_text())
    assert dict(rebuilt)["wif"] == wifs[1] and dict(rebuilt)["address"] == addresses[1]


def test_paper_wallet_from_seed_wrong_passphrase(tmp_path, monkeypatch, capsys):
    _pdf, md = _seed_file(tmp_path, monkeypatch, passphrase="the right passphrase")
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": "a wrong passphrase")
    assert pw.main(["--lang", "en", "--seed-file", str(md), "-o", str(tmp_path / "p")]) == 1
    assert "wrong passphrase" in capsys.readouterr().err
    assert not (tmp_path / "p.pdf").exists() and not (tmp_path / "p.md").exists()


@pytest.mark.parametrize("extra", [["--vanity", "ac"], ["--entropy-string", "x"]])
def test_seed_file_excludes_other_sources(tmp_path, extra):
    with pytest.raises(SystemExit):
        pw.parse_args(["--seed-file", str(tmp_path / "seed.md")] + extra)


def test_gift_paths_from_seed(tmp_path, monkeypatch):
    _pdf, md = _seed_file(tmp_path, monkeypatch)
    out = tmp_path / "gift"
    assert pw.main(["--lang", "en", "--seed-file", str(md), "--gift", "-w", "2", "-o", str(out)]) == 0
    fields = paperlib.md_fields((tmp_path / "gift.md").read_text())
    paths = [v for k, v in fields if k == "path"]
    h = btccore.HARDENED
    for path in paths:
        indices = btccore.parse_path(path)
        assert indices[0] == h + 184 and len(indices) == 1 + btccore.PAPER_PATH_LEVELS
        assert all(i >= h for i in indices)
    root = btccore.seed_root(dict(paperlib.md_fields(md.read_text()))["mnemonic"])
    wifs = [v for k, v in fields if k == "wif"]
    assert [btccore.wif_compressed(btccore.derived_secret(root, p)) for p in paths] == wifs
    (front, back), _reader = _pdf_text(tmp_path / "gift.pdf")
    assert all(p in front for p in paths)
    assert "Onlytheseedplus" in back and "Anywalletrestoring" not in back
    # Rebuilt like any other path.
    assert pw.main(["--lang", "en", "--seed-file", str(md), "--path", paths[0], "-o", str(tmp_path / "g2")]) == 0
    assert dict(paperlib.md_fields((tmp_path / "g2.md").read_text()))["wif"] == wifs[0]


def test_index_from_seed(tmp_path, monkeypatch):
    _pdf, md = _seed_file(tmp_path, monkeypatch)
    out = tmp_path / "next"
    assert pw.main(["--lang", "en", "--seed-file", str(md), "--index", "5", "-w", "3", "-o", str(out)]) == 0
    fields = paperlib.md_fields((tmp_path / "next.md").read_text())
    paths = [v for k, v in fields if k == "path"]
    assert paths == ["m/84'/0'/0'/0/5", "m/84'/0'/0'/0/6", "m/84'/0'/0'/0/7"]
    root = btccore.seed_root(dict(paperlib.md_fields(md.read_text()))["mnemonic"])
    wifs = [v for k, v in fields if k == "wif"]
    assert [btccore.wif_compressed(btccore.derived_secret(root, p)) for p in paths] == wifs


@pytest.mark.parametrize("argv", [["--index", "1"], ["--index", "-1", "--seed-file", "s.md"],
                                  ["--index", "1", "--seed-file", "s.md", "--gift"],
                                  ["--index", "1", "--seed-file", "s.md", "--path", "m/84'/0'/0'/0/1"]])
def test_index_option_rules(argv):
    with pytest.raises(SystemExit):
        pw.parse_args(argv)


def test_gift_with_random_seed(tmp_path):
    assert pw.main(["--lang", "en", "--random-seed", "--gift", "-o", str(tmp_path / "g")]) == 0
    seed = dict(paperlib.md_fields((tmp_path / "g-seed.md").read_text()))
    wallet = dict(paperlib.md_fields((tmp_path / "g.md").read_text()))
    assert wallet["path"].startswith("m/184'/") and seed["account path"] != "m/184'"
    root = btccore.seed_root(seed["mnemonic"])
    assert btccore.wif_compressed(btccore.derived_secret(root, wallet["path"])) == wallet["wif"]


@pytest.mark.parametrize("argv", [["--gift"], ["--gift", "--seed-file", "s.md", "--path", "m/184'/1'"],
                                  ["--gift", "--from-md", "w.md"]])
def test_gift_option_rules(argv):
    with pytest.raises(SystemExit):
        pw.parse_args(argv)


def test_path_needs_seed_file():
    with pytest.raises(SystemExit):
        pw.parse_args(["--path", "m/84'/0'/0'/1'"])


def test_paperwallet_markdown_matches_pdf(tmp_path):
    out = tmp_path / "w"
    assert pw.main(["--lang", "en", "--entropy-string", "md twin", "--copies", "1", "-o", str(out)]) == 0
    fields = dict(paperlib.md_fields((tmp_path / "w.md").read_text()))
    (front, back), _reader = _pdf_text(tmp_path / "w.pdf")
    assert fields["address"] in front and fields["wif"] in back
    assert address_from_wif(fields["wif"]) == fields["address"]


def test_key_qr_carries_the_script_type():
    """Electrum and Green read p2wpkh:WIF as native SegWit (a bare WIF as
    P2PKH); a BIP38 key keeps no prefix. The prefix gets a line of its own."""
    strip = pw.Strip(address="bc1q", key_text=pw.KEY_PREFIX + "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                     encrypted=False, wallet_no=1, wallets=1, copy_no=1, copies=1)
    layout = strip.secret_layout()
    assert layout.qr[-1] == strip.key_text and layout.qr[-1].startswith("p2wpkh:K")
    lines = [run[2] for run in layout.runs if len(run) == 5]
    assert lines[0] == "p2wpkh:" and "".join(lines[1:]).replace(" ", "") == strip.key_text[7:]
    strips = pw.build_wallets(pw.parse_args(["--entropy-string", "qr prefix", "--copies", "1"]))[0]
    assert [s.key_text[:7] for s in strips] == ["p2wpkh:"]


def test_random_seed_then_paper_wallets(tmp_path, capsys):
    out = tmp_path / "gift"
    assert pw.main(["--lang", "en", "--random-seed", "-w", "2", "-o", str(out)]) == 0
    seed_md = tmp_path / "gift-seed.md"
    assert (tmp_path / "gift-seed.pdf").exists() and (tmp_path / "gift.pdf").exists()
    seed = dict(paperlib.md_fields(seed_md.read_text()))
    assert seed["tool"] == "paperseed.py" and len(seed["mnemonic"].split()) == 24 and seed["passphrase"] == "no"
    root = btccore.seed_root(seed["mnemonic"])
    fields = paperlib.md_fields((tmp_path / "gift.md").read_text())
    pairs = [(v, w) for (k, v), (k2, w) in zip(fields, fields[1:]) if k == "address" and k2 == "wif"]
    paths = [v for k, v in fields if k == "path"]
    assert len(pairs) == 2 and len(paths) == 2
    for (address, wif), path in zip(pairs, paths):
        assert btccore.wif_compressed(btccore.derived_secret(root, path)) == wif
        assert address_from_wif(wif) == address
    out_text = capsys.readouterr().out
    assert seed["fingerprint"] in out_text and seed["mnemonic"].split()[0] + " " not in out_text


@pytest.mark.parametrize("extra", [["--seed-file", "s.md"], ["--entropy-string", "x"], ["--vanity", "ac"]])
def test_random_seed_excludes(extra):
    with pytest.raises(SystemExit):
        pw.parse_args(["--random-seed"] + extra)


def test_seed_words_qr_behind_the_seedqr(tmp_path, monkeypatch):
    _pdf, md = _seed_file(tmp_path, monkeypatch)
    (front, back), _reader = _pdf_text(tmp_path / "seed.pdf")
    assert "SEEDPHRASEASTEXT" in front and "sameinformationastheSeedQR" in front
    # The words QR (front of P4) lies right behind the SeedQR (back of P4).
    g = ps.GEOMETRY
    assert ps.WORDS_QR == (g.width - ps.QR[0] - ps.QR[2], ps.QR[1], ps.QR[2])
    seed = ps.Seed(mnemonic=BIP84_MNEMONIC, passphrase=False, fingerprint="", path="", xpub="", first_address="")
    assert ps.words_qr_layout(seed).qr[3] == BIP84_MNEMONIC  # plain words, single spaces
    # Once folded, P2 back lies on P4 front: its noise covers the words QR.
    dy, flip = g.decoy_offset(2)
    for v in (ps.QR[1], ps.QR[1] + ps.QR[2]):
        assert 0 <= dy + flip * v <= g.panel_h[2]


def test_random_seed_twelve_words(tmp_path):
    assert pw.main(["--lang", "en", "--random-seed", "--words", "12", "-o", str(tmp_path / "g")]) == 0
    seed = dict(paperlib.md_fields((tmp_path / "g-seed.md").read_text()))
    assert len(seed["mnemonic"].split()) == 12 and seed["words"] == "12"
    wallet = dict(paperlib.md_fields((tmp_path / "g.md").read_text()))
    root = btccore.seed_root(seed["mnemonic"])
    assert btccore.wif_compressed(btccore.derived_secret(root, wallet["path"])) == wallet["wif"]


def test_words_needs_random_seed():
    with pytest.raises(SystemExit):
        pw.parse_args(["--words", "12"])


# ---------------------------------------------------------------------------
# --from-md (only the PDF, from a Markdown file) and --no-pdf (only the .md)
# ---------------------------------------------------------------------------

def test_paperwallet_no_pdf_then_from_md(tmp_path, monkeypatch, capsys):
    password = "a long bip38 password"
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": password)
    assert pw.main(["--lang", "en", "-w", "2", "--bip38", "--no-pdf", "-o", str(tmp_path / "w")]) == 0
    assert (tmp_path / "w.md").exists() and not (tmp_path / "w.pdf").exists()
    fields = paperlib.md_fields((tmp_path / "w.md").read_text())
    capsys.readouterr()
    assert pw.main(["--lang", "en", "--from-md", str(tmp_path / "w.md")]) == 0
    assert (tmp_path / "w.pdf").exists() and "w.md" not in capsys.readouterr().out  # .md untouched
    (front, back), reader = _pdf_text(tmp_path / "w.pdf")
    assert len(reader.pages) == 4  # 2 wallets x 2 copies, 2 per sheet
    for key, value in fields:
        if key == "address":
            assert printed(front, value) == 2
        elif key in ("wif", "bip38"):
            assert printed(back, value) == 1
    # A tampered file is refused before anything is written.
    text = (tmp_path / "w.md").read_text()
    address = dict(fields)["address"]
    (tmp_path / "bad.md").write_text(text.replace(address, address[:-1] + ("q" if address[-1] != "q" else "p")))
    assert pw.main(["--lang", "en", "--from-md", str(tmp_path / "bad.md")]) == 1
    assert not (tmp_path / "bad.pdf").exists()


def test_paperseed_no_pdf_then_from_md(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": "a long seed passphrase")
    assert ps.main(["--lang", "en", "--passphrase", "--no-pdf", "--copies", "1", "-o", str(tmp_path / "s")]) == 0
    assert (tmp_path / "s.md").exists() and not (tmp_path / "s.pdf").exists()
    fields = dict(paperlib.md_fields((tmp_path / "s.md").read_text()))
    assert fields["copies"] == "1"
    assert ps.main(["--lang", "en", "--from-md", str(tmp_path / "s.md")]) == 0
    (front, back), reader = _pdf_text(tmp_path / "s.pdf")
    assert len(reader.pages) == 2 and all(w in back for w in fields["mnemonic"].split())
    # Wrong passphrase: the recomputed fingerprint does not match the file.
    monkeypatch.setattr(pw.getpass, "getpass", lambda prompt="": "another passphrase")
    assert ps.main(["--lang", "en", "--from-md", str(tmp_path / "s.md"), "-o", str(tmp_path / "t")]) == 1
    assert "does not match" in capsys.readouterr().err and not (tmp_path / "t.pdf").exists()


@pytest.mark.parametrize("extra", [["--no-pdf"], ["-w", "2"], ["--bip38"], ["--random-seed"]])
def test_from_md_excludes(extra):
    with pytest.raises(SystemExit):
        pw.parse_args(["--from-md", "w.md"] + extra)


def test_from_md_needs_the_right_tool(tmp_path):
    _seed = tmp_path / "s.md"
    _seed.write_text(paperlib.md_document("x", [("tool", "paperseed.py"), ("network", "main")]))
    assert pw.main(["--lang", "en", "--from-md", str(_seed)]) == 1
