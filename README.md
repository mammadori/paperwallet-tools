# Paperwallet tools

Command line programs that generate Bitcoin keys and BIP39 seeds on a computer disconnected from
the network, and lay them out in a PDF to print, cut and fold.

The result is a **card the size of a credit card**. On the outside is the address, used to
receive funds and to check the balance. On the inside, folded in the middle and covered by a
pattern that hides it against the light, is the private key that spends them. The card is meant
for giving bitcoin to someone, or for keeping some of yours away from any connected device.

There are two programs:

- **`paperwallet.py`** makes paper wallets: a Bitcoin address (`bc1q…`) with its private key,
  in clear or protected by a password ([BIP38]).
- **`paperseed.py`** makes a [BIP39] seed, the 12 or 24 words from which a wallet derives all its
  keys, and prints it on a larger card.

Both write a PDF to print double-sided and a `.md` file with the same data.

> **Warning.** Whoever holds the private key (or the seed) can spend the funds. The PDF and the
> `.md` file contain the secrets: generate them on an offline machine, check the printout, then
> delete them or keep them encrypted.

---

## Installation

You need Python 3 and five libraries, which you can take from the Debian packages or from pip.
On Debian you can also [build the `paperwallet-tools` package](#as-a-debian-package), which
pulls them in by itself. Install everything on a machine that you will then disconnect from the
network, or on a live system such as [Tails].

| library | what it is for | Debian package | pip |
|---|---|---|---|
| [libsecp256k1] | the elliptic curve maths of Bitcoin (the Bitcoin Core library) | `libsecp256k1-6` (sid), `libsecp256k1-2` (trixie) | — (system library) |
| [python-mnemonic] | the BIP39 words (the reference implementation) | `python3-mnemonic` | `mnemonic` |
| pycryptodome | the AES encryption of BIP38 | `python3-pycryptodome` | `pycryptodome` |
| reportlab, qrcode | the PDF and the QR codes | `python3-reportlab`, `python3-qrcode` | `reportlab`, `qrcode` |
| [Open Sans] | the typeface of the texts; without it the programs use Helvetica and say so | `fonts-open-sans` | — (system font) |

**With the Debian packages** (tested on Debian sid):

```bash
sudo apt install libsecp256k1-6 python3-mnemonic python3-pycryptodome python3-reportlab python3-qrcode fonts-open-sans
```

On Debian 13 trixie the library is packaged as `libsecp256k1-2` (version 0.5): install that
instead of `libsecp256k1-6`.

**With pip**, in a virtual environment. libsecp256k1 and Open Sans are not Python packages:
install them with the system's package manager (on Debian, `libsecp256k1-6`, or
`libsecp256k1-2` on trixie, and `fonts-open-sans`).

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

`requirements.txt` also lists pytest and pypdf, which only the [tests](#tests) need. With pip,
run the programs with the environment's Python: `.venv/bin/python paperwallet.py`.

Then:

1. Disconnect the machine from the network. As an extra safeguard, the programs also stop
   themselves from opening connections: at startup, before loading the libraries, they block
   Python's sockets. This protects against unintended connections; it does not replace
   disconnecting.
2. Run the programs from the project folder, as `./paperwallet.py` and `./paperseed.py`. If a
   library is missing, they stop and say which one.

They are tested with Python 3.14 and libsecp256k1 0.7.1, both with the Debian sid packages
(mnemonic 0.21, pycryptodome 3.20, reportlab 5.0, qrcode 8.2) and with those from pip.

### As a Debian package

The `debian/` folder builds the `paperwallet-tools` package. From the project folder:

```bash
sudo apt install build-essential
sudo apt build-dep ./
dpkg-buildpackage -us -uc -b
sudo apt install ../paperwallet-tools_0.1.1_all.deb
```

The build also runs the tests. The package installs the commands `paperwallet` and `paperseed`
(without `.py`, usable from any folder) and the manual pages `man paperwallet` and
`man paperseed`; it depends on the libraries it needs and recommends Open Sans.

## Your first paper wallet

```bash
./paperwallet.py -o wallet
```

You get `wallet.pdf` and `wallet.md` (without `-o`, the files are called `paperwallet.pdf` and
`paperwallet.md`). The console shows only public data, such as the address and the names of the
files written, never the key. The key comes from 32 random bytes of `/dev/random`, which is the
recommended choice; if you would rather roll dice, see [Using your own entropy](#using-your-own-entropy-dice).

Then:

1. **Make a test print** with a throwaway wallet: A4, **100% scale** (not "fit to page"),
   double-sided, flipping on the **long edge**. Hold the sheet against the light: the registration
   marks in the middle of the margins must line up.
2. **Print the real wallet.** Each sheet holds two strips, by default two copies of the same
   wallet, to keep in different places.
3. **Cut along the crop marks and fold** following the steps printed on the back: key side up,
   then lines 1, 2 and 3 in order.
4. **Seal** the open edge with adhesive tape over the two SEAL bands, and sign across the tape:
   if anyone opens the card, it shows.
5. **Check the address** before sending funds to it: import the key from the `.md` file into an
   offline wallet and check that it gives the printed address. How to do it with Electrum is
   explained in [Trying it without real bitcoin](#trying-it-without-real-bitcoin).
6. Delete `wallet.pdf` and `wallet.md`, or put them in an encrypted archive.

If you want the key protected by a password, add `--bip38`. The password is asked twice and is
never shown. With the default two copies, one is in clear and one is encrypted.

```bash
./paperwallet.py --bip38 -o wallet
```

## How the card is made

Each copy is a strip of 85.6 × 211.5 mm divided into four panels. Rolled up along lines 1, 2
and 3, it becomes a card of 85.6 × 54 mm, the size of a credit card.

| panel | front | back |
|---|---|---|
| P1 | **outside**: address and QR code, SEAL band | how to spend |
| P2 | **outside**: cover, SEAL band | how to store it |
| P3 | quick instructions | security pattern |
| P4 | security pattern | **private key** and QR code |

Once folded, the key is in the middle, under at least two layers of paper on each side. Only
the address and the cover are left outside. Other details:

- **Security pattern.** The two faces that touch the key carry a random pattern, new on every
  print, exactly over the QR code and the characters of the key. Against the light, the key
  blends into the noise. The pattern is not a valid QR code, so it cannot be scanned by mistake.
- **Nesting panels.** Each inner panel is 1.5 mm shorter than the previous one, so the fold does
  not crush them.
- **Text around the QR codes.** The content of each QR code is also written in small type along
  its four sides, without spaces. The large text, in groups of four characters, is easy to read,
  but the real address is a single string.
- **Key format.** The key QR code holds `p2wpkh:` followed by the WIF key. The prefix tells the
  wallet that the address is native SegWit: [Electrum] and Green read it as it is, while without
  it they look for an old-style address and find nothing. [Sparrow] and BlueWallet want the key
  without the prefix. A BIP38 key (`6P…`) has no prefix.
- **Cover.** It shows "wallet n/N · copy c/C" (the wallet number only when there are several)
  and a solarpunk illustration in the background.

## What you can do

### Several wallets at once

```bash
./paperwallet.py -w 4 --copies 2 -o gifts
```

`-w` sets how many different wallets to make (1 to 4), `--copies` how many copies of each (1 to
8, default 2). The program uses as many sheets as needed, two strips per sheet. With `--bip38`,
all the wallets share the same password.

### Backing up a seed

```bash
./paperseed.py -o seed
```

`paperseed.py` makes a 24-word BIP39 seed (12 with `--words 12`) and prints it on a larger card,
one per A4 sheet: folded, it measures 148 × 60 mm, as wide as a landscape A6 sheet. Inside are:

- the **numbered words** and a standard [SeedQR], which SeedSigner, Blockstream Jade and
  BlueWallet, among others, can read;
- a second **QR code with the words as text**, for wallets that do not read SeedQR, such as
  [Electrum] (which restores a BIP39 seed from Options › BIP39 seed). It is printed exactly behind
  the SeedQR, so that against the light the two blur into each other.

Outside is the account **xpub**, the extended public key that lets a watch-only wallet follow
the balance without exposing the seed.

The options specific to `paperseed.py` are:

- `--passphrase`, which adds a BIP39 passphrase. It is asked twice and is never printed or
  written down: the card only says that one is needed.
- `--path`, which changes the account path (default `m/84'/0'/0'`, or `m/84'/1'/0'` on the test
  networks).

### Giving bitcoin from your own seed

If you already have a seed made with `paperseed.py`, you can derive the paper wallets from it
instead of generating independent keys. The advantage is that if the recipient loses the card,
you can rebuild it.

```bash
./paperwallet.py --seed-file seed.md -w 4 -o gifts
```

The wallets are the standard receive addresses of the seed's account, one after the other:
`m/84'/0'/0'/0/0`, `m/84'/0'/0'/0/1` and so on. Any wallet finds them by itself when you restore
the seed, today or in twenty years, with nothing else needed. The path is still printed in small
type on the address side.

So that you do not hand out the same addresses twice, at the end the program tells you which
index to start from next time; pass it with `--index`:

```bash
./paperwallet.py --seed-file seed.md --index 4 -w 4 -o more-gifts
```

Keep the indices consecutive: when restoring a seed, wallets stop looking after about 20 empty
addresses in a row, so an address far beyond the others could be missed.

The card tells the recipient the truth: **as long as the seed exists, you can spend those funds
too**. To be their only owner, the recipient has to sweep them, that is, move them to a wallet
of their own.

To print a wallet again, pass the printed path (or several paths separated by commas):

```bash
./paperwallet.py --seed-file seed.md --path "m/84'/0'/0'/0/2"
```

If you do not have a seed yet, `--random-seed` makes a new one (24 words, or 12 with
`--words 12`, without a passphrase) and derives the wallets from it straight away. The seed is
written next to the wallets, as `gifts-seed.pdf` and `gifts-seed.md`: print and keep that one
too, because it is the master key of all the wallets.

```bash
./paperwallet.py --random-seed -w 4 -o gifts
```

#### Keeping the gifts apart from your own wallet

The standard addresses of the account show up in every wallet you import the seed into. If you
also use the same seed as your personal wallet, the gifts would mix with your balance: in that
case, add `--gift`.

```bash
./paperwallet.py --seed-file seed.md --gift -w 4 -o gifts
```

With `--gift`, each gift has a random path, for example
`m/184'/1023634473'/1534119162'/1895158284'/61505300'`: the four parts after `184'` make 124
bits in all, too many to guess. The number 184 is not used by any standard, so:

- when you import the seed into a wallet, the gifts do not show up and do not mix with your
  balance;
- the account key (`m/84'/0'/0'`), which many wallets keep on a connected device, is not enough
  to derive them: the whole seed is needed;
- whoever has only the seed cannot find them: rebuilding a gift takes the seed **and** the path
  printed on the card, passed with `--path`.

`--gift` also works with `--random-seed`.

### Vanity addresses

```bash
./paperwallet.py -w 4 --vanity sun,tree,leaf,moss -o gifts
```

The addresses will start with `bc1qsun…`, `bc1qtree…` and so on. You can give one prefix for all
the wallets, or one per wallet separated by commas. Each prefix has at most 6 characters from
the alphabet `qpzry9x8gf2tvdw0s3jn54khce6mua7l` (no `1`, `b`, `i` or `o`), and each extra
character multiplies the time by 32:

| characters | rough time (4 cores) |
|---|---|
| 3 | under 1 s |
| 4 | about 2 s |
| 5 | about 1 minute |
| 6 | about 40 minutes |

`--jobs N` sets how many processes to use (default: all the cores). Vanity prefixes cannot be
combined with a seed, because there the path determines the key.

### Generate today, print tomorrow

```bash
./paperwallet.py -w 4 --bip38 --no-pdf -o gifts   # only gifts.md
```

```bash
./paperwallet.py --from-md gifts.md               # then gifts.pdf
```

`--no-pdf` writes only the `.md` file. `--from-md` rebuilds the PDF from a `.md` file written
earlier by the same program, without changing the file. It checks the data first: each key must
give its address and, for a seed, the words, fingerprint and xpub must match. Both
options work the same way in `paperseed.py`.

### Trying it without real bitcoin

```bash
./paperwallet.py --network signet -o test
```

With `--network signet` (or `testnet`) you get `tb1q…` addresses of coins with no value. Every
panel says so diagonally, and so do the PDF and the console. To try the whole round trip:

1. Fund the `tb1q…` address from a signet faucet, for example [signetfaucet.com].
2. Open [Electrum] on the same network (`electrum --signet`) with any wallet, and go to
   Wallet › Private keys › Sweep. Scan the key QR code, or paste its text, `p2wpkh:cXXXX…`.
3. Check that the funds arrive in the wallet and that the paper address is left empty.

To check only that a key gives the printed address, with no network and no funds, start
`electrum --offline`, create a new wallet with "Import Bitcoin addresses or private keys" and
paste the text of the key QR code (`p2wpkh:…`).

## For the recipient of the card

The instructions are printed inside. In short:

1. Check the balance using the address only, in a watch-only wallet.
2. When you want to spend, open the card and **sweep** the whole balance into a wallet of your
   own. In [Electrum] use Wallet › Private keys › Sweep and scan the key QR code. In [Sparrow]
   use Tools › Sweep Private Key, choose Native SegWit and enter the key without `p2wpkh:`.
3. Always move everything at once: after the sweep, the key must not be used again.
4. Destroy every copy of the card.

## Using your own entropy (dice)

If you do not want to trust `/dev/random`, you can provide the randomness yourself, for example
by rolling dice:

```bash
./paperwallet.py --entropy-prompt -o wallet
```

```bash
./paperwallet.py --entropy-file dice.txt -o wallet
```

`--entropy-prompt` asks for the entropy without showing it as you type; `--entropy-file` reads
it from a file (`-` for standard input). There is also `--entropy-string TEXT`, but the text
would end up in the shell history. The key is the SHA-256 of what you provide.

**You need a lot of randomness**: at least 100 rolls of a six-sided die, or 64 hexadecimal
digits, or 256 coin flips. A sentence or a password made up by a person amounts to a *brain
wallet*, and sooner or later someone guesses it and empties the wallet. The program estimates
the entropy and, if it is below 256 bits, warns you before asking anything else, so you can
stop with Ctrl-C. The estimate is optimistic: it flags the cases that are certainly too weak,
but it does not vouch for the others. How it is computed is explained in
[Keys and entropy](#keys-and-entropy).

The same entropy always gives the same wallets. `paperseed.py` accepts the same options.

## Security

What the programs do:

- at startup they block Python's sockets, so neither the programs nor their libraries can open
  connections (the rest of the system stays connected, and native code is not covered);
- they use no temporary files: they write the PDF and the `.md` file once, readable only by you
  (mode `0600`); without `--force` they never overwrite an existing file, but write
  `wallet_01.pdf` instead and say so;
- before writing, they check their own work: key → address, BIP38 decryption, words → seed,
  fingerprint;
- the console shows only public information.

What is left to you, because the programs cannot control it:

- the print spooler (CUPS writes to `/var/spool`), network printers or printers with internal
  memory, swap and core dumps. The ideal is an offline live system such as [Tails], with the
  files on tmpfs, a USB printer without memory, and the machine switched off at the end;
- RAM: Python does not guarantee that secrets are wiped from it.

## Language

The programs speak **English** and **Italian**, both in the PDF and in the console. They follow
the system language; `--lang en` or `--lang it` forces one.

---

## Technical details

This part is for anyone who wants to audit the code or understand exactly what is computed.

### Code structure

| file | contents |
|---|---|
| **`btccore.py`** | **everything that determines keys, words, addresses and encryption**: networks, entropy → secrets, WIF and addresses, BIP38, BIP39/[BIP32] (paths, xpub, SeedQR), vanity search. It is the place to start an audit (see below). |
| `paperlib.py` | shared code: translations, user entropy, prompts, common options, PDF layout, `.md` files, writing files |
| `paperwallet.py`, `paperseed.py` | the two programs: card faces, self-checks, command line |
| `test_paperwallet.py` | the tests (see [Tests](#tests)) |
| `locale/it/LC_MESSAGES/paperwallet.po` | the Italian translation (see [Translations](#translations)) |
| `debian/` | the Debian package (see [As a Debian package](#as-a-debian-package)) |
| `assets/`, `tools/prepare_artwork.py` | the illustration and the script that prepares it (see [Artwork and fonts](#artwork-and-fonts)) |

Besides the standard library, `btccore.py` uses only libsecp256k1 (through ctypes),
python-mnemonic and pycryptodome. Base58, bech32 and BIP32 are written there and checked against
the official test vectors. It contains no PDF, graphics, translations, file access or console
output, and a test checks this.

### Keys and entropy

- Without your own entropy, the key is the SHA-256 of 32 bytes from `/dev/random`. With your own
  entropy it is `SHA-256(entropy)`, checked to lie in the range `[1, n-1]` of secp256k1. Empty
  entropy counts as no entropy.
- With several wallets, wallet i (from 0) uses `SHA-256(entropy ‖ i)` with `i` as 4 big-endian
  bytes; the first one uses `SHA-256(entropy)`.
- An input made only of hexadecimal digits is read as a number: its bytes are decoded and the
  SHA-256 is computed over them. Upper case, a `0x` prefix, spaces, newlines and separators
  (`, ; : - _ . / |`) do not change the key, and an odd number of digits gets a leading `0`. A
  sequence of only `1`–`6` is decoded the same way, but counts as dice rolls for the estimate.
- The entropy estimate recognises the kind of input and counts its bits per symbol. It is also
  capped by the compressed size (zlib), so repetitions such as `1111…` score low. The console
  shows only the estimate and the kind of input.

  | input | bits per symbol | for 256 bits |
  |---|---|---|
  | coin flips (`0`/`1`) | 1 | 256 |
  | dice rolls (`1`–`6`) | 2.585 | 100 |
  | decimal digits | 3.32 | 78 |
  | hexadecimal digits | 4 | 64 |
  | words (diceware estimate, 7776 words) | 12.9 | 20 |
  | other text | log₂ of the alphabet used | it depends |
  | binary data | 8 | 32 bytes |

- `paperseed.py` uses the first 16 or 32 bytes of the SHA-256 as BIP39 entropy.
- The BIP39 passphrase is NFKD-normalised, as the standard requires: an accented letter gives
  the same seed however it was typed, and the same seed as other wallets give.
- BIP38 is in non-EC-multiply mode with the compressed flag (`0xE0`). The *address hash* is
  computed, as the standard prescribes, over the P2PKH address of the same key.

### Paths derived from a seed

With `--seed-file`, wallet i (from 0) has the path `account/0/(N+i)`: `account` is the account
path written in the seed's `.md` file (usually `m/84'/0'/0'`, that is [BIP84]), `0` is the chain
of receive addresses and `N` is `--index` (default 0). With `--gift` the path is instead
`m/184'/a'/b'/c'/d'`, with `a`–`d` random hardened indices of 31 bits each. The keys are always
compressed and the addresses P2WPKH.

Before deriving, the program asks for the passphrase if the seed has one, and checks the
fingerprint. `--random-seed` writes the seed with `paperseed.py` (same network, same number of
copies, standard account path) and then proceeds as with `--seed-file`.

### Vanity search

From the derived key `k0`, with public key `A = k0·G`, the program looks for the smallest `i`
such that the address of `A + i·G` starts with the prefix; the final key is `k0 + i mod n`. The
search loop uses only public points, and the private key is put back together in the main
process.

The search processes are `fork`s of the program and write their result to anonymous shared
memory: no files, sockets or serialisation. The result is always the smallest `i`, whatever
`--jobs` is, so with your own entropy the wallet is reproducible.

The search runs on the CPU only, with libsecp256k1. For prefixes longer than 6 characters,
[VanitySearch] in split-key mode, built from source and run in a sandbox, could be considered.

### Layout

- The panels of the `paperwallet.py` strip measure 54, 54, 52.5 and 51 mm. Once folded, they are
  stacked in the order P1, P3, P4, P2.
- Fold lines are dash-dotted (mountain folds) on the front and dashed (valley folds) on the back.
- The back mirrors the front, so that each strip lands on itself when printed double-sided on
  the long edge.
- The security pattern is generated with `os.urandom` on every print, so knowing another copy of
  it does not help to subtract it. Under it there is a wavy hatching, as in bank envelopes.
- The `paperseed.py` card is a strip of 148 × 235.5 mm, with 38 mm QR codes and the words in
  three columns:

  | panel | front | back |
  |---|---|---|
  | P1 | **outside**: account xpub (QR code and text, fingerprint and path) | recovery guide |
  | P2 | **outside**: "SEED PHRASE" cover | pattern aligned with the words QR code |
  | P3 | storage guide | pattern aligned with the words |
  | P4 | QR code of the words as text, with a pattern behind the words | numbered words and SeedQR |

  Every secret has an aligned pattern above and below it. Unlike in `paperwallet.py`, the front
  also holds a secret (P4).

### The `.md` file

It holds the same secrets as the PDF, with mode `0600`: a `text` block of machine-readable
`key: value` lines, followed by the same guides as the card.

### Translations

English is the language of the source code. The system language is read from `LANGUAGE`,
`LC_ALL`, `LC_MESSAGES` and `LANG`, in this order, as gettext does: `it_*` gives Italian, any
other value English. The translations are in `locale/it/LC_MESSAGES/paperwallet.po`, which the
programs read directly, without compiling a `.mo` file. Sentences that are too long are shrunk
to fit their panel.

### Tests

The tests also need pytest, pypdf and, optionally, gettext's `msgfmt`, which checks the syntax
of the translations. With the Debian packages:

```bash
sudo apt install python3-pytest python3-pypdf gettext
python3 -m pytest -q
```

With pip, pytest and pypdf are already in `requirements.txt`:

```bash
.venv/bin/python -m pytest -q
```

Among other things, the tests check:

- that `btccore.py` imports no interface code and writes nothing to the console;
- the official BIP32, BIP84, BIP38 and SeedQR test vectors, WIF and base58 encoding, and the
  NFKD normalisation of the BIP39 passphrase;
- every `bc1q` address, recomputed from the WIF with an independent pure-Python implementation
  (secp256k1, hash160, bech32);
- real PDFs: they read the keys back, **decrypt** the BIP38 ones, check that they match the
  printed addresses, and that nothing secret reaches the console;
- the whole path `paperseed.py` → `paperwallet.py --seed-file` → rebuilding with `--path`,
  standard paths and `--index`, `--gift`, and the rejection of a wrong passphrase;
- the fold, simulated step by step: the pattern must fall exactly over the key and the panels
  must nest;
- that the `.po` file translates exactly the strings of the source, with the same placeholders,
  and that the PDFs come out in the requested language; with gettext installed, also the syntax
  of the catalogue;
- how copies are spread over sheets, that the vanity search gives the same result with one or
  more processes, the font search and the fallback to Helvetica.

### Artwork and fonts

- `assets/solarpunk-vault.jpg` is an illustration made by the author of the project, Marco
  Amadori, and distributed with it. Each face shows a different crop of it, and the PDF embeds
  it only once.
- The original (1672×941) is `assets/source/solarpunk-vault.webp`. `tools/prepare_artwork.py`
  derives the asset from it at half resolution (836×470, about 125 KB). If the colours come out
  too pale in print, as often happens with laser printers, it can raise the saturation
  (`--color`) and darken the mid-tones (`--gamma`):

  ```bash
  python3 tools/prepare_artwork.py --color 1.3 --gamma 1.2
  ```

- The texts are set in [Open Sans] (SIL Open Font License 1.1), embedded in the PDF as a subset.
  The programs look for it in `~/.local/share/fonts`, `~/.fonts`, `/usr/local/share/fonts` and
  `/usr/share/fonts`. Keys and addresses are set in Courier, a monospaced font in which every
  character is easy to tell apart.

## License

Paperwallet tools, illustration included, is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License, version 3 or (at your option) any
later version. The full text is in [`LICENSE`](LICENSE).

## References

- Standards: [BIP32], [BIP38], [BIP39], [BIP84], [SeedQR].
- Libraries: [libsecp256k1], [python-mnemonic].
- Programs mentioned: [Electrum], [Sparrow], [Tails], [VanitySearch].

[BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP38]: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP84]: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
[SeedQR]: https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md
[libsecp256k1]: https://github.com/bitcoin-core/secp256k1
[python-mnemonic]: https://github.com/trezor/python-mnemonic
[Electrum]: https://electrum.org/
[Sparrow]: https://sparrowwallet.com/
[Tails]: https://tails.net/
[VanitySearch]: https://github.com/JeanLucPons/VanitySearch
[Open Sans]: https://github.com/googlefonts/opensans
[signetfaucet.com]: https://signetfaucet.com/
