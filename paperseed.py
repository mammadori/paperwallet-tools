#!/usr/bin/env python3
"""
paperseed.py - offline BIP39 seed (mnemonic) generator, sister of paperwallet.py.

Produces the same duplex A4 sheets of roll-fold strips as paperwallet.py,
plus a Markdown file with the same information:

  * outside: the account extended public key (zpub for BIP84) as QR code and
             text, with the master fingerprint and the derivation path, for a
             watch-only wallet; a cover with the Bitcoin logo, sealed with tape;
  * inside:  the 12 or 24 words, numbered, plus the Standard SeedQR (the
             4-digit BIP39 index of every word), on the innermost panel,
             under the same aligned security patterns as the private keys of
             paperwallet.py; guides to restore and to store the seed.

An optional BIP39 passphrase (--passphrase) is asked twice and never printed
or written anywhere. The Markdown file can be fed to
paperwallet.py --seed-file to derive paper wallets from this seed, at the
receive addresses of its account or, with --gift, at random paths.

All BIP39/BIP32 code is in btccore.py; the layout is in paperlib.py.
"""

import sys

try:
    import btccore as btc  # first: disables the network before anything else is imported
    from btccore import *  # noqa: F401,F403
    from paperlib import *  # noqa: F401,F403
    from paperlib import _
except ModuleNotFoundError as e:  # a dependency is not installed
    sys.exit(f"missing {e.name}: install the packages listed in README.md")

import argparse
import getpass
from dataclasses import dataclass


@dataclass
class Seed:
    """A BIP39 seed and the public data of its account."""
    mnemonic: str
    passphrase: bool  # whether a BIP39 passphrase is needed (never stored)
    fingerprint: str
    path: str  # account derivation path
    xpub: str
    first_address: str


# One large card per sheet (148 x 60 mm): QR codes of 38 mm, the words in
# three columns.
GEOMETRY = WIDE
QR = (5.0, 5.0, 38.0)  # xpub QR (P1 front) and SeedQR (P4 back)
WORDS_QR = (GEOMETRY.width - QR[0] - QR[2], QR[1], QR[2])  # P4 front: right behind the SeedQR
TEXT_COL = 50.0  # left edge of the text right of the QR codes
GUIDE_SCALE = 1.2  # guides and cover, drawn larger on the large card


@dataclass
class SeedStrip:
    """Everything printed on one fold-up strip (one copy of the seed)."""
    seed: Seed
    copy_no: int
    copies: int
    geometry = GEOMETRY
    # QR codes kept clear of the test-network watermark.
    qr_rects = {("front", 1): QR, ("front", 4): WORDS_QR, ("back", 4): QR}

    def secret_layout(self):
        return words_layout(self.seed.mnemonic)

    def faces(self):
        seed = self.seed
        words = len(seed.mnemonic.split())
        passphrase_line = (_("• Keep the BIP39 passphrase elsewhere, never with the card.")
                           if seed.passphrase else None)
        return {
            ("front", 1): lambda c, w, h, rng: face_xpub(c, seed, w, h),
            ("front", 2): lambda c, w, h, rng: scaled(c, w, h, lambda w, h: face_cover(
                c, w, h, _("SEED  PHRASE"),
                _("BIP39 · {words} words · {prefix}").format(words=words, prefix=address_prefix()),
                _("PASSPHRASE REQUIRED") if seed.passphrase else _("NO PASSPHRASE"),
                _("seed inside — keep sealed"), copy_label(self.copy_no, self.copies))),
            ("front", 3): lambda c, w, h, rng: scaled(c, w, h, lambda w, h: face_store(
                c, w, h, rng, passphrase_line)),
            ("front", 4): lambda c, w, h, rng: face_words_qr(c, seed, w, h, rng),
            ("back", 1): lambda c, w, h, rng: scaled(c, w, h, lambda w, h: face_restore(c, seed, w, h, rng)),
            # Under the words QR of P4 front once folded: its aligned noise.
            ("back", 2): lambda c, w, h, rng: face_decoy(c, words_qr_layout(seed), w, h, rng,
                                                         *GEOMETRY.decoy_offset(2), mirror=True),
            ("back", 4): lambda c, w, h, rng: face_words(c, seed, w, h),
        }


def scaled(c, w, h, draw, k=GUIDE_SCALE):
    """Draw a face designed for a smaller card k times larger, filling w x h."""
    c.saveState()
    c.scale(k, k)
    draw(w / k, h / k)
    c.restoreState()


# ----------------------------------------------------------------------------
# Faces
# ----------------------------------------------------------------------------

def face_xpub(c, seed, w, h):
    """P1, outside: the account xpub (public: it shows balances, cannot spend)."""
    draw_artwork(c, w, h, VIEW_TERRACES)
    seal_band(c, w, h)
    header_band(c, w, h - SEAL_H - 1.2, _("ACCOUNT XPUB  ·  WATCH-ONLY"), _("PUBLIC"))
    qr_and_text(c, w, seed.xpub, f"{seed.fingerprint} · {seed.path}", size_pt=8.5, leading=3.6,
                per_line=7, qr=QR, text_x=TEXT_COL, note_pt=6.5)


def words_layout(mnemonic):
    """SeedQR on the left (with its digits in a ring), the numbered words in
    three columns on the right, top to bottom then left to right."""
    words = mnemonic.split()
    rows = len(words) // 3
    size = 9.5 if len(words) == 24 else 11.0
    leading = min(8.0, 34.0 / (rows - 1))
    runs = [(TEXT_COL + 31.0 * (i // rows), 42.0 - (i % rows) * leading, f"{i + 1:2d} {word}", size, 0)
            for i, word in enumerate(words)]
    digits = btc.seedqr_digits(mnemonic)
    return SecretLayout(qr=(*QR, digits), runs=runs + qr_ring_runs(digits, *QR))


def face_words(c, seed, w, h):
    """P4, back side: the words and the SeedQR, innermost once folded."""
    draw_artwork(c, w, h, VIEW_RIVER)
    words = len(seed.mnemonic.split())
    header_band(c, w, h - 2.8, _("SEED PHRASE  ·  BIP39  ·  {words} WORDS").format(words=words), _("SECRET"))
    layout = words_layout(seed.mnemonic)
    draw_qr(c, layout.qr[3], *QR)
    panel(c, TEXT_COL - 3.0, 3.5, w - TEXT_COL, 43.0)
    draw_runs(c, layout.runs)


def words_qr_layout(seed):
    """The QR code of the words as text on P4 front (front coordinates)."""
    return SecretLayout(qr=(*WORDS_QR, seed.mnemonic), runs=[])


def face_words_qr(c, seed, w, h, rng):
    """P4, front: the words as plain text (separated by spaces) in a QR code
    for wallets that do not read SeedQR, right behind the SeedQR so that the
    two scramble each other against light; behind the printed words, their
    aligned noise as on any other face next to a secret."""
    draw_tint(c, w, h, rng)
    words = SecretLayout(qr=None, runs=[r for r in words_layout(seed.mnemonic).runs if len(r) == 5])
    c.saveState()
    c.translate(w, 0)
    c.scale(-1, 1)
    draw_secret_noise(c, words, rng)
    c.restoreState()
    draw_qr(c, seed.mnemonic, *WORDS_QR)
    panel(c, 3, h - 10.2, w - 6, 8.4, alpha=0.92)
    label(c, _("SEED PHRASE AS TEXT  ·  words separated by spaces"), 5, h - 5.4, 7.0, SANS_BOLD,
          max_width=w - 10)
    label(c, _("same information as the SeedQR on the other side of this panel"), 5, h - 8.6, 6.2,
          SANS_ITALIC, "ink_soft", max_width=w - 10)
    pill(c, _("security pattern · not a key"), 30, 1.4, 5.0, SANS_ITALIC, "ink_soft", "center", 50, 0.85)


def restore_rows(seed):
    rows = [
        (SANS_BOLD, 0, _("HOW TO RESTORE THE WALLET")),
        (SANS, 0, _("Watch-only: import the xpub outside, then receive to its addresses.")),
        (SANS, 0, _("Sparrow: File › New Wallet › Mnemonic Words (BIP39),")),
        (SANS, 2.5, _("Native SegWit, derivation {path}.").format(path=seed.path)),
        (SANS, 0, _("Electrum: Standard wallet › I already have a seed ›")),
        (SANS, 2.5, _("Options › BIP39 seed, then native segwit and {path}.").format(path=seed.path)),
        (SANS, 0, _("Check the fingerprint {fingerprint} and the first address:")
         .format(fingerprint=seed.fingerprint)),
        (SANS, 2.5, seed.first_address),
    ]
    if seed.passphrase:
        rows.append((SANS, 0, _("Without the passphrase the words open another, empty wallet.")))
    return rows


def face_restore(c, seed, w, h, rng):
    """P1, back side: how to restore the seed in a wallet."""
    draw_tint(c, w, h, rng)
    draw_rows(c, restore_rows(seed), w, h - 5)


# ----------------------------------------------------------------------------
# Seed and outputs
# ----------------------------------------------------------------------------

def build_seed(args):
    """Return (seed, entropy estimate or None) without touching the disk."""
    target = 8 * btc.BIP39_ENTROPY[args.words]
    secrets, estimate = generate_secrets(args, 1)
    warn_weak_entropy(estimate, target)
    mnemonic = btc.mnemonic_from_secret(secrets[0], args.words)
    # Self-check: the words must validate and give the entropy back.
    if (btc.check_mnemonic(mnemonic) != mnemonic
            or btc.mnemonic_entropy(mnemonic) != secrets[0][:btc.BIP39_ENTROPY[args.words]]):
        raise RuntimeError(_("internal self-check failed (BIP39 round-trip)"))
    passphrase = ask_twice(_("BIP39 passphrase: ")) if args.passphrase else ""
    seed = make_seed(mnemonic, passphrase, args.path or btc.default_account_path())
    del passphrase
    return seed, estimate


def make_seed(mnemonic, passphrase, path):
    """The Seed of a mnemonic: fingerprint, account xpub and first address
    computed from the words, the passphrase and the account path."""
    path = btc.format_path(btc.parse_path(path))
    root = btc.seed_root(mnemonic, passphrase)
    return Seed(mnemonic=btc.check_mnemonic(mnemonic), passphrase=bool(passphrase),
                fingerprint=btc.fingerprint(root), path=path,
                xpub=btc.account_xpub(root, path), first_address=btc.first_address(root, path))


def seed_from_md(path, fields):
    """--from-md: the seed of a paperseed.py Markdown file, recomputed from its
    words (and passphrase, asked if needed) and checked against the file."""
    f = dict(fields)
    passphrase = ""
    if f.get("passphrase", "").startswith("yes"):
        passphrase = getpass.getpass(_("BIP39 passphrase: "))
    seed = make_seed(f.get("mnemonic", ""), passphrase, f.get("account path", ""))
    seed.passphrase = f.get("passphrase", "").startswith("yes")
    del passphrase
    if (seed.fingerprint, seed.xpub, seed.first_address) != (
            f.get("fingerprint"), f.get("account xpub"), f.get("first address")):
        raise ValueError(_("{path} does not match its own seed (fingerprint, xpub or first address): "
                           "wrong passphrase, or an edited file?").format(path=path))
    return seed


def markdown(seed, estimate, copies):
    """The Markdown twin of the PDF; paperwallet.py --seed-file reads its
    machine-readable block."""
    words = seed.mnemonic.split()
    fields = [("tool", "paperseed.py"), ("network", btc.NETWORK_NAME), ("words", len(words)),
              ("mnemonic", seed.mnemonic),
              ("passphrase", "yes (not stored here)" if seed.passphrase else "no"),
              ("fingerprint", seed.fingerprint), ("account path", seed.path),
              ("account xpub", seed.xpub), ("first address", seed.first_address),
              ("seedqr", btc.seedqr_digits(seed.mnemonic)), ("copies", copies)]
    if estimate is not None:
        fields.append(("user entropy", f"~{int(estimate.bits)} bits ({estimate.kind})"))
    rows = len(words) // 2
    table = ["| # | " + _("word") + " | # | " + _("word") + " |", "|---|---|---|---|"]
    table += [f"| {i + 1} | {words[i]} | {i + rows + 1} | {words[i + rows]} |" for i in range(rows)]
    paper = [_("paperwallet.py --seed-file FILE derives paper wallets from this seed at the receive "
               "addresses of its account, {path}/0/0, {path}/0/1 and so on, which any wallet restoring "
               "the seed finds. With --gift they are at random paths m/184'/a'/b'/c'/d' instead, which "
               "only this seed plus the path printed on the card rebuild (--path).")
             .format(path=seed.path)]
    sections = [(_("Words"), table),
                (restore_rows(seed)[0][2], md_lines(restore_rows(seed)[1:])),
                (_("HOW TO STORE IT"), md_lines(store_rows(
                    _("• Keep the BIP39 passphrase elsewhere, never with the card.")
                    if seed.passphrase else None)[1:])),
                (_("Paper wallets from this seed"), paper)]
    return md_document(_("Bitcoin seed (BIP39)"), fields, sections)


# ----------------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------------

def write_seed(args, output):
    """Generate the seed, or read it back with --from-md, and write NAME.pdf
    and/or NAME.md; returns (seed, estimate, strips, paths). Also used by
    paperwallet.py --random-seed."""
    estimate = None
    if getattr(args, "from_md", None):
        fields = read_md(args.from_md, "paperseed.py")
        seed = seed_from_md(args.from_md, fields)
        copies = args.copies or int(dict(fields).get("copies", 2))
    else:
        seed, estimate = build_seed(args)
        copies = args.copies or 2
    strips = [SeedStrip(seed, i + 1, copies) for i in range(copies)]
    pdf = None if args.no_pdf else render_pdf(strips, _("Bitcoin seed (BIP39)"))
    text = None if getattr(args, "from_md", None) else markdown(seed, estimate, copies)
    paths = write_outputs(output, pdf, text, overwrite=args.force)
    return seed, estimate, strips, paths


def print_seed(seed, strips, paths):
    """Console summary: public information only."""
    print(_("fingerprint: {fingerprint}").format(fingerprint=seed.fingerprint))
    print(_("account: {path} {xpub}").format(path=seed.path, xpub=seed.xpub))
    print(_("first address: {address}").format(address=seed.first_address))
    sheets = -(-len(strips) // GEOMETRY.per_sheet)
    if any(p.endswith(".pdf") for p in paths):
        print(_("strips: {copies} · A4 sheets: {sheets}").format(copies=len(strips), sheets=sheets))
    for path in paths:
        print(_("written: {path} (mode 0600)").format(path=path))


def parse_args(argv):
    ap = argparse.ArgumentParser(
        description=_("Generate an offline BIP39 seed (mnemonic) as a duplex A4 PDF."))
    add_common_args(ap, "paperseed.pdf")
    ap.add_argument("--words", type=int, choices=sorted(btc.BIP39_ENTROPY), default=24,
                    help=_("number of words (default 24)"))
    ap.add_argument("--passphrase", action="store_true",
                    help=_("ask a BIP39 passphrase (never printed or written)"))
    ap.add_argument("--path", metavar="PATH",
                    help=_("account derivation path (default m/84'/0'/0', m/84'/1'/0' on test networks)"))
    args = ap.parse_args(argv)
    check_common_args(ap, args)
    return args


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    select_language(argv)
    args = parse_args(argv)
    try:
        network = args.network
        if args.from_md:
            network = network_of(args, dict(read_md(args.from_md, "paperseed.py"))["network"], args.from_md)
        announce_network(network)
        output = choose_output(args, pdf=not args.no_pdf, md=not args.from_md)
        seed, estimate, strips, paths = write_seed(args, output)
    except (ValueError, RuntimeError, OSError) as e:
        # Only our own messages / OS errors here: none of them carry secrets.
        print(_("error: {message}").format(message=_(str(e))), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(_("aborted"), file=sys.stderr)
        return 130
    warn_user_entropy(estimate)
    print_seed(seed, strips, paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
