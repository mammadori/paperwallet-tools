#!/usr/bin/env python3
"""
paperwallet.py - offline Bitcoin paper wallet generator.

Produces A4, double-sided (flip on long edge) PDF sheets with two strips
of 85.6 x 211.5 mm each, plus a Markdown file with the same information.
A strip, cut out along the crop marks and roll-folded on its three
numbered lines, becomes a credit-card sized (85.6 x 54 mm) wallet:

  * outside: P2WPKH (bc1q...) address as monospace text + QR code,
             plus a cover with the Bitcoin logo, sealed with tape;
  * inside:  the private key (WIF compressed, or BIP38 encrypted) as
             monospace text + QR code, on the innermost panel, under at
             least two more layers of paper. The face folded right over
             the key and the back of its own panel carry random marks
             aligned with it (new on every print), so that it cannot be
             read against light; the other inner faces explain how to
             spend and how to store the wallet.

The keys come from /dev/random or user entropy, or are derived from a BIP39
seed written by paperseed.py (--seed-file): at the receive addresses of its
account (account/0/i), which any wallet restoring the seed finds, or with
--gift at m/184' plus 124 random bits, which only seed + printed path rebuild.

All key, address and encryption code is in btccore.py; the layout is in
paperlib.py.

Security properties:
  * network access is disabled for the whole process;
  * no temporary files: PDF and Markdown are built in memory and written
    once, directly to the requested output paths, with mode 0600;
  * nothing secret (entropy, private key, password) is printed to the console.
"""

import sys

try:
    import btccore as btc  # first: disables the network before anything else is imported
    from btccore import *  # noqa: F401,F403  (re-exported for the tests and for audit tools)
    from paperlib import *  # noqa: F401,F403
    from paperlib import _
except ModuleNotFoundError as e:  # a dependency is not installed
    sys.exit(f"missing {e.name}: install the packages listed in README.md")

import argparse
import getpass
import os
import re
from dataclasses import dataclass


VANITY_MAX = 6  # 30 bits, still fits the 4-byte comparison in btccore
# Script type in front of the WIF in the key QR code, as Electrum and Green
# read it: without it they look for a legacy (P2PKH) address and find nothing.
KEY_PREFIX = "p2wpkh:"


def parse_vanity(prefix):
    """Normalise a vanity prefix: the characters right after 'bc1q' (or 'tb1q')."""
    p = prefix.strip().lower()
    if p.startswith(address_prefix()):
        p = p[4:]
    if not 1 <= len(p) <= VANITY_MAX:
        raise ValueError(_("vanity prefix must be 1 to {max} characters after bc1q")
                         .format(max=VANITY_MAX))
    bad = sorted({ch for ch in p if ch not in BECH32_CHARSET})
    if bad:
        raise ValueError(_("invalid characters in vanity prefix: {chars} (bech32 has no 1, b, i, o)")
                         .format(chars=" ".join(bad)))
    return p


def vanity_tries(prefix):
    """Expected number of attempts: 32 possibilities per bech32 character."""
    return 32 ** len(prefix)


# ----------------------------------------------------------------------------
# The strip of one copy of one wallet, and its faces
# ----------------------------------------------------------------------------

@dataclass
class Strip:
    """Everything printed on one fold-up strip (one copy of one wallet)."""
    address: str
    key_text: str  # "p2wpkh:" + WIF, or BIP38 "6P..." string
    encrypted: bool
    wallet_no: int  # 1-based
    wallets: int
    copy_no: int  # 1-based, per wallet
    copies: int
    path: str = None  # derivation path, for keys derived from a BIP39 seed
    fingerprint: str = None  # of that seed

    def secret_layout(self):
        return qr_text_layout(self.key_text, split=True)

    def faces(self):
        return {
            ("front", 1): lambda c, w, h, rng: face_address(c, self, w, h),
            ("front", 2): lambda c, w, h, rng: face_cover(
                c, w, h, _("PAPER  WALLET"), _("native SegWit · {prefix}").format(prefix=address_prefix()),
                _("BIP38 ENCRYPTED KEY") if self.encrypted else _("UNENCRYPTED KEY"),
                _("private key inside — keep sealed"),
                copy_label(self.copy_no, self.copies, self.wallet_no, self.wallets)),
            ("front", 3): lambda c, w, h, rng: face_notes(c, self, w, h, rng),
            ("back", 1): lambda c, w, h, rng: face_spend(c, self, w, h, rng),
            ("back", 2): lambda c, w, h, rng: face_store(
                c, w, h, rng,
                _("• Keep the BIP38 password elsewhere, never with the card.") if self.encrypted else None,
                origin_rows(self.path) if self.path else ()),
            ("back", 4): lambda c, w, h, rng: face_key(c, self, w, h),
        }


def face_address(c, strip, w, h):
    """P1, outside: the public address (safe to show) and, for a key derived
    from a seed, its derivation path in small print."""
    draw_artwork(c, w, h, VIEW_TERRACES)
    seal_band(c, w, h)
    header_band(c, w, h - SEAL_H - 1.2, _("BITCOIN ADDRESS  ·  P2WPKH (SegWit)"), _("LOAD / DEPOSIT"))
    qr_and_text(c, w, strip.address, _("public — safe to share"))
    if strip.path:
        parts = strip.path.split("/")
        if btc.is_wallet_path(strip.path):  # short: one line
            lines = [strip.path]
        else:  # m/184'/a'/b'/c'/d': the random levels two by two
            tail = parts[-btc.PAPER_PATH_LEVELS:]
            lines = ["/".join(parts[:-btc.PAPER_PATH_LEVELS]) + "/",
                     "/".join(tail[:2]) + "/", "/".join(tail[2:])]
        spare = (3 - len(lines)) * 2.1  # the panel fits three lines
        panel(c, TEXT_X - 2.5, 30.6 + spare, w - TEXT_X - 0.5, 8.9 - spare, alpha=0.84)
        label(c, _("derivation path · seed {fingerprint}").format(fingerprint=strip.fingerprint),
              TEXT_X, 37.7, 4.6, SANS_ITALIC, "ink_soft", max_width=w - TEXT_X - 4)
        draw_runs(c, [(TEXT_X, 35.5 - i * 2.1, line, 5.0, 0) for i, line in enumerate(lines)])


def face_notes(c, strip, w, h, rng):
    """P3, inside: quick instructions next to the spending guide."""
    draw_artwork(c, w, h, VIEW_TERRACES)
    draw_foliage(c, w, h, rng)
    panel(c, 6, 6, w - 12, h - 12, alpha=0.88, r=2.5)
    # (font, indent in mm, text)
    rows = [
        (SANS_BOLD, 0, _("HOW TO USE")),
        (SANS, 0, _("1. Fund it: send bitcoin to the address outside.")),
        (SANS, 0, _("2. Spend it: sweep the WHOLE balance into a wallet,")),
        (SANS, 2.5, _("then consider this paper used.")),
    ]
    if strip.encrypted:
        rows += [(SANS, 0, _("3. Decrypt the 6P… key with its BIP38 password;")),
                 (SANS, 2.5, _("keep the password apart from this card."))]
    else:
        rows += [(SANS, 0, _("3. Anyone who reads the key owns the funds:")),
                 (SANS, 2.5, _("keep the card folded and sealed."))]
    y = h - 12.5
    for font, indent, text in rows:
        label(c, text, 9 + indent, y, 6.2 if font == SANS_BOLD else 5.5, font,
              max_width=w - 18 - indent)
        y -= 3.5
    label(c, _("date ____________   amount ________________"), 9, 9.5, 5.5, SANS, "ink_soft",
          max_width=w - 18)


def spend_rows(strip):
    rows = [
        (SANS_BOLD, 0, _("HOW TO SPEND: SWEEP THE WHOLE BALANCE")),
        (SANS, 0, _("1. Check the balance with the address only (watch-only).")),
        (SANS, 0, _("2. On a trusted device, sweep the key into your wallet:")),
    ]
    if strip.encrypted:
        rows += [(SANS, 2.5, _("Sparrow: Tools › Sweep Private Key, Native SegWit;")),
                 (SANS, 2.5, _("Electrum: decrypt it first, then sweep p2wpkh:KEY.")),
                 (SANS, 0, _("3. The 6P… key needs its password: use a wallet with")),
                 (SANS, 2.5, _("BIP38 support, or decrypt it offline first."))]
    else:
        rows += [(SANS, 2.5, _("Electrum: Wallet › Private keys › Sweep, scan the QR;")),
                 (SANS, 2.5, _("Sparrow: Tools › Sweep Private Key, Native SegWit,")),
                 (SANS, 5, _("with the key without p2wpkh: in front.")),
                 (SANS, 0, _("3. Sweep everything in one go, never just a part:")),
                 (SANS, 2.5, _("the key must not be used again afterwards."))]
    return rows + [(SANS, 0, _("4. Then destroy every copy of this wallet."))]


def face_spend(c, strip, w, h, rng):
    """P1, back side: how to take the funds out (the first inner face seen
    when the card is opened)."""
    draw_tint(c, w, h, rng)
    draw_rows(c, spend_rows(strip), w, h - 5)


def origin_rows(path):
    """Note on a key derived from a seed: how it is rebuilt and who else may
    be able to spend it."""
    return [
        (SANS_BOLD, 0, _("ORIGIN OF THIS KEY")),
        (SANS, 0, _("Derived from a BIP39 seed (generator key) of whoever gave")),
        (SANS, 0, _("you this card, who may not keep that seed for long.")),
        (SANS, 0, _("Any wallet restoring that seed finds it again;")
         if btc.is_wallet_path(path) else _("Only the seed plus the path printed outside rebuild it;")),
        (SANS, 0, _("while the seed exists, whoever holds it can spend too.")),
    ]


def face_key(c, strip, w, h):
    """P4, back side: the private key, innermost once folded."""
    draw_artwork(c, w, h, VIEW_RIVER)
    title = (_("PRIVATE KEY  ·  BIP38 ENCRYPTED") if strip.encrypted
             else _("PRIVATE KEY  ·  WIF (compressed)"))
    header_band(c, w, h - 2.8, title, _("SPEND"))
    hint = _("password required") if strip.encrypted else _("SECRET — never share")
    qr_and_text(c, w, strip.key_text, f"{hint} · …{strip.address[-6:]}", split=True)


# ----------------------------------------------------------------------------
# Wallets
# ----------------------------------------------------------------------------

@dataclass
class Wallet:
    """One wallet, as listed in the Markdown file."""
    address: str
    wif: str = None  # set when at least one strip is in clear
    bip38: str = None  # set when at least one strip is encrypted
    path: str = None
    fingerprint: str = None


def strip_plan(wallets, copies, encrypt):
    """[(wallet index, copy index, copies, encrypted)] in strip order. With
    --bip38 a wallet with several copies gets half of them in clear and half
    BIP38-encrypted; a wallet with a single copy is BIP38 only."""
    plan = []
    for w in range(wallets):
        for i in range(copies):
            plan.append((w, i, copies, encrypt and (copies == 1 or i >= copies // 2)))
    return plan


def vanity_prefixes(args, wallets):
    """One normalised prefix per wallet, or Nones without --vanity."""
    if not args.vanity:
        return [None] * wallets
    parts = [parse_vanity(p) for p in args.vanity.split(",")]
    if len(parts) == 1:
        return parts * wallets
    if len(parts) != wallets:
        raise ValueError(_("give one vanity prefix, or one per wallet ({n})").format(n=wallets))
    return parts


def read_seed_file(path):
    """The fields of a Markdown file written by paperseed.py."""
    fields = dict(read_md(path, "paperseed.py"))
    missing = [k for k in ("mnemonic", "passphrase", "fingerprint", "account path") if not fields.get(k)]
    if missing:
        raise ValueError(_("{path} is not a paperseed.py file (missing: {fields})")
                         .format(path=path, fields=", ".join(missing)))
    return fields


COPIES_RE = re.compile(r"(\d+) \((\d+) WIF \+ (\d+) BIP38\)")


def wallets_from_md(args):
    """--from-md: the wallets of a paperwallet.py Markdown file, checked (every
    WIF must give its address on this network, every BIP38 key must be well
    formed), and their strips: as many copies as the file says, or --copies."""
    wallets, counts = [], []
    for key, value in read_md(args.from_md, "paperwallet.py"):
        if key == "wallet":
            wallets.append(Wallet(address=None))
            counts.append(None)
        elif wallets:
            w = wallets[-1]
            if key in ("address", "wif", "bip38", "path"):
                setattr(w, key, value)
            elif key == "seed fingerprint":
                w.fingerprint = value
            elif key == "copies" and COPIES_RE.fullmatch(value):
                m = COPIES_RE.fullmatch(value)
                counts[-1] = (int(m[2]), int(m[3]))
    if not wallets:
        raise ValueError(_("{path} lists no wallet").format(path=args.from_md))
    strips = []
    for n, (w, count) in enumerate(zip(wallets, counts), 1):
        ok = bool(w.address and (w.wif or w.bip38))
        try:
            if ok and w.wif:
                secret, _compressed = btc.secret_from_wif(w.wif)
                ok = wif_compressed(secret) == w.wif and p2wpkh_address(secret) == w.address
        except Exception:
            ok = False
        if not ok or (w.bip38 and not btc.is_bip38(w.bip38)):
            raise ValueError(_("wallet {n} of {path}: the key does not match the address")
                             .format(n=n, path=args.from_md))
        if args.copies or count is None:
            copies = args.copies or 2
            kinds = [enc for _w, _i, _c, enc in strip_plan(1, copies, bool(w.bip38))]
            kinds = [bool(w.bip38) and (enc or not w.wif) for enc in kinds]
        else:
            kinds = [False] * count[0] + [True] * count[1]
        strips += [Strip(address=w.address, key_text=w.bip38 if enc else KEY_PREFIX + w.wif, encrypted=enc, wallet_no=n,
                         wallets=len(wallets), copy_no=i + 1, copies=len(kinds), path=w.path,
                         fingerprint=w.fingerprint)
                   for i, enc in enumerate(kinds)]
    return strips, wallets


def seed_secrets(args, seed):
    """[(secret, path)] derived from the seed of --seed-file: at the paths
    of --path, at fresh random paths of the gift tree with --gift, or else
    at the receive addresses of its account from --index on."""
    passphrase = ""
    if seed["passphrase"].startswith("yes"):
        passphrase = getpass.getpass(_("BIP39 passphrase: "))
    root = btc.seed_root(seed["mnemonic"], passphrase)
    del passphrase
    if btc.fingerprint(root) != seed["fingerprint"]:
        raise ValueError(_("the seed fingerprint does not match the file: wrong passphrase?"))
    if args.path:
        paths = [btc.format_path(btc.parse_path(p)) for p in args.path.split(",")]
    elif args.gift:
        paths = [btc.random_paper_path(btc.gift_root()) for _i in range(args.wallets or 1)]
    else:
        paths = [btc.receive_path(seed["account path"], args.index + i) for i in range(args.wallets or 1)]
    return [(btc.derived_secret(root, p), p) for p in paths], btc.fingerprint(root)


def build_wallets(args, seed=None):
    """Return (strips, wallets, entropy estimate or None) without touching the disk."""
    if seed:
        derived, fp = seed_secrets(args, seed)
        secrets = [s for s, _p in derived]
        paths = [p for _s, p in derived]
        prefixes, estimate = [None] * len(secrets), None
    else:
        prefixes = vanity_prefixes(args, args.wallets or 1)
        secrets, estimate = generate_secrets(args, args.wallets or 1)
        paths, fp = [None] * len(secrets), None
        warn_weak_entropy(estimate)
    count = len(secrets)
    plan = strip_plan(count, args.copies or 2, args.encrypt)
    password = ask_twice(_("BIP38 password: ")) if args.encrypt else None
    wallets = []
    for w, (secret, prefix) in enumerate(zip(secrets, prefixes)):
        if prefix:
            print(_("wallet {n}/{total}").format(n=w + 1, total=count) + ": "
                  + _("searching {prefix}… (~{tries} attempts, {jobs} processes)")
                  .format(prefix=address_prefix() + prefix, tries=f"{vanity_tries(prefix):,}", jobs=args.jobs),
                  file=sys.stderr)
            secret, _offset = vanity_search(secret, prefix, args.jobs)
        wif = wif_compressed(secret)
        address = p2wpkh_address(secret)
        # Self-check: the WIF must round-trip to the same secret and address.
        back, compressed = btc.secret_from_wif(wif)
        if back != secret or not compressed or p2wpkh_address(back) != address:
            raise RuntimeError(_("internal self-check failed (WIF round-trip)"))
        wallet = Wallet(address=address, path=paths[w], fingerprint=fp)
        if any(not enc for pw_, _i, _n, enc in plan if pw_ == w):
            wallet.wif = wif
        if any(enc for pw_, _i, _n, enc in plan if pw_ == w):
            wallet.bip38 = bip38_encrypt(secret, password)
            # Self-check: decrypting must give the same key back.
            if bip38_decrypt(wallet.bip38, password) != (secret, True):
                raise RuntimeError(_("internal self-check failed (BIP38 round-trip)"))
        wallets.append(wallet)
    del password
    strips = [Strip(address=wallets[w].address, key_text=wallets[w].bip38 if enc else KEY_PREFIX + wallets[w].wif,
                    encrypted=enc, wallet_no=w + 1, wallets=count, copy_no=i + 1, copies=copies,
                    path=wallets[w].path, fingerprint=fp)
              for w, i, copies, enc in plan]
    return strips, wallets, estimate


def new_seed(args, output):
    """--random-seed: let paperseed.py write a new seed next to the output
    (NAME-seed.pdf and NAME-seed.md), then read it back like --seed-file."""
    import paperseed
    name = os.path.splitext(output_paths(output)[0])[0] + "-seed"
    if not args.force:
        name = free_output(name, pdf=not args.no_pdf)
    seed_args = argparse.Namespace(entropy_file=None, entropy_string=None, entropy_prompt=False, from_md=None,
                                   words=args.words or 24, passphrase=False, path=None,
                                   copies=args.copies, force=args.force, no_pdf=args.no_pdf)
    seed, _estimate, strips, paths = paperseed.write_seed(seed_args, name)
    print(_("new seed:"))
    paperseed.print_seed(seed, strips, paths)
    return read_seed_file(paths[-1])


def markdown(strips, wallets, estimate):
    """The Markdown twin of the PDF: the same keys, addresses, paths and guides."""
    fields = [("tool", "paperwallet.py"), ("network", btc.NETWORK_NAME), ("wallets", len(wallets))]
    if estimate is not None:
        fields.append(("user entropy", f"~{int(estimate.bits)} bits ({estimate.kind})"))
    for n, w in enumerate(wallets, 1):
        copies = [s for s in strips if s.wallet_no == n]
        enc = sum(s.encrypted for s in copies)
        fields += [("wallet", n), ("address", w.address)]
        if w.wif:
            fields.append(("wif", w.wif))
        if w.bip38:
            fields.append(("bip38", w.bip38))
        if w.path:
            fields += [("path", w.path), ("seed fingerprint", w.fingerprint)]
        fields.append(("copies", f"{len(copies)} ({len(copies) - enc} WIF + {enc} BIP38)"))
    spend = spend_rows(strips[0])
    sections = [(spend[0][2], md_lines(spend[1:])),
                (_("HOW TO STORE IT"), md_lines(store_rows(
                    _("• Keep the BIP38 password elsewhere, never with the card.")
                    if any(w.bip38 for w in wallets) else None)[1:]))]
    if any(w.path for w in wallets):
        origin = origin_rows(next(w.path for w in wallets if w.path))
        sections.append((origin[0][2], [" ".join(text for _f, _i, text in origin[1:])]))
    return md_document(_("Bitcoin paper wallet"), fields, sections)


# ----------------------------------------------------------------------------
# Command line
# ----------------------------------------------------------------------------

def default_jobs():
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def parse_args(argv):
    ap = argparse.ArgumentParser(
        description=_("Generate an offline Bitcoin P2WPKH paper wallet as a duplex A4 PDF."))
    src = add_common_args(ap, "paperwallet.pdf")
    src.add_argument("--seed-file", dest="seed_file", metavar="FILE.md",
                     help=_("derive the keys from the seed in a Markdown file written by paperseed.py"))
    src.add_argument("--random-seed", action="store_true",
                     help=_("first create a new random seed with paperseed.py (NAME-seed.pdf and .md, "
                            "no passphrase), then derive the keys from it"))
    ap.add_argument("--words", type=int, choices=sorted(btc.BIP39_ENTROPY), default=None,
                    help=_("with --random-seed: number of words of the new seed (default 24)"))
    ap.add_argument("--path", metavar="PATH[,PATH...]",
                    help=_("with --seed-file: derive at these paths (to rebuild a wallet) "
                           "instead of new ones"))
    ap.add_argument("--index", type=int, default=None, metavar="N",
                    help=_("with a seed: first receive address of the account to use (default 0); "
                           "the wallets take N, N+1, ..."))
    ap.add_argument("--gift", action="store_true",
                    help=_("with a seed: derive at random paths m/184'/a'/b'/c'/d' instead of at the "
                           "receive addresses of the seed's account, a tree no wallet scans and the "
                           "account keys cannot reach"))
    ap.add_argument("-w", "--wallets", type=int, choices=range(1, 5), default=None, metavar="{1,2,3,4}",
                    help=_("number of different wallets (default 1)"))
    ap.add_argument("--vanity", metavar="PREFIX[,PREFIX...]",
                    help=_("address prefix after bc1q, for all wallets or one per wallet"))
    ap.add_argument("--jobs", type=int, default=default_jobs(), metavar="N",
                    help=_("processes for the vanity search (default: all CPU cores)"))
    ap.add_argument("--bip38", dest="encrypt", action="store_true",
                    help=_("ask a password and add BIP38-encrypted strips"))
    args = ap.parse_args(argv)
    check_common_args(ap, args)
    if args.jobs < 1:
        ap.error(_("--jobs must be at least 1"))
    if args.words and not args.random_seed:
        ap.error(_("--words needs --random-seed"))
    if args.path and not args.seed_file:
        ap.error(_("--path needs --seed-file"))
    if args.gift and not (args.seed_file or args.random_seed):
        ap.error(_("--gift needs --seed-file or --random-seed"))
    if args.gift and args.path:
        ap.error(_("--gift makes new paths: it cannot be used with --path"))
    if args.index is not None:
        if not (args.seed_file or args.random_seed):
            ap.error(_("--index needs --seed-file or --random-seed"))
        if args.gift or args.path:
            ap.error(_("--index cannot be used with --gift or --path"))
        if not 0 <= args.index < btc.HARDENED - 4:
            ap.error(_("--index must be between 0 and 2147483643"))
    args.index = args.index or 0
    if (args.seed_file or args.random_seed) and args.vanity:
        ap.error(_("--vanity cannot be used with a seed: the derivation path fixes the key"))
    if args.from_md:
        for option, used in (("-w/--wallets", args.wallets), ("--vanity", args.vanity), ("--path", args.path),
                             ("--bip38", args.encrypt), ("--words", args.words), ("--gift", args.gift)):
            if used:
                ap.error(_("--from-md takes the wallets from the file: it cannot be used with {option}")
                         .format(option=option))
    if args.path and args.wallets and args.wallets != len(args.path.split(",")):
        ap.error(_("--wallets and the number of --path entries differ"))
    return args


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    select_language(argv)
    args = parse_args(argv)
    try:
        seed, estimate = None, None
        if args.from_md:
            network = network_of(args, dict(read_md(args.from_md, "paperwallet.py"))["network"], args.from_md)
        elif args.seed_file:
            seed = read_seed_file(args.seed_file)
            network = network_of(args, seed["network"], args.seed_file)
        else:
            network = args.network
        announce_network(network)
        # Chosen (and said) before the prompts and the vanity search.
        output = choose_output(args, pdf=not args.no_pdf, md=not args.from_md)
        if args.from_md:
            strips, wallets = wallets_from_md(args)
        else:
            if args.random_seed:
                seed = new_seed(args, output)
            strips, wallets, estimate = build_wallets(args, seed)
        pdf = None if args.no_pdf else render_pdf(strips, _("Bitcoin paper wallet"))
        text = None if args.from_md else markdown(strips, wallets, estimate)
        paths = write_outputs(output, pdf, text, overwrite=args.force)
    except (ValueError, RuntimeError, OSError) as e:
        # Only our own messages / OS errors here: none of them carry secrets.
        print(_("error: {message}").format(message=_(str(e))), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(_("aborted"), file=sys.stderr)
        return 130
    warn_user_entropy(estimate)
    # Only public information goes to the console.
    for w, wallet in enumerate(wallets):
        if len(wallets) == 1:
            print(_("address: {address}").format(address=wallet.address))
        else:
            print(_("wallet {n}/{total}").format(n=w + 1, total=len(wallets)) + ": " + wallet.address)
        if wallet.path:
            print("  " + _("path: {path}").format(path=wallet.path))
    if pdf is not None:
        encrypted = sum(s.encrypted for s in strips)
        sheets = -(-len(strips) // STRIPS_PER_SHEET)
        print(_("strips: {plain} WIF + {encrypted} BIP38 · A4 sheets: {sheets}")
              .format(plain=len(strips) - encrypted, encrypted=encrypted, sheets=sheets))
    for path in paths:
        print(_("written: {path} (mode 0600)").format(path=path))
    standard = [btc.parse_path(w.path)[-1] for w in wallets if w.path and btc.is_wallet_path(w.path)]
    if standard and not (args.path or args.from_md):
        print(_("next time use --index {index} for new wallets from this seed").format(index=max(standard) + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
