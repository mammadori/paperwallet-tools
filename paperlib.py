#!/usr/bin/env python3
"""
paperlib.py - user interface shared by paperwallet.py and paperseed.py.

Localisation, reading and estimating user entropy, prompts, the command-line
options common to both tools, and the PDF layout: duplex A4 sheets with two
roll-fold strips that become credit-card sized cards with the secret
innermost, aligned security patterns, seal bands, fold marks; plus the
Markdown twin of every PDF and the 0600, never-overwrite output files.

No key, address or encryption is computed here: that is all in btccore.py,
which is imported first and disables the network for the whole process.
"""

import btccore as btc  # first: disables the network before anything else is imported
from btccore import (ENTROPY_SEPARATORS, NETWORK_NAMES, derive_secrets, hex_digits,  # noqa: F401
                     is_test_network, normalize_entropy, set_network, wipe)

import argparse
import ast
import getpass
import gettext
import io
import math
import os
import random
import string
import sys
import unicodedata
import zlib
from dataclasses import dataclass

import qrcode
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.pdfgen.canvas import FILL_EVEN_ODD

MAX_ENTROPY_FILE = 64 * 1024 * 1024


# =============================================================================
# Localisation
#
# English is the source language (the msgids); every other supported language
# has a gettext catalog in locale/<lang>/LC_MESSAGES/paperwallet.po. The .po
# file is read directly, so no msgfmt/.mo build step is needed.
# =============================================================================

LANGUAGES = ("en", "it")
DOMAIN = "paperwallet"
LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locale")


def po_path(lang):
    return os.path.join(LOCALE_DIR, lang, "LC_MESSAGES", DOMAIN + ".po")


def load_po(path):
    """Parse a .po file into {msgid: msgstr}. Entries are separated by blank
    lines; fuzzy, untranslated entries and the header are skipped."""
    with open(path, encoding="utf-8") as f:
        blocks = f.read().split("\n\n")
    catalog = {}
    for block in blocks:
        fields, key, fuzzy = {}, None, False
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("#,") and "fuzzy" in line:
                fuzzy = True
            elif line.startswith("#") or not line:
                continue
            elif line.startswith('"'):
                fields[key] += ast.literal_eval(line)  # continuation line
            else:
                key, _sep, value = line.partition(" ")
                fields[key] = ast.literal_eval(value)
        msgid, msgstr = fields.get("msgid"), fields.get("msgstr")
        if msgid and msgstr and not fuzzy:
            catalog[msgid] = msgstr
    return catalog


class POTranslations(gettext.NullTranslations):
    def __init__(self, catalog):
        super().__init__()
        self._catalog = catalog

    def gettext(self, message):
        return self._catalog.get(message, message)


def detect_language(environ=None):
    """Pick the language from the POSIX locale variables, in gettext priority
    order. Anything other than a supported language falls back to English."""
    environ = os.environ if environ is None else environ
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = environ.get(var)
        if not value:
            continue
        for item in value.split(":"):  # LANGUAGE may be a priority list
            code = item.split(".")[0].split("@")[0].split("_")[0].lower()
            if code in LANGUAGES:
                return code
        return "en"
    return "en"


_translation = gettext.NullTranslations()


def _(message):
    return _translation.gettext(message)


def set_language(lang):
    global _translation
    if lang not in LANGUAGES:
        raise ValueError(f"unsupported language: {lang}")
    _translation = gettext.NullTranslations() if lang == "en" else POTranslations(load_po(po_path(lang)))


def read_user_entropy(args):
    """Return the user-supplied entropy as a bytearray (possibly empty)."""
    if args.entropy_file:
        if args.entropy_file == "-":
            data = sys.stdin.buffer.read(MAX_ENTROPY_FILE + 1)
        else:
            with open(args.entropy_file, "rb") as f:
                data = f.read(MAX_ENTROPY_FILE + 1)
        if len(data) > MAX_ENTROPY_FILE:
            raise ValueError(_("entropy file is larger than 64 MiB"))
        return bytearray(data)
    if args.entropy_string is not None:
        return bytearray(unicodedata.normalize("NFC", args.entropy_string).encode("utf-8"))
    if args.entropy_prompt:
        text = getpass.getpass(_("Entropy string (hidden): "))
        return bytearray(unicodedata.normalize("NFC", text).encode("utf-8"))
    return bytearray()


TARGET_ENTROPY_BITS = 256
DICEWARE_WORD_BITS = math.log2(7776)  # a word drawn from a 7776-word list


@dataclass
class EntropyEstimate:
    bits: float
    kind: str  # untranslated key, see entropy_kind_label()


def entropy_kind_label(kind):
    return {
        "coins": _("coin flips"),
        "dice": _("dice rolls"),
        "decimal": _("decimal digits"),
        "hex": _("hexadecimal digits"),
        "words": _("words"),
        "text": _("text"),
        "bytes": _("binary data"),
    }[kind]


def estimate_entropy(data):
    """Rough UPPER BOUND of the entropy in user input, assuming each symbol was
    chosen uniformly at random from the alphabet the input appears to use.
    Real entropy can only be lower (people are bad at being random); the
    estimate is also capped by the zlib-compressed size, which catches
    repetitions such as "1111...". It never reveals anything about the data."""
    data = bytes(data)
    if not data:
        return EntropyEstimate(0.0, "bytes")
    compressed_bits = 8 * len(zlib.compress(data, 9))
    try:
        text = unicodedata.normalize("NFC", data.decode("utf-8"))
    except UnicodeDecodeError:
        text = None
    if text is None or not all(ch.isprintable() or ch.isspace() for ch in text):
        bits, kind = 8.0 * len(data), "bytes"
    else:
        digits = hex_digits(data)  # also drops a 0x prefix
        symbols = list(digits) if digits else [ch for ch in text if ch not in ENTROPY_SEPARATORS]
        alphabet = set(symbols)
        words = text.split()
        if alphabet and alphabet <= set("01"):
            bits, kind = float(len(symbols)), "coins"
        elif alphabet and alphabet <= set("123456"):
            bits, kind = len(symbols) * math.log2(6), "dice"
        elif alphabet and alphabet <= set(string.digits):
            bits, kind = len(symbols) * math.log2(10), "decimal"
        elif alphabet and alphabet <= set(string.hexdigits):
            bits, kind = len(symbols) * 4.0, "hex"
        elif len(words) >= 2 and all(w.isalpha() for w in words):
            bits, kind = len(words) * DICEWARE_WORD_BITS, "words"
        else:
            size = (26 * any(ch.islower() for ch in text) + 26 * any(ch.isupper() for ch in text)
                    + 10 * any(ch.isdigit() for ch in text)
                    + 33 * any(not ch.isalnum() for ch in text)
                    + 100 * any(ord(ch) > 127 for ch in text))
            bits, kind = len(text) * math.log2(max(size, 2)), "text"
    return EntropyEstimate(min(bits, 8.0 * len(data), compressed_bits), kind)


def generate_secrets(args, count=1):
    """Read the user entropy given on the command line (if any), estimate it,
    and let btccore derive `count` secrets from it or from /dev/random.
    Returns (secrets, estimate): estimate is an EntropyEstimate of the user
    entropy, or None when /dev/random was used."""
    entropy = read_user_entropy(args)
    try:
        if not entropy:
            return derive_secrets(None, count), None
        estimate = estimate_entropy(entropy)
        raw = entropy
        entropy, digits = normalize_entropy(raw)
        wipe(raw)
        if digits is not None:
            print(_("entropy taken as a hexadecimal number: {digits} digits, {nbytes} bytes")
                  .format(digits=len(digits), nbytes=len(entropy)), file=sys.stderr)
        return derive_secrets(entropy, count), estimate
    finally:
        wipe(entropy)


# =============================================================================
# PDF rendering
#
# All drawing below happens in millimetres: every page starts with
# canvas.scale(mm, mm). Font sizes are given in points and multiplied by PT.
# =============================================================================

PT = 1 / mm  # one typographic point expressed in millimetres

PAGE_W, PAGE_H = A4[0] / mm, A4[1] / mm  # 210 x 297
# Each wallet copy is a strip of four panels, roll-folded into a card. From
# the top of the front side: P1 address and P2 cover (the outside of the
# card), P3 notes and P4 secret (innermost). Each inner panel is 1.5 mm
# shorter than the one wrapping it, so that it nests inside without jamming
# in the fold. Strip coordinates have their origin bottom-left; the folds
# are horizontal, so heights are the same on both sides of the paper.

GAP = 10.0  # space between the strips, used by the crop marks
SEAL_H = 7.0  # band at the open edge of the folded card, where tape seals it
CROP_OFFSET, CROP_LEN = 1.0, 3.5


@dataclass(frozen=True)
class Geometry:
    """Size of a strip and how many go on an A4 sheet."""
    width: float
    heights: tuple  # P1, P2, P3, P4
    per_sheet: int

    @property
    def panel_h(self):
        return dict(zip((1, 2, 3, 4), self.heights))

    @property
    def height(self):
        return sum(self.heights)

    @property
    def panel_y(self):
        """Bottom edge of each panel."""
        h = self.panel_h
        return {4: 0.0, 3: h[4], 2: h[4] + h[3], 1: h[4] + h[3] + h[2]}

    @property
    def folds(self):
        """Fold lines, numbered in folding order (key side up): 1 turns P4
        onto P3, 2 turns both onto P2, 3 turns P1 down over the stack."""
        y = self.panel_y
        return {1: y[3], 2: y[2], 3: y[1]}

    @property
    def folded(self):
        """Where each panel lies once folded, as height v -> a + s * v measured
        on the back side (which stays face up while folding). Stack from the
        top: P1, P3, P4 with the secret facing P3, P2."""
        f = self.folds
        return {1: (2 * f[3], -1), 2: (0.0, 1), 3: (2 * f[2], -1), 4: (2 * f[2] - 2 * f[1], 1)}

    def decoy_offset(self, panel):
        """(dy, flip) that places the secret-face layout on another panel so
        that, once folded, it lies exactly over the secret: a height v on the
        secret face maps to dy + flip * v on that panel's back side."""
        a4, s4 = self.folded[4]
        a, s = self.folded[panel]
        return s * (a4 - a) - self.panel_y[panel], s * s4

    @property
    def origin_x(self):
        return (PAGE_W - self.per_sheet * self.width - (self.per_sheet - 1) * GAP) / 2

    @property
    def origin_y(self):
        return (PAGE_H - self.height) / 2


# paperwallet.py: two ID-1 (credit-card, 85.6 x 54 mm) cards per sheet.
CARD = Geometry(85.6, (54.0, 54.0, 52.5, 51.0), 2)
# paperseed.py: one large card per sheet (148 x 60 mm, the width of A6).
WIDE = Geometry(148.0, (60.0, 60.0, 58.5, 57.0), 1)

# The card geometry, as plain names.
STRIP_W, PANEL_H, STRIP_H = CARD.width, CARD.panel_h, CARD.height
PANEL_Y, FOLDS, FOLDED = CARD.panel_y, CARD.folds, CARD.folded
STRIPS_PER_SHEET, ORIGIN_X, ORIGIN_Y = CARD.per_sheet, CARD.origin_x, CARD.origin_y


def decoy_offset(panel, geometry=CARD):
    return geometry.decoy_offset(panel)


# Open Sans for all text, taken from the fonts installed on the system (Debian:
# fonts-open-sans). Keys and addresses stay in Courier, a monospace PDF base
# font, so that every character is unambiguous.
SANS, SANS_BOLD, SANS_ITALIC = "OpenSans", "OpenSans-Bold", "OpenSans-Italic"
MONO = "Courier-Bold"
FONT_FILES = {SANS: "OpenSans-Regular.ttf", SANS_BOLD: "OpenSans-Bold.ttf",
              SANS_ITALIC: "OpenSans-Italic.ttf"}
# Used under the same names when Open Sans is not installed.
FALLBACK_FACES = {SANS: "Helvetica", SANS_BOLD: "Helvetica-Bold", SANS_ITALIC: "Helvetica-Oblique"}
FONT_DIRS = [os.path.expanduser("~/.local/share/fonts"), os.path.expanduser("~/.fonts"),
             "/usr/local/share/fonts", "/usr/share/fonts"]


def find_font_files(dirs=None):
    """Map each Open Sans font name to its static .ttf file, or None if any of
    the three is missing (variable fonts are not usable by reportlab)."""
    wanted = {filename: name for name, filename in FONT_FILES.items()}
    found = {}
    for base in FONT_DIRS if dirs is None else dirs:
        for root, _subdirs, files in os.walk(base):
            for filename in files:
                if filename in wanted and wanted[filename] not in found:
                    found[wanted[filename]] = os.path.join(root, filename)
    return found if len(found) == len(FONT_FILES) else None


def register_fonts():
    """Register Open Sans (embedded as a subset), or Helvetica under the same
    names if it is not installed. Safe to call more than once."""
    if SANS in pdfmetrics.getRegisteredFontNames():
        return
    files = find_font_files()
    if files is None:
        print(_("warning: Open Sans not found, using Helvetica (install the fonts-open-sans package)"),
              file=sys.stderr)
        for name, face in FALLBACK_FACES.items():
            pdfmetrics.registerFont(pdfmetrics.Font(name, face, "WinAnsiEncoding"))
        return
    for name, path in files.items():
        pdfmetrics.registerFont(TTFont(name, path))


# Desaturated sage palette for text and the inner-flap foliage.
C = {k: HexColor(v) for k, v in dict(
    leaf="#a3b19e", leaf_dark="#8d9c88", leaf_pale="#b9c3b5",
    ink="#2d322d", ink_soft="#5d655c", mark="#000000",
    tint="#7f8c7b", key="#b8732e", tape="#d7b23c", test="#c0392b",
).items()}


def chunk_text(text, group=4, per_line=3):
    """Split a key/address into lines of space-separated 4-char groups."""
    groups = [text[i:i + group] for i in range(0, len(text), group)]
    return [" ".join(groups[i:i + per_line]) for i in range(0, len(groups), per_line)]


QR_QUIET = 1.6


def qr_matrix(data):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.get_matrix()


RING_MARGIN = 2.0  # white border around a QR code, where its ring of text runs


def draw_qr(c, data, x, y, size, quiet=QR_QUIET):
    """Draw a vector QR code (no raster image, no temp file) on a white square
    with a border for the ring of text around it (qr_ring_runs)."""
    matrix = qr_matrix(data)
    n = len(matrix)
    c.setFillColor(white)
    c.roundRect(x - RING_MARGIN, y - RING_MARGIN, size + 2 * RING_MARGIN, size + 2 * RING_MARGIN,
                1.4, stroke=0, fill=1)
    inner = size - 2 * quiet
    m = inner / n
    c.setFillColor(C["mark"])
    path = c.beginPath()
    for row, cells in enumerate(matrix):
        col = 0
        while col < n:
            if cells[col]:
                start = col
                while col < n and cells[col]:
                    col += 1
                # Tiny overlap avoids hairline gaps between adjacent modules.
                path.rect(x + quiet + start * m, y + quiet + (n - 1 - row) * m,
                          (col - start) * m + 0.01, m + 0.01)
            else:
                col += 1
    c.drawPath(path, stroke=0, fill=1)


def panel(c, x, y, w, h, alpha=0.86, r=1.6):
    """Translucent white panel that keeps text readable over the artwork."""
    c.saveState()
    c.setFillColor(white)
    c.setFillAlpha(alpha)
    c.roundRect(x, y, w, h, r, stroke=0, fill=1)
    c.restoreState()


def fit_size(c, text, font, size_pt, max_width=None):
    """Font size (mm) for text, shrunk if needed so that it fits in max_width."""
    size = size_pt * PT
    while max_width and size > 3.5 * PT and c.stringWidth(text, font, size) > max_width:
        size *= 0.96
    return size


def label(c, text, x, y, size_pt=6.0, font=SANS_BOLD, color="ink", anchor="left",
          max_width=None):
    """Draw one line of text; with max_width the font shrinks until it fits
    (translations can be noticeably longer than the English source)."""
    size = fit_size(c, text, font, size_pt, max_width)
    c.setFillColor(C[color])
    c.setFont(font, size)
    if anchor == "right":
        c.drawRightString(x, y, text)
    elif anchor == "center":
        c.drawCentredString(x, y, text)
    else:
        c.drawString(x, y, text)


# ----------------------------------------------------------------------------
# Background artwork: one solarpunk illustration, embedded once in the PDF and
# shown through a different "view" (crop) on some faces of the strip.
# ----------------------------------------------------------------------------

ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
BACKGROUND = os.path.join(ASSET_DIR, "solarpunk-vault.jpg")

# Views on the artwork as fractions of the image size (origin top-left), so
# they do not depend on its resolution: centre x, centre y and width; the
# height follows from the aspect ratio of the face.
VIEW_COVER = (0.611, 0.478, 0.778)  # the vault door: the only Bitcoin logo of the strip
VIEW_TERRACES = (0.323, 0.499, 0.646)  # left terraces and waterfalls, no logo
VIEW_RIVER = (0.419, 0.553, 0.455)  # river and bridges, no logo

_artwork_size = []


def artwork_size():
    if not _artwork_size:
        _artwork_size.extend(ImageReader(BACKGROUND).getSize())
    return _artwork_size


def draw_artwork(c, w, h, view):
    """Fill the (already clipped) w x h face with the given view of the artwork.
    The whole image is placed, scaled and shifted, so reportlab embeds the
    JPEG a single time and every face just references it."""
    iw, ih = artwork_size()
    cx, cy, vw = view[0] * iw, view[1] * ih, view[2] * iw
    vh = vw * h / w
    left = min(max(cx - vw / 2, 0), iw - vw)  # keep the view inside the image
    top = min(max(cy - vh / 2, 0), ih - vh)
    scale = w / vw  # millimetres per pixel
    c.drawImage(BACKGROUND, -left * scale, h + top * scale - ih * scale, iw * scale, ih * scale)


def _leaf(c, x, y, length, angle, color):
    c.saveState()
    c.translate(x, y)
    c.rotate(angle)
    c.setFillColor(color)
    p = c.beginPath()
    p.moveTo(0, 0)
    p.curveTo(length * 0.3, length * 0.28, length * 0.75, length * 0.22, length, 0)
    p.curveTo(length * 0.75, -length * 0.22, length * 0.3, -length * 0.28, 0, 0)
    p.close()
    c.drawPath(p, stroke=0, fill=1)
    c.restoreState()


def draw_foliage(c, w, h, rng, count=260):
    """Dense leaves behind the notes, a further layer over the folded key."""
    for _i in range(count):
        _leaf(c, rng.uniform(-2, w + 2), rng.uniform(-2, h + 2), rng.uniform(1.5, 3.2),
              rng.uniform(0, 360), rng.choice((C["leaf"], C["leaf_dark"], C["leaf_pale"])))


# ----------------------------------------------------------------------------
# The faces of a strip. Each function draws in local coordinates (0..w, 0..h)
# and is called with the canvas already translated and clipped to the panel.
# ----------------------------------------------------------------------------

# Layout shared by the address and key faces: QR on the left, text on the right.
QR_X, QR_Y, QR_SIZE = 4.0, 4.0, 32.0
TEXT_X, TEXT_SIZE, TEXT_LEADING = 41.0, 8.6, 3.7


@dataclass
class SecretLayout:
    """Where a face prints a secret, in that face's coordinates: the QR code
    (x, y, size, data; data only for its module count) and the text runs
    (x, baseline, text, size in points, angle in degrees). The security
    pattern of the faces folded against it is drawn from this."""
    qr: tuple
    runs: list


def qr_text_layout(data, size_pt=TEXT_SIZE, leading=TEXT_LEADING, per_line=3, split=False,
                   qr=(QR_X, QR_Y, QR_SIZE), text_x=TEXT_X):
    """Layout of qr_and_text(): QR on the left, grouped text on the right.
    A script type prefix ("p2wpkh:") gets a line of its own."""
    prefix, colon, rest = data.rpartition(":")
    lines = ([prefix + colon] if colon else []) + chunk_text(rest, per_line=per_line)
    top = 9.8 + len(lines) * leading
    runs = [(text_x, top - i * leading, line, size_pt, 0) for i, line in enumerate(lines)]
    return SecretLayout(qr=(*qr, data), runs=runs + qr_ring_runs(data, *qr, split))


RING_PT = 4.2  # the exact QR content, unspaced, in a ring around the code
RING_GAP = 0.5


def qr_ring_runs(data, x, y, size, split=False):
    """Runs that write data around the QR square, clockwise from the top-left
    corner, each side turned to face outwards. It shows exactly what the code
    contains: one unbroken string, without the spaces of the grouped text.
    The string is repeated (separated by '·') as many whole times as the
    perimeter allows, never cut, and the characters are spread evenly over all
    four sides (a sixth element of each run gives their pitch).

    With split (private keys, which fit twice) each copy takes two sides,
    cut in half at the same point: the first copy runs along the top and
    goes on down the right side, the second along the bottom and goes on up
    the left side; draw_ring_arrows() marks the two turns."""
    advance = 0.6 * RING_PT * PT  # Courier: every glyph is 0.6 em wide
    slots = 4 * int(size / advance + 1e-9)
    if split and 2 * len(data) <= slots:
        half = (len(data) + 1) // 2
        chunks = [data[:half], data[half:]] * 2
        sides = [((x, y + size + RING_GAP), 0), ((x + size + RING_GAP, y + size), -90),
                 ((x + size, y - RING_GAP), 180), ((x - RING_GAP, y), 90)]
        return [(ox, oy, chunk, RING_PT, angle, size / half) for ((ox, oy), angle), chunk in zip(sides, chunks)]
    unit = data + "·"
    reps = max(1, (slots + 1) // len(unit))
    text = (unit * reps)[:-1]
    counts = [len(text) // 4 + (i < len(text) % 4) for i in range(4)]
    # (origin of the side, angle): top, right, bottom, left.
    sides = [((x, y + size + RING_GAP), 0), ((x + size + RING_GAP, y + size), -90),
             ((x + size, y - RING_GAP), 180), ((x - RING_GAP, y), 90)]
    runs, start = [], 0
    for ((ox, oy), angle), count in zip(sides, counts):
        runs.append((ox, oy, text[start:start + count], RING_PT, angle, size / count))
        start += count
    return runs


def draw_ring_arrows(c, x, y, size, r=1.75):
    """Small curved arrows at the top-right and bottom-left corners of a
    split ring: the copy along the top goes on down the right side, the one
    along the bottom goes on up the left side."""
    c.saveState()
    c.setStrokeColor(C["ink_soft"])
    c.setFillColor(C["ink_soft"])
    c.setLineWidth(0.18)
    for cx, cy, start, tip, dx, dy in ((x + size, y + size, 90, (x + size + r, y + size), 0, -1),
                                       (x, y, 270, (x - r, y), 0, 1)):
        p = c.beginPath()
        p.arc(cx - r, cy - r, cx + r, cy + r, start, -90)  # clockwise quarter circle
        c.drawPath(p, stroke=1, fill=0)
        tx, ty = tip  # arrowhead pointing along the next side
        head = c.beginPath()
        head.moveTo(tx + dx * 0.55, ty + dy * 0.55)
        head.lineTo(tx - 0.26, ty - dy * 0.05)
        head.lineTo(tx + 0.26, ty - dy * 0.05)
        head.close()
        c.drawPath(head, stroke=0, fill=1)
    c.restoreState()


def qr_and_text(c, w, data, note, size_pt=TEXT_SIZE, leading=TEXT_LEADING, per_line=3, split=False,
                qr=(QR_X, QR_Y, QR_SIZE), text_x=TEXT_X, note_pt=5.4):
    """QR code, grouped monospace text and a one-line note under it."""
    layout = qr_text_layout(data, size_pt, leading, per_line, split, qr, text_x)
    draw_qr(c, data, *qr)
    if split:
        draw_ring_arrows(c, *qr)
    lines = [r for r in layout.runs if len(r) == 5]
    panel(c, text_x - 2.5, 9, w - text_x - 0.5, 6 + len(lines) * leading)
    draw_runs(c, layout.runs)
    panel(c, text_x - 2.5, 4, w - text_x - 0.5, 4.2, alpha=0.8)
    label(c, note, text_x, 5.4, note_pt, SANS_ITALIC, "ink_soft", max_width=w - text_x - 4)
    return layout


def run_pitch(c, run):
    """Distance between the characters of a run: its own pitch if it has one
    (rings), else the natural advance of the monospace font."""
    natural = c.stringWidth("0", MONO, run[3] * PT)
    return run[5] if len(run) > 5 else natural


def draw_runs(c, runs):
    """Monospace text runs of a SecretLayout: (x, y, text, size, angle[, pitch])."""
    c.setFillColor(C["ink"])
    for run in runs:
        x, y, text, size_pt, angle = run[:5]
        c.saveState()
        c.translate(x, y)
        c.rotate(angle)
        t = c.beginText(0, 0)
        t.setFont(MONO, size_pt * PT)
        t.setCharSpace(run_pitch(c, run) - c.stringWidth("0", MONO, size_pt * PT))
        t.textOut(text)
        c.drawText(t)
        c.restoreState()


def header_band(c, w, top, title, action):
    """Title bar of the address and key faces: title left, action word right."""
    panel(c, 3, top - 5.6, w - 6, 5.6)
    label(c, action, w - 5, top - 3.5, 5.6, SANS, "ink_soft", "right")
    room = w - 13 - c.stringWidth(action, SANS, 5.6 * PT)
    label(c, title, 5, top - 3.5, 6.4, SANS_BOLD, max_width=room)


def pill(c, text, x, y, size_pt, font, color, anchor, max_width, alpha):
    """Text on a translucent panel sized to the text itself."""
    width = c.stringWidth(text, font, fit_size(c, text, font, size_pt, max_width)) + 4
    left = {"left": x - 2, "right": x - width + 2, "center": x - width / 2}[anchor]
    c.saveState()
    c.setFillColor(white)
    c.setFillAlpha(alpha)
    c.roundRect(left, y - 1.8, width, 5.2, 1.6, stroke=0, fill=1)
    c.restoreState()
    label(c, text, x, y, size_pt, font, color, anchor, max_width)


def seal_band(c, w, h):
    """Hatched band along the top of the address and cover faces: once folded
    both meet at the open edge of the card, which is taped shut there."""
    c.saveState()
    c.setFillColor(white)
    c.setFillAlpha(0.55)
    c.rect(0, h - SEAL_H, w, SEAL_H, stroke=0, fill=1)
    c.restoreState()
    c.setStrokeColor(C["ink_soft"])
    c.setLineWidth(0.15)
    p = c.beginPath()
    x = -SEAL_H
    while x < w:
        p.moveTo(x, h - SEAL_H)
        p.lineTo(x + SEAL_H, h)
        x += 1.6
    c.drawPath(p, stroke=1, fill=0)
    pill(c, _("SEAL · tape over this edge, sign across the tape"), w / 2, h - SEAL_H / 2 - 0.8,
         5.4, SANS_BOLD, "ink", "center", w - 12, 0.9)


def draw_rows(c, rows, w, top, x=9.0, leading=3.4):
    """Lines of (font, indent in mm, text) over a translucent panel."""
    panel(c, 5, top - len(rows) * leading - 2.5, w - 10, len(rows) * leading + 5, alpha=0.9, r=2.5)
    y = top - 1.2
    for font, indent, text in rows:
        label(c, text, x + indent, y, 6.0 if font == SANS_BOLD else 5.3, font,
              "ink" if font == SANS_BOLD else "ink_soft", max_width=w - 2 * x - indent)
        y -= leading


def draw_tint(c, w, h, rng):
    """Security-envelope tint: two crossing sets of wavy lines, with a random
    phase, amplitude and period for every line of every print."""
    c.setStrokeColor(C["tint"])
    c.setLineWidth(0.22)
    for slope in (0.35, -0.35):
        p = c.beginPath()
        y = -w * 0.35 - 2
        while y < h + w * 0.35 + 2:
            phase, amp, period = rng.uniform(0, 2 * math.pi), rng.uniform(0.4, 0.9), rng.uniform(5, 9)
            for k in range(31):
                x = -1 + k * (w + 2) / 30
                point = (x, y + slope * x + amp * math.sin(phase + 2 * math.pi * x / period))
                (p.lineTo if k else p.moveTo)(*point)
            y += 1.6
        c.drawPath(p, stroke=1, fill=0)


def draw_secret_noise(c, layout, rng):
    """Random marks exactly where a face prints the modules of its QR code and
    the characters of its secret (that face's coordinates). It is neither a QR
    code (no finder patterns) nor text, so it can be neither scanned nor
    mistaken for a key; against light it overlaps the real secret and
    scrambles it."""
    if layout.qr:
        x, y, size, data = layout.qr
        n = len(qr_matrix(data))
        m = (size - 2 * QR_QUIET) / n
        c.setFillColor(C["mark"])
        p = c.beginPath()
        for row in range(n):
            for col in range(n):
                if rng.getrandbits(1):
                    p.rect(x + QR_QUIET + col * m, y + QR_QUIET + row * m, m + 0.01, m + 0.01)
        c.drawPath(p, stroke=0, fill=1)

    c.setStrokeColor(C["ink"])
    c.setLineCap(1)
    for run in layout.runs:
        x0, base, text, size_pt, angle = run[:5]
        size = size_pt * PT
        advance = run_pitch(c, run)
        glyph_h = 0.62 * size
        c.saveState()
        c.translate(x0, base)
        c.rotate(angle)
        c.setLineWidth(0.1 * size)  # about the stroke of Courier-Bold
        p = c.beginPath()
        for j, ch in enumerate(text):
            if ch == " ":
                continue
            left = j * advance
            for _k in range(4):
                p.moveTo(left + rng.uniform(0.1, 0.9) * advance, rng.uniform(-0.25, 1) * glyph_h)
                p.lineTo(left + rng.uniform(0.1, 0.9) * advance, rng.uniform(-0.25, 1) * glyph_h)
        c.drawPath(p, stroke=1, fill=0)
        c.restoreState()
    c.setLineCap(0)


def face_decoy(c, layout, w, h, rng, dy, flip, mirror=False):
    """Inner face that lies over or under the secret once folded: tint plus
    secret noise aligned with it. mirror is for the front side, where the
    secret is seen through the paper reversed left to right."""
    draw_tint(c, w, h, rng)
    c.saveState()
    if mirror:
        c.translate(w, 0)
        c.scale(-1, 1)
    c.translate(0, dy)
    c.scale(1, flip)
    draw_secret_noise(c, layout, rng)
    c.restoreState()
    pill(c, _("security pattern · not a key"), w / 2, 1.4, 5.0, SANS_ITALIC, "ink_soft",
         "center", w - 10, 0.85)


def face_cover(c, w, h, subtitle, info, badge, sealed_note, copy_text):
    """P2, outside (printed upside down, reads correctly once folded). The
    vault door of the artwork is the strip's single Bitcoin logo."""
    draw_artwork(c, w, h, VIEW_COVER)
    seal_band(c, w, h)
    panel(c, 3, 14, 38, 26, alpha=0.82, r=3)
    label(c, "BITCOIN", 6, 30.5, 17, SANS_BOLD, max_width=32)
    label(c, subtitle, 6.2, 24.5, 7.5, SANS, "ink_soft", max_width=32)
    label(c, info, 6.2, 19, 5.6, SANS_ITALIC, "ink_soft", max_width=32)
    pill(c, badge, w - 5, 5.8, 5.6, SANS_BOLD, "ink", "right", 36, 0.9)
    pill(c, sealed_note, 5, 5.8, 5.2, SANS_ITALIC, "ink_soft", "left", 38, 0.8)
    pill(c, copy_text, w - 5, h - SEAL_H - 4.5, 5.2, SANS, "ink_soft", "right", 50, 0.8)


def copy_label(copy_no, copies, item_no=1, items=1):
    text = _("copy {n}/{total}").format(n=copy_no, total=copies)
    if items > 1:
        text = _("wallet {n}/{total}").format(n=item_no, total=items) + "  ·  " + text
    return text


def face_store(c, w, h, rng, secret_line, extra_rows=()):
    """P2, back side: how to keep the card. secret_line is about the password
    or passphrase kept apart, or None; extra_rows follow in the same panel."""
    draw_tint(c, w, h, rng)
    rows = store_rows(secret_line)
    if extra_rows:
        draw_rows(c, rows + [(SANS, 0, "")] + list(extra_rows), w, h - 4, leading=3.2)
    else:
        draw_rows(c, rows + [(SANS, 0, _("• Check the balance now and then, with the address only."))],
                  w, h - 5)


def store_rows(secret_line=None):
    return [
        (SANS_BOLD, 0, _("HOW TO STORE IT")),
        (SANS, 0, _("• Keep it folded and sealed. A broken seal means the secret")),
        (SANS, 2.5, _("may have been seen: move the funds to a new wallet.")),
        (SANS, 0, _("• Dry and dark, in a sealed bag, away from heat and fire.")),
        (SANS, 0, _("• Copies in different places; never photograph, scan")),
        (SANS, 2.5, _("or photocopy the inside.")),
        (SANS, 0, secret_line or _("• Tell someone you trust that it exists and where it is.")),
    ]


def md_lines(rows):
    """Guide rows of a face as Markdown: bullets become list items, indented
    rows continue the previous item."""
    out = []
    for _font, indent, text in rows:
        if indent:
            out[-1] += " " + text
        else:
            out.append("- " + text[1:].strip() if text.startswith("•") else text)
    return out


# ----------------------------------------------------------------------------
# Page geometry, crop and fold marks, the duplex layout
# ----------------------------------------------------------------------------

def strip_origin(slot, back=False, g=CARD):
    """Lower-left corner of a strip. The back side is mirrored left/right: with
    long-edge duplex on portrait A4, the point (x, y) of the front lies behind
    the point (PAGE_W - x, y) of the back."""
    x = g.origin_x + slot * (g.width + GAP)
    if back:
        x = PAGE_W - x - g.width
    return x, g.origin_y


def draw_strip_marks(c, x, y, back, g=CARD):
    """Crop marks at the corners and numbered fold marks. Seen from the front
    every fold is a mountain fold (dash-dot), from the back a valley fold
    (dashed, also drawn faintly across the strip)."""
    c.setStrokeColor(C["mark"])
    c.setLineWidth(0.25 * PT)
    for cx, sx in ((x, -1), (x + g.width, 1)):
        for cy, sy in ((y, -1), (y + g.height, 1)):
            c.line(cx + sx * CROP_OFFSET, cy, cx + sx * (CROP_OFFSET + CROP_LEN), cy)
            c.line(cx, cy + sy * CROP_OFFSET, cx, cy + sy * (CROP_OFFSET + CROP_LEN))
    outer_left = x < PAGE_W / 2  # numbers go on the page-edge side
    for n, fv in g.folds.items():
        fy = y + fv
        c.setLineWidth(0.35 * PT)
        c.setDash(*((1.0, 0.6) if back else ((2.0, 0.6, 0.4, 0.6), 0)))
        c.line(x - CROP_OFFSET - CROP_LEN - 1, fy, x - CROP_OFFSET, fy)
        c.line(x + g.width + CROP_OFFSET, fy, x + g.width + CROP_OFFSET + CROP_LEN + 1, fy)
        if back:
            c.saveState()
            c.setStrokeAlpha(0.35)
            c.line(x, fy, x + g.width, fy)
            c.restoreState()
        c.setDash()
        nx = x - CROP_OFFSET - CROP_LEN - 3.2 if outer_left else x + g.width + CROP_OFFSET + CROP_LEN + 3.2
        label(c, str(n), nx, fy - 1.0, 8, SANS_BOLD, "ink", "center")


def draw_fold_diagram(c, x, y):
    """Side view of the folded card: P1 on top, then P3, P4 with the key
    facing up, and P2; tape over the open edge on the right."""
    x0, x1, gap = x + 14, x + 60, 3.0
    y4, y3, y2, y1 = y + 8, y + 8 + gap, y + 8 + 2 * gap, y + 8 + 3 * gap
    c.setStrokeColor(C["tape"])
    c.setLineWidth(1.4)
    c.setStrokeAlpha(0.7)
    p = c.beginPath()
    p.moveTo(x1 - 6, y1 + 1)
    p.lineTo(x1 + gap + 1.6, y1 + 1)
    p.lineTo(x1 + gap + 1.6, y4 - 1)
    p.lineTo(x1 - 6, y4 - 1)
    c.drawPath(p, stroke=1, fill=0)
    c.setStrokeAlpha(1)
    c.setFillColor(C["key"])
    c.rect(x0 + 8, y3 + 0.3, 24, 1.0, stroke=0, fill=1)
    c.setStrokeColor(C["ink"])
    c.setLineWidth(0.5)
    c.setLineCap(1)
    p = c.beginPath()
    p.moveTo(x1 - 1.5, y1)  # P1, free end on the right
    p.lineTo(x0, y1)
    p.arcTo(x0 - 1.5 * gap, y4, x0 + 1.5 * gap, y1, 90, 180)  # fold 3
    p.lineTo(x1, y4)  # P2
    p.arcTo(x1 - gap, y4, x1 + gap, y2, -90, 180)  # fold 2
    p.lineTo(x0 + 3, y2)  # P3
    p.arcTo(x0 + 3 - gap / 2, y3, x0 + 3 + gap / 2, y2, 90, 180)  # fold 1
    p.lineTo(x1 - 3, y3)  # P4
    c.drawPath(p, stroke=1, fill=0)
    c.setLineCap(0)
    label(c, "3", x0 - 1.5 * gap - 2.5, (y1 + y4) / 2 - 1, 7, SANS_BOLD, "ink", "center")
    label(c, "2", x1 + gap + 4.5, (y2 + y4) / 2 - 1, 7, SANS_BOLD, "ink", "center")
    label(c, "1", x0 - 1.4, (y2 + y3) / 2 - 1, 6, SANS_BOLD, "ink", "center")
    label(c, _("address"), (x0 + x1) / 2, y1 + 1.6, 5.5, SANS, "ink_soft", "center")
    label(c, _("private key"), x0 + 20, y4 - 4.5, 5.5, SANS_BOLD, "key", "center")
    label(c, _("folded card, seen from the side"), (x0 + x1) / 2, y - 1, 5.5, SANS_ITALIC,
          "ink_soft", "center", max_width=x1 - x0 + 10)


def draw_page_furniture(c, side_text, back, g=CARD):
    """Registration targets on the vertical axis (they overlap front/back when
    held against light), printing, cutting and folding instructions."""
    c.setStrokeColor(C["mark"])
    c.setLineWidth(0.25 * PT)
    for ty in (g.origin_y / 2, PAGE_H - g.origin_y / 2):
        c.circle(PAGE_W / 2, ty, 2.0, stroke=1, fill=0)
        c.line(PAGE_W / 2 - 3.5, ty, PAGE_W / 2 + 3.5, ty)
        c.line(PAGE_W / 2, ty - 3.5, PAGE_W / 2, ty + 3.5)
    top = PAGE_H - g.origin_y / 2 - 1
    half = PAGE_W / 2 - g.origin_x - 7
    label(c, side_text, g.origin_x, top, 7, SANS_BOLD, "ink_soft", max_width=half)
    label(c, _("A4 · print at 100% (no scaling) · duplex, flip on LONG edge"),
          PAGE_W - g.origin_x, top, 6.5, SANS, "ink_soft", "right", max_width=half)
    if not back:
        label(c, _("Cut on the crop marks."), g.origin_x, g.origin_y / 2 - 1, 6.5, SANS, "ink_soft",
              max_width=half)
        label(c, _("Lines 1–3: mountain folds on this side; the steps are on the back."),
              PAGE_W - g.origin_x, g.origin_y / 2 - 1, 6.5, SANS, "ink_soft", "right", max_width=half)
        return
    steps = [
        (SANS_BOLD, _("FOLDING: key side up, lines in order")),
        (SANS, _("1  fold the key panel up along line 1")),
        (SANS, _("2  fold up again along line 2")),
        (SANS, _("3  fold the top panel down along line 3: address outside")),
        (SANS, _("4  tape the open edge (SEAL) and sign across the tape")),
        (SANS_ITALIC, _("Inner panels are slightly shorter, so that they nest.")),
    ]
    y = g.origin_y - 7  # closer lines when the bottom margin is narrow
    leading = min(4.2, (g.origin_y - 10) / 5.5)
    for font, text in steps:
        label(c, text, g.origin_x, y, 6.5 if font == SANS_BOLD else 6, font,
              "ink" if font == SANS_BOLD else "ink_soft", max_width=half)
        y -= leading
    draw_fold_diagram(c, PAGE_W / 2 + 8, min(8.0, g.origin_y - 24))


def draw_test_mark(c, w, h, qr=None):
    """Big diagonal watermark on every panel of a test-network strip, so that
    it can never be taken for a real wallet. With qr = (x, y, size) the
    panel's QR code (and its ring) is left out, so that it still scans."""
    text = btc.NETWORK_NAME.upper() + " · " + _("NO VALUE")
    c.saveState()
    if qr is not None:
        qx, qy, qs = qr
        clip = c.beginPath()
        clip.rect(0, 0, w, h)
        clip.rect(qx - RING_MARGIN, qy - RING_MARGIN, qs + 2 * RING_MARGIN, qs + 2 * RING_MARGIN)
        c.clipPath(clip, stroke=0, fill=0, fillMode=FILL_EVEN_ODD)
    c.translate(w / 2, h / 2)
    c.rotate(math.degrees(math.atan2(h, w)))
    c.setFillColor(C["test"])
    c.setFillAlpha(0.55)
    size = fit_size(c, text, SANS_BOLD, 26, math.hypot(w, h) - 14)
    c.setFont(SANS_BOLD, size)
    c.drawCentredString(0, -size / 3, text)
    c.restoreState()


def _at(c, x, y, w, h, rotate=False):
    """Enter a panel's local coordinate system, clipped to the panel."""
    c.saveState()
    if rotate:
        c.translate(x + w, y + h)
        c.rotate(180)
    else:
        c.translate(x, y)
    clip = c.beginPath()
    clip.rect(0, 0, w, h)
    c.clipPath(clip, stroke=0, fill=0)


CARD_QR_RECTS = {("front", 1): (QR_X, QR_Y, QR_SIZE), ("back", 4): (QR_X, QR_Y, QR_SIZE)}


def draw_front(c, strip, x, y, rng):
    """Outside of the card (P1, P2) plus the front of the inner panels."""
    g = getattr(strip, "geometry", CARD)
    faces = strip.faces()
    qrs = getattr(strip, "qr_rects", CARD_QR_RECTS)
    for n, rotate in ((1, False), (2, True), (3, False), (4, False)):
        h = g.panel_h[n]
        _at(c, x, y + g.panel_y[n], g.width, h, rotate)
        if ("front", n) in faces:
            faces["front", n](c, g.width, h, rng)
        else:  # P4: directly behind the secret, through the same sheet of paper
            face_decoy(c, strip.secret_layout(), g.width, h, rng, 0.0, 1, mirror=True)
        if is_test_network():
            draw_test_mark(c, g.width, h, qrs.get(("front", n)))
        c.restoreState()


def draw_back(c, strip, x, y, rng):
    """Back side: the secret on P4 and, on P3 that lies right over it, aligned
    secret noise; P1 and P2 carry guides on tint (or more noise)."""
    g = getattr(strip, "geometry", CARD)
    faces = strip.faces()
    qrs = getattr(strip, "qr_rects", CARD_QR_RECTS)
    for n in (1, 2, 3, 4):
        h = g.panel_h[n]
        _at(c, x, y + g.panel_y[n], g.width, h)
        if n == 3:
            face_decoy(c, strip.secret_layout(), g.width, h, rng, *g.decoy_offset(3))
        else:
            faces["back", n](c, g.width, h, rng)
        if is_test_network():
            draw_test_mark(c, g.width, h, qrs.get(("back", n)))
        c.restoreState()


def render_pdf(strips, title):
    """Build the PDF in memory, one or two strips per duplex A4 sheet (front
    page, then back page) as their geometry says; returns the PDF bytes. Each
    strip provides faces() and secret_layout(), and optionally geometry and
    qr_rects (the QR codes kept clear of the test-network watermark)."""
    register_fonts()
    rng = random.SystemRandom()  # security patterns differ on every print
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4, invariant=1, pageCompression=1, initialFontName=SANS)
    if is_test_network():
        title += " · " + network_mark()
    c.setTitle(title)
    c.setAuthor("")
    c.setSubject("")
    c.setCreator(os.path.basename(sys.argv[0]) or "paperlib.py")
    g = getattr(strips[0], "geometry", CARD)
    sheets = [strips[i:i + g.per_sheet] for i in range(0, len(strips), g.per_sheet)]
    for s, sheet in enumerate(sheets):
        tag = ""
        if len(sheets) > 1:
            tag = "  ·  " + _("sheet {n}/{total}").format(n=s + 1, total=len(sheets))
        if is_test_network():
            tag += "  ·  " + network_mark()
        for back, side in ((False, _("FRONT — outside")), (True, _("BACK — inside (private keys)"))):
            c.scale(mm, mm)
            draw_page_furniture(c, side + tag, back, g)
            for slot, strip in enumerate(sheet):
                x, y = strip_origin(slot, back, g)
                (draw_back if back else draw_front)(c, strip, x, y, rng)
                draw_strip_marks(c, x, y, back, g)
            c.showPage()
    c.save()
    return buf.getvalue()


def network_mark():
    return btc.NETWORK_NAME.upper() + " · " + _("NO VALUE")


MAX_NUMBERED = 999


def numbered_paths(path):
    """path, then name_01.ext, name_02.ext, ... (the suffix goes before the extension)."""
    yield path
    root, ext = os.path.splitext(path)
    for i in range(1, MAX_NUMBERED + 1):
        yield f"{root}_{i:02d}{ext}"


def free_path(path):
    """The first of numbered_paths(path) that does not exist yet."""
    for candidate in numbered_paths(path):
        if not os.path.lexists(candidate):
            return candidate
    raise ValueError(_("no free file name left for {path}").format(path=path))


def output_paths(path):
    """(PDF path, Markdown path) for an output name: wallet, wallet.pdf and
    wallet.md all give wallet.pdf + wallet.md."""
    root, ext = os.path.splitext(path)
    if ext.lower() not in (".pdf", ".md"):
        root = path
    return root + ".pdf", root + ".md"


def free_output(path, pdf=True, md=True):
    """The first of path, name_01, name_02, ... whose files to be written
    (PDF and/or Markdown) do not exist yet."""
    for candidate in numbered_paths(output_paths(path)[0]):
        pdf_path, md_path = output_paths(candidate)
        if not (pdf and os.path.lexists(pdf_path)) and not (md and os.path.lexists(md_path)):
            return candidate
    raise ValueError(_("no free file name left for {path}").format(path=path))


def write_outputs(path, pdf=None, text=None, overwrite=False):
    """Write the PDF and/or its Markdown twin, mode 0600, never through a
    temporary file. Without overwrite, a name taken in the meantime moves
    them to the next free numbered name. Returns the paths written."""
    while True:
        pdf_path, md_path = output_paths(path)
        todo = [(p, d) for p, d in ((pdf_path, pdf), (md_path, text and text.encode("utf-8"))) if d is not None]
        written = []
        try:
            for target, data in todo:
                write_private_file(target, data, overwrite)
                written.append(target)
        except FileExistsError:
            for target in written:
                os.unlink(target)  # keep the pair together under one name
            path = free_output(path, pdf is not None, text is not None)
            continue
        return written


def choose_output(args, pdf=True, md=True):
    """Output name decided (and said) before any prompt or long search."""
    if args.force:
        return args.output
    output = free_output(args.output, pdf, md)
    if output_paths(output) != output_paths(args.output):  # "wallet" -> "wallet.pdf" is no change
        old = output_paths(args.output)[0 if pdf else 1]
        new = output_paths(output)[0 if pdf else 1]
        print(_("{path} already exists, writing {new} instead").format(path=old, new=new), file=sys.stderr)
    return output


def write_private_file(path, data, overwrite=False):
    """Write the PDF directly to its destination (no temp file), mode 0600."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    os.fchmod(fd, 0o600)  # a file overwritten with --force keeps its old mode otherwise
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


# =============================================================================
# Command line
# =============================================================================

def ask_twice(prompt):
    """Prompt twice for a password or passphrase (never echoed)."""
    pw = getpass.getpass(prompt)
    if not pw:
        raise ValueError(_("empty password"))
    if getpass.getpass(_("Confirm password: ")) != pw:
        raise ValueError(_("passwords do not match"))
    if len(pw) < 12:
        print(_("warning: password shorter than 12 characters"), file=sys.stderr)
    return pw


def warn_weak_entropy(estimate, target=TARGET_ENTROPY_BITS):
    """Said before any password prompt or search, to allow Ctrl-C."""
    if estimate is not None and estimate.bits < target:
        print(_("warning: the entropy you supplied is at most ~{bits} bits ({kind}), less than {target}; "
                "the keys are weaker than random ones. Example: 100 dice rolls give ~258 bits.")
              .format(bits=int(estimate.bits), kind=entropy_kind_label(estimate.kind), target=target),
              file=sys.stderr)


def warn_user_entropy(estimate):
    if estimate is not None:
        print(_("warning: key derived from user entropy; it is only as strong as that input "
                "(at most ~{bits} bits, {kind})")
              .format(bits=int(estimate.bits), kind=entropy_kind_label(estimate.kind)), file=sys.stderr)


def add_common_args(ap, output, entropy=True):
    """Options shared by the tools, with the same names and meaning. Returns
    the mutually exclusive group of the entropy sources (or None)."""
    src = None
    if entropy:
        src = ap.add_mutually_exclusive_group()
        add_entropy_args(src)
        src.add_argument("--from-md", metavar="FILE.md",
                         help=_("only rebuild the PDF from a Markdown file written earlier by this tool "
                                "(its data are checked first)"))
    ap.add_argument("--no-pdf", action="store_true", help=_("write only the Markdown file, no PDF"))
    ap.add_argument("--copies", type=int, default=None, metavar="N",
                    help=_("copies of each wallet, one strip each (default 2, or as in --from-md)"))
    ap.add_argument("-n", "--network", choices=tuple(NETWORK_NAMES), default=None,
                    help=_("main (default) or a test network, whose coins have no value: "
                           "for trying out funding and sweeping"))
    ap.add_argument("-o", "--output", default=None,
                    help=_("output name: writes NAME.pdf and NAME.md (default {default}; "
                           "with --from-md, the name of that file)").format(default=output))
    ap.set_defaults(default_output=output)
    ap.add_argument("--force", action="store_true",
                    help=_("overwrite the output files if they exist (default: write name_01, name_02, ...)"))
    ap.add_argument("--lang", choices=LANGUAGES,
                    help=_("language of the wallet and messages (default: from the system locale)"))
    return src


def add_entropy_args(group):
    group.add_argument("--entropy-file", metavar="PATH",
                       help=_("read entropy from a file ('-' for stdin); empty means /dev/random"))
    group.add_argument("--entropy-string", metavar="TEXT",
                       help=_("entropy as a string (visible in shell history and ps: prefer --entropy-prompt)"))
    group.add_argument("--entropy-prompt", action="store_true",
                       help=_("type the entropy string at a hidden prompt"))


def check_common_args(ap, args):
    if args.copies is not None and not 1 <= args.copies <= MAX_COPIES:
        ap.error(_("--copies must be between 1 and {max}").format(max=MAX_COPIES))
    from_md = getattr(args, "from_md", None)
    if from_md and args.no_pdf:
        ap.error(_("--from-md writes only the PDF: it cannot be used with --no-pdf"))
    if args.output is None:
        args.output = os.path.splitext(from_md)[0] if from_md else args.default_output


def read_md(path, tool):
    """The fields of a Markdown file written by the given tool."""
    with open(path, encoding="utf-8") as f:
        fields = md_fields(f.read())
    head = dict(fields)
    if head.get("tool") != tool:
        raise ValueError(_("{path} was not written by {tool}").format(path=path, tool=tool))
    if head.get("network") not in NETWORK_NAMES:
        raise ValueError(_("unknown network in {path}: {network}").format(path=path, network=head.get("network")))
    return fields


def network_of(args, file_network, path):
    """The network of a file read back, unless --network says otherwise."""
    if args.network and args.network != file_network:
        raise ValueError(_("--network {network} differs from the network of {path} ({file})")
                         .format(network=args.network, path=path, file=file_network))
    return file_network


def announce_network(name):
    set_network(name or "main")
    if is_test_network():
        print(_("network {network}: test keys and addresses, the coins have no value")
              .format(network=btc.NETWORK_NAME), file=sys.stderr)


def md_document(title, fields, sections=()):
    """Markdown twin of a PDF: a title, a warning, a machine-readable block of
    'key: value' lines (English keys, read back by the tools) and free
    sections of (heading, lines)."""
    if is_test_network():
        title += " · " + network_mark()
    out = [f"# {title}", "",
           "> " + _("SECRET: this file holds the same secrets as the PDF. Keep it offline and "
                    "encrypted, or delete it once the paper copies are checked."), "",
           "```text"]
    out += [f"{key}: {value}" for key, value in fields]
    out += ["```", ""]
    for heading, lines in sections:
        out += [f"## {heading}", ""] + list(lines) + [""]
    return "\n".join(out)


def md_fields(text):
    """The 'key: value' lines of the first ```text block of md_document()
    output, as a list of pairs (keys may repeat)."""
    fields, inside = [], False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            if inside:
                break
            inside = line.strip() == "```text"
            continue
        if inside and ":" in line:
            key, value = line.split(":", 1)
            fields.append((key.strip(), value.strip()))
    return fields


MAX_COPIES = 8


def select_language(argv):
    """Set the language before argparse builds its (translated) help text."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=LANGUAGES)
    known = pre.parse_known_args(argv)[0]
    set_language(known.lang or detect_language())
