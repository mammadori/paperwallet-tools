#!/usr/bin/env python3
"""
Prepare the background artwork for printing: optionally boost colour and
darken the mid-tones (laser printers wash out pale pastels), then downscale.

    python tools/prepare_artwork.py [SOURCE] [-o assets/solarpunk-vault.jpg]

SOURCE defaults to the full-resolution original in assets/source/. Always
start again from it rather than re-processing the downscaled asset.
"""

import argparse

from PIL import Image, ImageEnhance


def prepare(src, color, gamma, scale):
    im = Image.open(src).convert("RGB")
    im = ImageEnhance.Color(im).enhance(color)
    # gamma > 1 darkens the mid-tones and leaves pure white untouched
    lut = [round(255 * (i / 255) ** gamma) for i in range(256)]
    im = im.point(lut * 3)
    size = (round(im.width * scale), round(im.height * scale))
    return im.resize(size, Image.LANCZOS)


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("source", nargs="?", default="assets/source/solarpunk-vault.webp")
    ap.add_argument("-o", "--output", default="assets/solarpunk-vault.jpg")
    ap.add_argument("--color", type=float, default=1.0, help="saturation factor (1 = unchanged)")
    ap.add_argument("--gamma", type=float, default=1.0, help="mid-tone darkening (1 = unchanged)")
    ap.add_argument("--scale", type=float, default=0.5, help="resolution factor (1 = unchanged)")
    ap.add_argument("--quality", type=int, default=85, help="JPEG quality")
    args = ap.parse_args()
    im = prepare(args.source, args.color, args.gamma, args.scale)
    im.save(args.output, "JPEG", quality=args.quality, optimize=True)
    print(f"{args.output}: {im.width}x{im.height}")


if __name__ == "__main__":
    main()
