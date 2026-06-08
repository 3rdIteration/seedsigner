#!/usr/bin/env python3
"""Generate the KeyCard Signer splash / screensaver artwork.

Draws a stylized smartcard ("keycard") — rounded card body with a subtle
vertical gradient, a gold EMV chip, and contactless arcs — on a solid black
background, 240x240. The art is painted in the **upper band** of the canvas so
the opening splash can render the product name / version / tagline underneath
it (see ``views/screensaver.py``).

Deterministic (no randomness, no network) so the asset is reproducible across
builds. Run:

    python scripts/gen_keycard_image.py

Output: ``src/seedsigner/resources/img/keycard_240.png`` (RGB, black bg, 240x240).
"""

import os

from PIL import Image, ImageDraw

CANVAS = 240
OUT = os.path.join(
    os.path.dirname(__file__),
    "..", "src", "seedsigner", "resources", "img", "keycard_240.png",
)

# Card body, painted in the upper band (y: 40..150) leaving the lower ~90px
# of the canvas free for the three splash text lines.
CARD_X0, CARD_Y0 = 44, 44
CARD_X1, CARD_Y1 = 196, 150
CARD_RADIUS = 14

# Colors
BG = (0, 0, 0)
CARD_TOP = (66, 69, 82)        # slate w/ a slight blue (nods to ETH)
CARD_BOTTOM = (32, 33, 41)
CARD_BORDER = (104, 107, 122)
CARD_HIGHLIGHT = (140, 143, 158)
CHIP_GOLD = (214, 178, 64)
CHIP_GOLD_DK = (150, 120, 32)
ARC_COLOR = (206, 208, 216)


def _vertical_gradient(size, top_rgb, bottom_rgb):
    w, h = size
    grad = Image.new("RGB", size)
    px = grad.load()
    for y in range(h):
        t = y / max(1, h - 1)
        r = round(top_rgb[0] + (bottom_rgb[0] - top_rgb[0]) * t)
        g = round(top_rgb[1] + (bottom_rgb[1] - top_rgb[1]) * t)
        b = round(top_rgb[2] + (bottom_rgb[2] - top_rgb[2]) * t)
        for x in range(w):
            px[x, y] = (r, g, b)
    return grad


def build():
    img = Image.new("RGB", (CANVAS, CANVAS), BG)

    # --- Card body: gradient clipped to a rounded-rect mask ---
    mask = Image.new("L", (CANVAS, CANVAS), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (CARD_X0, CARD_Y0, CARD_X1, CARD_Y1), radius=CARD_RADIUS, fill=255
    )
    gradient = _vertical_gradient((CANVAS, CANVAS), CARD_TOP, CARD_BOTTOM)
    img.paste(gradient, (0, 0), mask)

    draw = ImageDraw.Draw(img)

    # Outer border + a soft inner highlight on the top edge for depth.
    draw.rounded_rectangle(
        (CARD_X0, CARD_Y0, CARD_X1, CARD_Y1),
        radius=CARD_RADIUS, outline=CARD_BORDER, width=2,
    )
    draw.rounded_rectangle(
        (CARD_X0 + 3, CARD_Y0 + 3, CARD_X1 - 3, CARD_Y1 - 3),
        radius=CARD_RADIUS - 3, outline=CARD_HIGHLIGHT, width=1,
    )

    # --- EMV chip (upper-left of the card) ---
    cx0, cy0, cx1, cy1 = CARD_X0 + 18, CARD_Y0 + 22, CARD_X0 + 52, CARD_Y0 + 50
    draw.rounded_rectangle((cx0, cy0, cx1, cy1), radius=4, fill=CHIP_GOLD)
    # contact grid: H-pattern (horizontal split + central pad + two verticals)
    midy = (cy0 + cy1) // 2
    midx = (cx0 + cx1) // 2
    draw.line((cx0 + 2, midy, cx1 - 2, midy), fill=CHIP_GOLD_DK, width=2)
    draw.line((midx, cy0 + 2, midx, cy1 - 2), fill=CHIP_GOLD_DK, width=2)
    draw.rectangle((midx - 5, midy - 4, midx + 5, midy + 4), outline=CHIP_GOLD_DK, width=2)

    # --- Contactless arcs (to the right of the chip) ---
    ax, ay = cx1 + 16, midy  # arc focal point
    for i, r in enumerate((9, 16, 23)):
        draw.arc((ax - r, ay - r, ax + r, ay + r), start=-50, end=50,
                 fill=ARC_COLOR, width=2)

    # --- Accent base stripe: ETH-purple to BTC-orange (both chains) ---
    sy0 = CARD_Y1 - 20
    sx0, sx1 = CARD_X0 + 14, CARD_X1 - 14
    span = sx1 - sx0
    eth = (140, 109, 253)
    btc = (255, 148, 22)
    stripe = Image.new("RGB", (span, 4))
    spx = stripe.load()
    for x in range(span):
        t = x / max(1, span - 1)
        spx_col = (
            round(eth[0] + (btc[0] - eth[0]) * t),
            round(eth[1] + (btc[1] - eth[1]) * t),
            round(eth[2] + (btc[2] - eth[2]) * t),
        )
        for y in range(4):
            spx[x, y] = spx_col
    img.paste(stripe, (sx0, sy0))

    img.save(OUT)
    print("wrote", os.path.normpath(OUT))
    chk = Image.open(OUT)
    print("mode", chk.mode, "size", chk.size, "corner", chk.convert("RGBA").getpixel((0, 0)))
    print("card band y:", CARD_Y0, "..", CARD_Y1)


if __name__ == "__main__":
    build()
