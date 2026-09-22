"""Render a captured terminal session (from `script`) to a PNG.

Used by `make screenshot` to produce docs/tests-passing.png from a real `make test` run.
Usage: python3 scripts/screenshot.py <typescript> <out.png>
Needs Pillow and the DejaVu Sans Mono font.
"""
import re, sys
from PIL import Image, ImageDraw, ImageFont

src, out = sys.argv[1], sys.argv[2]
raw = open(src, "rb").read().decode("utf-8", "replace")
lines = raw.replace("\r\n", "\n").split("\n")
lines = [l for l in lines if not l.startswith("Script started") and not l.startswith("Script done")]
while lines and not lines[-1].strip():
    lines.pop()
# carriage returns inside a line overwrite what came before
lines = [re.sub(r"\x1b[()][0-9A-Za-z]", "", l.split("\r")[-1]) for l in lines]

PROMPT = [("\x1b[1;92m", "~/Turnine-week-4"), ("\x1b[0m", " $ make test")]

SCALE = 2
FONT_SIZE = 14 * SCALE
LINE_H = 19 * SCALE
PAD_X, PAD_Y, TITLE_H = 18 * SCALE, 14 * SCALE, 30 * SCALE
regular = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", FONT_SIZE)
bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", FONT_SIZE)
CHAR_W = regular.getlength("M")

BG, FG, CHROME = (30, 30, 30), (204, 204, 204), (50, 50, 52)
PALETTE = {30: (0, 0, 0), 31: (205, 49, 49), 32: (13, 188, 121), 33: (229, 229, 16), 34: (36, 114, 200),
           35: (188, 63, 188), 36: (17, 168, 205), 37: (229, 229, 229), 90: (102, 102, 102),
           91: (241, 76, 76), 92: (35, 209, 139), 93: (245, 245, 67), 94: (59, 142, 234),
           95: (214, 112, 214), 96: (41, 184, 219), 97: (229, 229, 229)}
SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

def spans(line):
    """Split a line into (text, color, bold) runs following SGR codes."""
    color, is_bold, pos, out = FG, False, 0, []
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((OTHER.sub("", line[pos:m.start()]), color, is_bold))
        for code in (m.group(1) or "0").split(";"):
            code = int(code or 0)
            if code == 0:
                color, is_bold = FG, False
            elif code == 1:
                is_bold = True
            elif code == 22:
                is_bold = False
            elif code == 39:
                color = FG
            elif code in PALETTE:
                color = PALETTE[code]
        pos = m.end()
    out.append((OTHER.sub("", line[pos:]), color, is_bold))
    return out

rows = [[(text, *style) for text, *style in spans("".join(c + t for c, t in PROMPT))]] + [spans(l) for l in lines]
cols = max(sum(len(t) for t, _, _ in row) for row in rows)
width = int(PAD_X * 2 + CHAR_W * cols)
height = TITLE_H + PAD_Y * 2 + LINE_H * len(rows)

img = Image.new("RGB", (width, height), (0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([0, 0, width - 1, height - 1], radius=10 * SCALE, fill=BG)
d.rounded_rectangle([0, 0, width - 1, TITLE_H + 10 * SCALE], radius=10 * SCALE, fill=CHROME)
d.rectangle([0, TITLE_H, width - 1, TITLE_H + 10 * SCALE], fill=BG)
for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
    cx, cy, r = 16 * SCALE + i * 20 * SCALE, TITLE_H // 2, 6 * SCALE
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=c)
title = "Token-22-CTs: make test"
d.text(((width - regular.getlength(title)) / 2, (TITLE_H - FONT_SIZE) / 2 - SCALE), title, font=regular, fill=(170, 170, 170))

y = TITLE_H + PAD_Y
for row in rows:
    x = PAD_X
    for text, color, is_bold in row:
        if text:
            d.text((x, y), text, font=bold if is_bold else regular, fill=color)
            x += CHAR_W * len(text)
    y += LINE_H
img.save(out, optimize=True)
print(out, img.size, len(rows), "rows")
