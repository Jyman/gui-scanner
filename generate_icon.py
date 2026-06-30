"""Generate app icon: a shield with a magnifying glass overlay."""
from PIL import Image, ImageDraw

SIZES = [16, 32, 48, 64, 128, 256]
BG = (122, 162, 247, 255)
SHIELD = (36, 40, 59, 255)
ACCENT = (158, 206, 106, 255)
LENS = (224, 175, 104, 255)


def shield_points(w, h):
    cx, top = w / 2, h * 0.10
    bw, bh = w * 0.72, h * 0.78
    left, right = cx - bw / 2, cx + bw / 2
    return [
        (cx, top),
        (right, top + bh * 0.10),
        (right, top + bh * 0.50),
        (cx, top + bh),
        (left, top + bh * 0.50),
        (left, top + bh * 0.10),
    ]


def render(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    pad = size * 0.06
    d.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=size * 0.18,
        fill=BG,
    )

    pts = shield_points(size, size)
    d.polygon(pts, fill=SHIELD)

    cx, cy = size / 2, size * 0.50
    r = size * 0.18
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=LENS, width=max(2, size // 32))
    handle = size * 0.10
    d.line(
        [(cx + r * 0.7, cy + r * 0.7), (cx + r * 0.7 + handle, cy + r * 0.7 + handle)],
        fill=LENS,
        width=max(2, size // 24),
    )

    check_w = size * 0.10
    check_h = size * 0.06
    bx, by = cx - check_w / 2, size * 0.78
    d.line(
        [(bx, by), (bx + check_w * 0.4, by + check_h), (bx + check_w, by - check_h * 0.6)],
        fill=ACCENT,
        width=max(2, size // 28),
    )

    return img


def main():
    frames = [render(s) for s in SIZES]
    frames[0].save(
        "assets/yinhu.ico",
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=frames[1:],
    )
    print("Wrote assets/yinhu.ico")


if __name__ == "__main__":
    import os
    os.makedirs("assets", exist_ok=True)
    main()
