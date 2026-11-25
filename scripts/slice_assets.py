"""Slice the Spar brand sheets into individual assets.

Inputs (copied into assets/source/ for reproducibility):
  sheet-brand.jpeg   logo mark + wordmark, 4 illustration cards, 8 monoline icons
  sheet-logo-specs.jpeg   app-icon housing at 512/256, favicon 16, bare mark

Outputs: assets/logo/*, assets/icons/*, assets/illustrations/* (PNG, RGBA
where the dark page background is keyed out to transparency).

Detection is adaptive: row/column profiles of luminance masks cluster the
sheet into bands and elements; no hardcoded pixel boxes.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "source"
OUT_LOGO = ROOT / "assets" / "logo"
OUT_ICONS = ROOT / "assets" / "icons"
OUT_ILLUS = ROOT / "assets" / "illustrations"

ICON_NAMES = [
    "target-scope", "attack-agent", "verification-proof", "coordinator",
    "trial-calibration", "isolation-sandbox", "continuous-trigger", "guard-budget",
]
ILLUS_NAMES = ["white-box-aiming", "attack-execution", "critic-verification", "patch-reattack"]


def clusters(mask_1d: np.ndarray, min_gap: int, min_size: int) -> list[tuple[int, int]]:
    runs = []
    start = None
    gap = 0
    for i, v in enumerate(mask_1d):
        if v:
            if start is None:
                start = i
            gap = 0
        elif start is not None:
            gap += 1
            if gap >= min_gap:
                end = i - gap
                if end - start + 1 >= min_size:
                    runs.append((start, end))
                start = None
                gap = 0
    if start is not None:
        end = len(mask_1d) - 1
        if end - start + 1 >= min_size:
            runs.append((start, end))
    return runs


def key_alpha(rgb: np.ndarray, lo: float = 26.0, hi: float = 72.0) -> np.ndarray:
    """Smooth alpha from luminance: page-black becomes transparent,
    antialiased stroke edges get partial alpha."""
    lum = rgb.max(axis=2).astype(float)
    a = np.clip((lum - lo) / (hi - lo), 0.0, 1.0)
    return (a * 255).astype(np.uint8)


def save_keyed(img: Image.Image, path: Path, pad: int = 4, drop_text_rows: bool = False) -> None:
    rgb = np.array(img.convert("RGB"))
    alpha = key_alpha(rgb)
    ys, xs = np.where(alpha > 8)
    if len(ys) == 0:
        raise SystemExit(f"empty crop for {path}")
    y0, y1 = max(ys.min() - pad, 0), min(ys.max() + pad, rgb.shape[0] - 1)
    x0, x1 = max(xs.min() - pad, 0), min(xs.max() + pad, rgb.shape[1] - 1)
    rgb = rgb[y0:y1 + 1, x0:x1 + 1]
    alpha = alpha[y0:y1 + 1, x0:x1 + 1]
    if drop_text_rows:
        # some sheet glyphs carry a baked-in caption under the icon; trim a
        # short trailing text band so the icon set stays uniform
        rows = (alpha > 60).sum(axis=1) >= 2
        runs = clusters(rows, min_gap=3, min_size=2)
        if len(runs) >= 2:
            last_h = runs[-1][1] - runs[-1][0] + 1
            body_h = runs[-2][1] - runs[-2][0] + 1
            if last_h <= 60 and body_h >= 80 and last_h < 0.4 * body_h:
                alpha[runs[-1][0]:, :] = 0
                rgb[runs[-1][0]:, :, :] = 0
                ys2, xs2 = np.where(alpha > 8)
                y1b = ys2.max() + pad
                rgb = rgb[: y1b + 1]
                alpha = alpha[: y1b + 1]
    out = np.dstack([rgb, alpha]).astype(np.uint8)
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(out, "RGBA").save(path)
    print(f"  {path.relative_to(ROOT)}  {out.shape[1]}x{out.shape[0]}")


def save_flat(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.convert("RGB").save(path)
    print(f"  {path.relative_to(ROOT)}  {img.size[0]}x{img.size[1]}")


def slice_brand_sheet(path: Path) -> None:
    img = Image.open(path).convert("RGB")
    rgb = np.array(img)
    lum = rgb.max(axis=2).astype(int)
    H, W = lum.shape
    bright = lum > 70
    panel = (lum > 30) & (lum <= 62)
    content = lum > 30

    row_runs = clusters(content.sum(axis=1) > W * 0.02, min_gap=18, min_size=30)
    print(f"bands: {row_runs}")
    icon_band = label_band = None
    card_bands = []
    header_band = None
    for (y0, y1) in row_runs:
        band_bright = bright[y0:y1 + 1]
        band_panel = panel[y0:y1 + 1]
        height = y1 - y0 + 1
        col_runs = clusters(band_bright.sum(axis=0) > 2, min_gap=24, min_size=20)
        panel_frac = band_panel.mean()
        if y0 < H * 0.30 and len(col_runs) == 2 and panel_frac < 0.05:
            header_band = (y0, y1, col_runs)
        elif panel_frac > 0.15 and len(col_runs) == 2:
            card_bands.append((y0, y1, col_runs))
        elif len(col_runs) == 8 and height >= 70:
            icon_band = (y0, y1, col_runs)
        elif len(col_runs) == 8:
            label_band = (y0, y1, col_runs)
    if header_band is None or icon_band is None or len(card_bands) != 2:
        raise SystemExit(f"band classification failed: header={header_band is not None} cards={len(card_bands)} icons={icon_band is not None}")

    # header: mark + wordmark
    y0, y1, cols = header_band
    (mx0, mx1), (wx0, wx1) = cols
    save_keyed(img.crop((mx0, y0, mx1 + 1, y1 + 1)), OUT_LOGO / "spar-mark.png")
    save_keyed(img.crop((wx0, y0, wx1 + 1, y1 + 1)), OUT_LOGO / "spar-wordmark.png")

    # illustration cards (keep opaque panel + caption)
    cards = []
    for (y0, y1, cols) in card_bands:
        for (x0, x1) in cols:
            cards.append((x0, y0, x1 + 1, y1 + 1))
    cards.sort(key=lambda c: (c[1], c[0]))
    for name, box in zip(ILLUS_NAMES, cards):
        save_flat(img.crop(box), OUT_ILLUS / f"{name}.png")

    # monoline icons, keyed transparent
    y0, y1, cols = icon_band
    if len(cols) != 8:
        raise SystemExit(f"expected 8 icon clusters, got {len(cols)}")
    for name, (x0, x1) in zip(ICON_NAMES, cols):
        save_keyed(img.crop((x0, y0, x1 + 1, y1 + 1)), OUT_ICONS / f"{name}.png", drop_text_rows=True)


def slice_spec_sheet(path: Path) -> None:
    img = Image.open(path).convert("RGB")
    rgb = np.array(img)
    lum = rgb.max(axis=2).astype(int)
    H, W = lum.shape
    vivid = lum > 95  # orange art + metallic rims; excludes gray labels/grid

    def tight(fx0, fy0, fx1, fy1, pad=6):
        x0, y0, x1, y1 = int(fx0 * W), int(fy0 * H), int(fx1 * W), int(fy1 * H)
        sub = vivid[y0:y1, x0:x1]
        ys, xs = np.where(sub)
        if len(ys) == 0:
            raise SystemExit(f"no vivid pixels in window {fx0},{fy0},{fx1},{fy1}")
        by0, by1 = y0 + ys.min() - pad, y0 + ys.max() + pad
        bx0, bx1 = x0 + xs.min() - pad, x0 + xs.max() + pad
        return (max(bx0, 0), max(by0, 0), min(bx1, W - 1), min(by1, H - 1))

    # windows chosen to exclude the sheet's dimension labels and arrows
    box512 = tight(0.05, 0.215, 0.43, 0.80)
    boxmark = tight(0.865, 0.465, 0.955, 0.60)

    app512 = img.crop(box512).resize((512, 512), Image.LANCZOS)
    save_flat(app512, OUT_LOGO / "app-icon-512.png")
    save_flat(app512.resize((256, 256), Image.LANCZOS), OUT_LOGO / "app-icon-256.png")
    # favicons are honest downscales of the 512 housing (a 16px redraw from
    # the sheet's labeled 16px sample would carry its caption pixels)
    save_flat(app512.resize((32, 32), Image.LANCZOS), OUT_LOGO / "favicon-32.png")
    save_flat(app512.resize((16, 16), Image.LANCZOS), OUT_LOGO / "favicon-16.png")
    save_keyed(img.crop(boxmark), OUT_LOGO / "spar-mark-glossy.png")


def build_lockup() -> None:
    # lockup: flat mark + wordmark on one transparent canvas
    mark = Image.open(OUT_LOGO / "spar-mark.png").convert("RGBA")
    word = Image.open(OUT_LOGO / "spar-wordmark.png").convert("RGBA")
    mh = 240
    mark = mark.resize((int(mark.width * mh / mark.height), mh), Image.LANCZOS)
    wh = int(mh * 0.86)
    word = word.resize((int(word.width * wh / word.height), wh), Image.LANCZOS)
    gap = 48
    canvas = Image.new("RGBA", (mark.width + gap + word.width, mh), (0, 0, 0, 0))
    canvas.alpha_composite(mark, (0, 0))
    canvas.alpha_composite(word, (mark.width + gap, (mh - wh) // 2 - 10))
    save_flat_rgba(canvas, OUT_LOGO / "spar-lockup.png")


def save_flat_rgba(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path)
    print(f"  {path.relative_to(ROOT)}  {img.size[0]}x{img.size[1]}")


def slice_glossy_icons(path: Path) -> None:
    """Slice the glossy 3D icon sheet (8 icons + caption band) on dark bg.

    Luminance keying would turn the icons' own dark metal facets translucent,
    so the connected backdrop is flood-filled from the crop corners instead;
    interior dark pixels stay opaque. Captions are dropped by row band.
    """
    from PIL import ImageDraw

    img = Image.open(path).convert("RGB")
    rgb = np.array(img)
    bg = np.median(np.concatenate([rgb[0], rgb[-1], rgb[:, 0], rgb[:, -1]]), axis=0)
    dist = np.sqrt(((rgb.astype(float) - bg) ** 2).sum(axis=2))
    content = dist > 30
    bands = clusters(content.sum(axis=1) > img.width * 0.02, min_gap=6, min_size=10)
    if len(bands) < 2:
        raise SystemExit(f"expected icon + caption bands, got {len(bands)}")
    y0, y1 = bands[0]
    cols = clusters(content[y0:y1 + 1].sum(axis=0) > 2, min_gap=24, min_size=20)
    if len(cols) != 8:
        raise SystemExit(f"expected 8 icon clusters, got {len(cols)}")
    for name, (x0, x1) in zip(ICON_NAMES, cols):
        crop = img.crop((x0, y0, x1 + 1, y1 + 1))
        w, h = crop.size
        for seed in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
            ImageDraw.floodfill(crop, seed, (255, 0, 255), thresh=20)
        arr = np.array(crop)
        alpha = np.where((arr == (255, 0, 255)).all(axis=2), 0, 255).astype(np.uint8)
        ys, xs = np.where(alpha > 0)
        pad = 2
        box = (max(xs.min() - pad, 0), max(ys.min() - pad, 0),
               min(xs.max() + pad + 1, w), min(ys.max() + pad + 1, h))
        out = np.dstack([arr[box[1]:box[3], box[0]:box[2]], alpha[box[1]:box[3], box[0]:box[2]]])
        icon = Image.fromarray(out.astype(np.uint8), "RGBA")
        th = 96
        icon = icon.resize((int(icon.width * th / icon.height), th), Image.LANCZOS)
        save_flat_rgba(icon, OUT_ICONS / f"{name}.png")


def build_nav_icon(path: Path) -> None:
    """Animated top-left nav mark from the transparent app-icon GIF.

    Crops the union content bbox, downscales to 64px (2x of the 32px nav),
    and re-encodes with one global palette plus a reserved transparent index
    so the loop stays small and keeps its alpha. Also emits a static first
    frame for prefers-reduced-motion.
    """
    src = Image.open(path)
    frames = []
    boxes = []
    for i in range(src.n_frames):
        src.seek(i)
        f = src.convert("RGBA")
        frames.append(f)
        a = np.array(f)[:, :, 3]
        ys, xs = np.where(a > 8)
        boxes.append((xs.min(), ys.min(), xs.max(), ys.max()))
    u = (min(b[0] for b in boxes), min(b[1] for b in boxes),
         max(b[2] for b in boxes), max(b[3] for b in boxes))
    size = 64
    small = []
    for f in frames:
        c = f.crop(u)
        c.thumbnail((size, size), Image.LANCZOS)
        canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        canvas.alpha_composite(c, ((size - c.width) // 2, (size - c.height) // 2))
        small.append(canvas)
    stack = np.concatenate([np.array(s)[:, :, :3][np.array(s)[:, :, 3] > 128] for s in small])
    pal = Image.fromarray(stack.reshape(-1, 1, 3)).convert("P", palette=Image.ADAPTIVE, colors=255)
    palette = pal.getpalette()
    palette[255 * 3:255 * 3 + 3] = [0, 0, 0]
    pal.putpalette(palette)
    quant = []
    for s in small:
        arr = np.array(s)
        q = np.array(s.convert("RGB").quantize(palette=pal, dither=Image.Dither.NONE))
        q[arr[:, :, 3] < 128] = 255
        qi = Image.fromarray(q, "P")
        qi.putpalette(palette)
        quant.append(qi)
    out = OUT_LOGO / "spar-nav.gif"
    quant[0].save(
        out, save_all=True, append_images=quant[1:],
        duration=src.info.get("duration", 100), loop=0,
        transparency=255, disposal=2,
    )
    print(f"  {out.relative_to(ROOT)}  {out.stat().st_size} bytes")
    save_flat_rgba(small[0], OUT_LOGO / "spar-nav.png")


def publish_docs_nav() -> None:
    docs = ROOT / "docs" / "assets"
    for name in ("spar-nav.gif", "spar-nav.png"):
        shutil.copyfile(OUT_LOGO / name, docs / name)
        print(f"  docs/assets/{name}")


def publish_docs_icons() -> None:
    docs = ROOT / "docs" / "assets" / "icons"
    docs.mkdir(parents=True, exist_ok=True)
    for name in ICON_NAMES:
        shutil.copyfile(OUT_ICONS / f"{name}.png", docs / f"{name}.png")
    print(f"  docs/assets/icons/  ({len(ICON_NAMES)} icons)")


def slice_transparent_lockup(path: Path) -> None:
    """Split the 2026-11 transparent RGBA lockup (blade emblem + wordmark).

    Unlike the JPEG sheets, this source already carries alpha, so clusters
    come from the alpha channel and crops keep it verbatim.
    """
    img = Image.open(path).convert("RGBA")
    alpha = np.array(img)[:, :, 3]
    runs = clusters((alpha > 8).sum(axis=0) > 0, min_gap=24, min_size=20)
    if len(runs) != 2:
        raise SystemExit(f"expected emblem + wordmark clusters, got {len(runs)}")
    (ex0, ex1), (wx0, wx1) = runs

    def tight(crop: Image.Image) -> Image.Image:
        # getbbox() keeps faint alpha noise rows; trim at the same threshold
        # the column clusters use so crops carry no transparent padding
        a = np.array(crop)[:, :, 3]
        ys, xs = np.where(a > 8)
        return crop.crop((int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1))

    emblem = tight(img.crop((ex0, 0, ex1 + 1, img.height)))
    word = tight(img.crop((wx0, 0, wx1 + 1, img.height)))
    eh = 240
    save_flat_rgba(
        emblem.resize((int(emblem.width * eh / emblem.height), eh), Image.LANCZOS),
        OUT_LOGO / "spar-blades.png",
    )
    ww = 640
    save_flat_rgba(
        word.resize((ww, int(word.height * ww / word.width)), Image.LANCZOS),
        OUT_LOGO / "spar-wordmark.png",
    )


def build_blades_loop(path: Path) -> None:
    """Square emblem loop from the rotating-blades render.

    The render's near-black backdrop is crushed to pure black so the page can
    screen-blend the loop over the sharks hero without a visible rectangle.
    """
    out = OUT_LOGO / "spar-blades.mp4"
    subprocess.run(
        [
            "ffmpeg", "-v", "error", "-y", "-i", str(path),
            "-vf",
            "crop=min(iw\\,ih):min(iw\\,ih):(iw-min(iw\\,ih))/2:0,"
            "scale=240:240:flags=lanczos,"
            "colorlevels=rimin=0.0627:gimin=0.0627:bimin=0.0627,"
            "format=yuv420p",
            "-c:v", "libx264", "-crf", "20", "-preset", "slow",
            "-movflags", "+faststart",
            str(out),
        ],
        check=True,
    )
    print(f"  {out.relative_to(ROOT)}  {out.stat().st_size} bytes")


def publish_docs_logo() -> None:
    docs = ROOT / "docs" / "assets"
    docs.mkdir(parents=True, exist_ok=True)
    for name in ("spar-wordmark.png", "spar-blades.png", "spar-blades.mp4"):
        shutil.copyfile(OUT_LOGO / name, docs / name)
        print(f"  docs/assets/{name}")


def main() -> int:
    for out in (OUT_LOGO, OUT_ICONS, OUT_ILLUS):
        out.mkdir(parents=True, exist_ok=True)
    slice_brand_sheet(SRC / "sheet-brand.jpeg")
    slice_glossy_icons(SRC / "sheet-icons-glossy.png")
    slice_spec_sheet(SRC / "sheet-logo-specs.jpeg")
    slice_transparent_lockup(SRC / "sheet-lockup-2026-11.png")
    build_lockup()
    build_blades_loop(SRC / "blades-rotating-clockwise.mp4")
    build_nav_icon(SRC / "nav-icon-1124.gif")
    publish_docs_logo()
    publish_docs_icons()
    publish_docs_nav()
    return 0


if __name__ == "__main__":
    sys.exit(main())
