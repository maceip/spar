"""Record a real `spar demo --trials 20` execution and render an optimized terminal GIF.

Runs `/Users/mac/spar/.venv/bin/python -m spar demo --trials 20` inside an isolated
temporary working directory (leaving zero `.spar/` or `spar_tests/` leftovers in the repo),
renders high-contrast dark-theme frames with Pillow using Menlo, and optimizes the
assembled GIF with `gifsicle -O3`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Sequence

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_GIF = REPO_ROOT / "assets" / "spar-demo.gif"
MENLO_PATH = Path("/System/Library/Fonts/Menlo.ttc")

# Spar dark terminal palette
BG_COLOR = "#0D1117"
CHROME_BG = "#161B22"
BORDER_COLOR = "#30363D"
TEXT_COLOR = "#E6EDF3"
MUTED_COLOR = "#8B949E"
GREEN_COLOR = "#3FB950"
RED_COLOR = "#F85149"
YELLOW_COLOR = "#D29922"
BLUE_COLOR = "#58A6FF"
WHITE_COLOR = "#FFFFFF"

CANVAS_W = 1200
CANVAS_H = 740
TITLEBAR_H = 38
PAD_X = 24
PAD_Y = 16
FONT_SIZE = 13
LINE_H = 20
MAX_COLS = 144


@dataclass
class StyledSpan:
    text: str
    color: str = TEXT_COLOR
    bold: bool = False


def _load_fonts(size: int) -> tuple[ImageFont.FreeTypeFont | ImageFont.ImageFont, ImageFont.FreeTypeFont | ImageFont.ImageFont]:
    if MENLO_PATH.is_file():
        try:
            reg = ImageFont.truetype(str(MENLO_PATH), size=size, index=0)
            bold = ImageFont.truetype(str(MENLO_PATH), size=size, index=1)
            return reg, bold
        except OSError:
            pass
    for fallback in (
        "/System/Library/Fonts/SFNSMono.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ):
        p = Path(fallback)
        if p.is_file():
            try:
                f = ImageFont.truetype(str(p), size=size)
                return f, f
            except OSError:
                continue
    default = ImageFont.load_default()
    return default, default


def capture_real_demo(trials: int = 20) -> tuple[str, int]:
    """Execute `python -m spar demo --trials <trials>` in an isolated temp cwd."""
    with tempfile.TemporaryDirectory(prefix="spar_gif_rec_") as td:
        tmp_path = Path(td)
        cmd = [sys.executable, "-m", "spar", "demo", "--trials", str(trials), "--spar-dir", ".spar"]
        proc = subprocess.run(
            cmd,
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=600,
        )
        combined = proc.stdout or ""
        if proc.stderr:
            combined = f"{combined.rstrip()}\n{proc.stderr.lstrip()}" if combined else proc.stderr
        return combined, proc.returncode


def _truncate_line(line: str, max_cols: int = MAX_COLS) -> str:
    if len(line) <= max_cols:
        return line
    return line[: max_cols - 1] + "…"


def _style_line(raw: str) -> list[StyledSpan]:
    """Apply semantic terminal syntax highlighting to real `spar demo` output lines."""
    line = _truncate_line(raw.rstrip("\n"))
    if not line:
        return [StyledSpan("", TEXT_COLOR)]

    if line.startswith("$ "):
        return [
            StyledSpan("$ ", GREEN_COLOR, bold=True),
            StyledSpan(line[2:], WHITE_COLOR, bold=True),
        ]
    if line.startswith("spar demo:"):
        m = re.search(r"(http://[^\s]+)", line)
        if m:
            i0, i1 = m.span(1)
            return [
                StyledSpan(line[:i0], BLUE_COLOR, bold=True),
                StyledSpan(line[i0:i1], GREEN_COLOR, bold=True),
                StyledSpan(line[i1:], BLUE_COLOR),
            ]
        return [StyledSpan(line, BLUE_COLOR, bold=True)]
    if line.lstrip().startswith("(ephemeral in-memory"):
        return [StyledSpan(line, MUTED_COLOR)]
    if line.startswith("Spar:"):
        return [StyledSpan(line, WHITE_COLOR, bold=True)]
    if line.startswith("Recon:"):
        return [StyledSpan(line, BLUE_COLOR)]

    # Findings table rows: `  HIGH  <obj>  20/20 [0.84,1.00]  proof: ...`
    m_find = re.match(r"^(\s*)(CRITICAL|HIGH|MED|LOW)(\s+)(.+?)(\s+\d+/\d+\s+\[[^\]]+\])(\s+proof:\s*)(.*)$", line)
    if m_find:
        sev = m_find.group(2)
        sev_col = RED_COLOR if sev in ("CRITICAL", "HIGH") else (YELLOW_COLOR if sev == "MED" else BLUE_COLOR)
        return [
            StyledSpan(m_find.group(1), TEXT_COLOR),
            StyledSpan(sev, sev_col, bold=True),
            StyledSpan(m_find.group(3), TEXT_COLOR),
            StyledSpan(m_find.group(4), TEXT_COLOR),
            StyledSpan(m_find.group(5), GREEN_COLOR, bold=True),
            StyledSpan(m_find.group(6), BLUE_COLOR),
            StyledSpan(m_find.group(7), MUTED_COLOR),
        ]

    if line.startswith("  report ") or line.startswith("  tests ") or line.startswith("  cost "):
        parts = line.split("  ", 2)
        if len(parts) >= 3:
            return [
                StyledSpan("  " + parts[1] + "  ", BLUE_COLOR, bold=True),
                StyledSpan(parts[2], TEXT_COLOR),
            ]
    if line.startswith("  outcome "):
        return [
            StyledSpan("  outcome ", BLUE_COLOR, bold=True),
            StyledSpan(line[len("  outcome ") :], GREEN_COLOR if "integrity=pass" in line else RED_COLOR, bold=True),
        ]
    if line.startswith("  first-screen proof:"):
        prefix = "  first-screen proof:"
        return [
            StyledSpan(prefix, YELLOW_COLOR, bold=True),
            StyledSpan(line[len(prefix) :], WHITE_COLOR, bold=True),
        ]

    if line.startswith("Running the emitted regression suite"):
        return [StyledSpan(line, BLUE_COLOR, bold=True)]
    if re.match(r"^F+\s+\[100%\]$", line.strip()):
        idx = line.find("[100%]")
        return [
            StyledSpan(line[:idx], RED_COLOR, bold=True),
            StyledSpan(line[idx:], MUTED_COLOR),
        ]
    if line.startswith("===") or line.startswith("---"):
        return [StyledSpan(line, MUTED_COLOR)]
    if line.startswith("FAILED ") or line.startswith("E   AssertionError:"):
        return [StyledSpan(line, RED_COLOR)]
    if "failed in " in line and line.strip().endswith("s"):
        return [StyledSpan(line, RED_COLOR, bold=True)]
    if line.startswith("Suite failed as expected"):
        return [StyledSpan(line, GREEN_COLOR, bold=True)]
    return [StyledSpan(line, TEXT_COLOR)]


def _parse_captured_phases(raw_output: str) -> dict[str, list[str]]:
    """Split real captured stdout into logical animation sections."""
    lines = [ln.rstrip("\r") for ln in raw_output.splitlines()]

    banner: list[str] = []
    summary_header: list[str] = []
    findings: list[str] = []
    metadata: list[str] = []
    first_proof: list[str] = []
    pytest_lines: list[str] = []

    in_pytest = False
    for ln in lines:
        s = ln.strip()
        if not in_pytest:
            if s.startswith("spar demo:") or s.startswith("(ephemeral in-memory"):
                banner.append(ln)
            elif s.startswith("Spar:") or s.startswith("Recon:"):
                summary_header.append(ln)
            elif re.match(r"^(CRITICAL|HIGH|MED|LOW)\s+", s):
                findings.append(ln)
            elif re.match(r"^(report|tests|cost|outcome)\s+", s):
                metadata.append(ln)
            elif s.startswith("first-screen proof:"):
                first_proof.append(ln)
            elif s.startswith("Running the emitted regression suite"):
                in_pytest = True
                pytest_lines.append(ln)
        else:
            pytest_lines.append(ln)

    # Condense pytest tracebacks to clean progress bar + short test summary + exit confirmation
    compact_pytest: list[str] = []
    short_summary: list[str] = []
    in_short = False
    for ln in pytest_lines:
        s = ln.strip()
        if s.startswith("Running the emitted regression suite") or re.match(r"^F+\s+\[100%\]$", s):
            compact_pytest.append(ln)
        elif s.startswith("=========================== short test summary info"):
            in_short = True
            compact_pytest.append(ln)
        elif in_short:
            if s.startswith("FAILED "):
                short_summary.append(ln)
            elif "failed in " in s or s.startswith("Suite failed as expected"):
                in_short = False
                if len(short_summary) > 3:
                    compact_pytest.extend(short_summary[:2])
                    compact_pytest.append(f"... ({len(short_summary) - 2} more failing finding tests)")
                else:
                    compact_pytest.extend(short_summary)
                compact_pytest.append(ln)
        elif s.startswith("Suite failed as expected"):
            compact_pytest.append(ln)

    return {
        "banner": banner,
        "summary_header": summary_header,
        "findings": findings,
        "metadata": metadata,
        "first_proof": first_proof,
        "pytest": compact_pytest,
    }


def _render_frame(
    lines: Sequence[str],
    reg_font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    bold_font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    *,
    show_cursor: bool = False,
) -> Image.Image:
    img = Image.new("RGB", (CANVAS_W, CANVAS_H), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Outer terminal frame + macOS-style dark chrome header
    draw.rectangle([0, 0, CANVAS_W - 1, CANVAS_H - 1], outline=BORDER_COLOR, width=1)
    draw.rectangle([1, 1, CANVAS_W - 2, TITLEBAR_H], fill=CHROME_BG)
    draw.line([(1, TITLEBAR_H), (CANVAS_W - 2, TITLEBAR_H)], fill=BORDER_COLOR, width=1)

    for idx, dot_col in enumerate(("#FF5F56", "#FFBD2E", "#27C93F")):
        cx = 20 + idx * 20
        cy = TITLEBAR_H // 2
        draw.ellipse([cx - 5, cy - 5, cx + 5, cy + 5], fill=dot_col)

    title_txt = "spar demo --trials 20  (localhost-only synthetic target)"
    draw.text((CANVAS_W // 2 - 210, 10), title_txt, font=reg_font, fill=MUTED_COLOR)

    # Keep only the bottom viewport lines that fit inside the terminal canvas
    max_visible = (CANVAS_H - TITLEBAR_H - 2 * PAD_Y) // LINE_H
    visible = list(lines[-max_visible:])

    y = TITLEBAR_H + PAD_Y
    last_end_x = PAD_X
    for raw in visible:
        x = PAD_X
        for span in _style_line(raw):
            fnt = bold_font if span.bold else reg_font
            draw.text((x, y), span.text, font=fnt, fill=span.color)
            bbox = draw.textbbox((x, y), span.text, font=fnt)
            x = bbox[2]
        last_end_x = x
        y += LINE_H

    if show_cursor and visible:
        cy = y - LINE_H + 3
        draw.rectangle([last_end_x + 3, cy, last_end_x + 11, cy + FONT_SIZE + 2], fill=BLUE_COLOR)

    return img


def build_frames(raw_output: str) -> tuple[list[Image.Image], list[int]]:
    """Build animation frames + per-frame durations (ms) from real `spar demo` output."""
    reg_font, bold_font = _load_fonts(FONT_SIZE)
    phases = _parse_captured_phases(raw_output)

    frames: list[Image.Image] = []
    durations: list[int] = []

    def _push(lines: list[str], dur_ms: int, *, cursor: bool = False) -> None:
        frames.append(_render_frame(lines, reg_font, bold_font, show_cursor=cursor))
        durations.append(dur_ms)

    # Phase 1: `$ spar demo` typing + live target banner
    cmd_str = "spar demo"
    for n in range(1, len(cmd_str) + 1):
        _push([f"$ {cmd_str[:n]}"], 75, cursor=True)
    _push([f"$ {cmd_str}"], 320, cursor=False)

    buf: list[str] = [f"$ {cmd_str}"]
    for bline in phases["banner"]:
        buf.append(bline)
    _push(buf, 700)

    # Subtle progress indicator before recon + findings resolve
    for spin in ("⠋ Running AST aiming, PyRIT attacks, deterministic oracles, and IndependentCritic (20 trials/objective)…",
                 "⠙ Running AST aiming, PyRIT attacks, deterministic oracles, and IndependentCritic (20 trials/objective)…",
                 "⠸ Running AST aiming, PyRIT attacks, deterministic oracles, and IndependentCritic (20 trials/objective)…"):
        _push(buf + ["", spin], 320)

    # Phase 2: Recon & 11 proven findings table
    buf.append("")
    buf.extend(phases["summary_header"])
    _push(buf, 550)

    for fline in phases["findings"]:
        buf.append(fline)
        _push(buf, 170)

    buf.append("")
    for mline in phases["metadata"]:
        buf.append(mline)
    _push(buf, 650)

    # Phase 3: Regression suite & final proven finding screen
    buf.append("")
    for idx, pline in enumerate(phases["pytest"]):
        buf.append(pline)
        step_ms = 220 if idx < 2 else 140
        _push(buf, step_ms)

    if phases["first_proof"]:
        buf.append("")
        buf.extend(phases["first_proof"])

    # Final held frame ends clearly on proven findings + failing regression suite confirmation
    _push(buf, 3600)
    return frames, durations


def render_demo_gif(raw_output: str, out_path: Path, *, optimize_gifsicle: bool = True) -> dict[str, int]:
    """Render and optimize `assets/spar-demo.gif`, returning frame count, dimensions, and byte size."""
    frames, durations = build_frames(raw_output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    paletted = [fr.convert("P", palette=Image.Palette.ADAPTIVE, colors=64) for fr in frames]
    tmp_gif = out_path.with_suffix(".raw.gif")
    paletted[0].save(
        tmp_gif,
        save_all=True,
        append_images=paletted[1:],
        duration=durations,
        loop=0,
        optimize=False,
    )

    gifsicle_bin = shutil.which("gifsicle") or "/opt/homebrew/bin/gifsicle"
    if optimize_gifsicle and Path(gifsicle_bin).is_file():
        subprocess.run(
            [gifsicle_bin, "-O3", str(tmp_gif), "-o", str(out_path)],
            check=True,
            capture_output=True,
        )
        tmp_gif.unlink(missing_ok=True)
    else:
        tmp_gif.replace(out_path)

    return {
        "frames": len(frames),
        "width": CANVAS_W,
        "height": CANVAS_H,
        "bytes": out_path.stat().st_size,
    }


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Capture real `spar demo --trials 20` output and render assets/spar-demo.gif.")
    ap.add_argument("--trials", type=int, default=20, help="Trials per objective for `spar demo` (default 20)")
    ap.add_argument("--out", default=str(DEFAULT_OUT_GIF), help="Output GIF path")
    ap.add_argument("--input-log", default=None, help="Optional existing captured `spar demo` log file")
    ap.add_argument("--save-log", default=None, help="Optional path to save captured stdout text")
    args = ap.parse_args(argv)

    if args.input_log:
        raw_output = Path(args.input_log).read_text(encoding="utf-8")
        rc = 0
    else:
        raw_output, rc = capture_real_demo(trials=args.trials)
        if args.save_log:
            Path(args.save_log).write_text(raw_output, encoding="utf-8")
        if rc != 0:
            print(f"error: `spar demo --trials {args.trials}` exited with code {rc}", file=sys.stderr)
            print(raw_output, file=sys.stderr)
            return rc

    info = render_demo_gif(raw_output, Path(args.out))
    print(f"Recorded {args.out}: {info['frames']} frames, {info['width']}x{info['height']}, {info['bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
