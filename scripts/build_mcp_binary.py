#!/usr/bin/env python3
"""Build a standalone, single-file Spar instant MCP server executable via PyInstaller.

Produces an independent binary for macOS, Linux, or Windows that bundles Python,
Spar, PyYAML, Pillow, PyRIT converters/models, and the zero-dependency stdio MCP
server (`spar.mcp_server`).

Usage:
  python scripts/build_mcp_binary.py --output-name spar-mcp-darwin-arm64
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent

# Giant optional ML/cloud/web dependencies dragged in transitively by pyrit/evals
# that Spar's core runtime and MCP server do not need at runtime.
EXCLUDED_MODULES = [
    "torch",
    "torchvision",
    "torchaudio",
    "transformers",
    "datasets",
    "pyarrow",
    "pandas",
    "scipy",
    "numpy",
    "matplotlib",
    "av",
    "lxml",
    "tkinter",
    "_tkinter",
    "pytest",
    "agentdojo",
    "langchain",
    "langchain_core",
    "langgraph",
    "fastapi",
    "uvicorn",
    "starlette",
    "anthropic",
    "google.genai",
    "cohere",
    "playwright",
    "reportlab",
    "docx",
    "openpyxl",
    "pypdf",
    "pyodbc",
    "aioodbc",
    "sqlalchemy.dialects.mysql",
    "sqlalchemy.dialects.oracle",
]

HIDDEN_IMPORTS = [
    "spar",
    "spar.cli",
    "spar.mcp_server",
    "spar.policy",
    "spar.guard",
    "spar.ledger",
    "spar.target",
    "spar.aim",
    "spar.oracles",
    "spar.fix",
    "spar.integrity",
    "spar.report",
    "spar.loop",
    "spar.sarif_export",
    "spar.attacks",
    "spar.attacks.pyrit_adapter",
    "spar.attacks.recipes",
    "spar.attacks.held_out",
    "spar.attacks.benign",
    "spar.attacks.fixtures",
    "spar.demo_target",
    "spar.demo_target.app",
    "spar.third_party.mantis",
    "spar.third_party.mantis.evidence",
    "spar.third_party.mantis.sarif",
    "pyrit",
    "pyrit.common",
    "pyrit.converter",
    "pyrit.converter.converter",
    "pyrit.converter.base64_converter",
    "pyrit.converter.leetspeak_converter",
    "pyrit.converter.rot13_converter",
    "pyrit.converter.unicode_confusable_converter",
    "pyrit.memory",
    "pyrit.memory.central_memory",
    "pyrit.memory.memory_interface",
    "pyrit.memory.memory_models",
    "pyrit.memory.sqlite_memory",
    "pyrit.models",
    "pyrit.prompt_target",
    "pyrit.prompt_target.common",
    "pyrit.prompt_target.common.prompt_target",
    "pyrit.prompt_target.common.target_configuration",
    "pyrit.setup",
    "pyrit.setup.initialization",
    "aiosqlite",
    "sqlite3",
    "yaml",
    "PIL",
    "PIL.Image",
    "confusables",
    "confusable_homoglyphs",
]


def _default_output_name() -> str:
    sys_name = platform.system().lower()
    if sys_name == "darwin":
        os_tag = "darwin"
    elif sys_name == "windows":
        os_tag = "windows"
    else:
        os_tag = "linux"
    mach = platform.machine().lower()
    arch_tag = "arm64" if mach in ("arm64", "aarch64") else "x64"
    return f"spar-mcp-{os_tag}-{arch_tag}"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build(output_name: str, dist_dir: Path, work_dir: Path) -> Path:
    entry = work_dir / "_spar_mcp_entry.py"
    work_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)
    entry.write_text(
        "from spar.mcp_server import main\n"
        "if __name__ == '__main__':\n"
        "    raise SystemExit(main())\n",
        encoding="utf-8",
    )

    sep = ";" if os.name == "nt" else ":"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--name",
        output_name,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir / "build"),
        "--specpath",
        str(work_dir),
        "--paths",
        str(REPO_ROOT),
    ]

    # Bundle package data needed at runtime (demo_target source for white-box demo aiming, Mantis LICENSE, default spar.yaml).
    data_pairs = [
        (REPO_ROOT / "spar" / "demo_target" / "app.py", "spar/demo_target"),
        (REPO_ROOT / "spar" / "third_party" / "mantis" / "LICENSE", "spar/third_party/mantis"),
        (REPO_ROOT / "spar.yaml", "."),
    ]
    # Alembic loads pyrit/memory/alembic/env.py and migration scripts as raw .py files on disk.
    try:
        import pyrit  # type: ignore[import-untyped]

        alembic_dir = Path(pyrit.__file__).resolve().parent / "memory" / "alembic"
        if alembic_dir.is_dir():
            data_pairs.append((alembic_dir, "pyrit/memory/alembic"))
    except Exception:
        pass
    for src, dest in data_pairs:
        if src.exists():
            cmd.extend(["--add-data", f"{src}{sep}{dest}"])

    # Collect data files required by confusables / confusable_homoglyphs / pyrit.
    for pkg in (
        "confusables",
        "confusable_homoglyphs",
        "pyrit.models",
        "pyrit.memory",
        "pyrit.executor",
    ):
        cmd.extend(["--collect-data", pkg])

    # PyRIT uses lazy_imports.py (dynamic importlib.import_module); collect the
    # core subpackages loaded at runtime so frozen binaries never hit lazy import misses.
    for pkg in (
        "pyrit.analytics",
        "pyrit.auth",
        "pyrit.common",
        "pyrit.exceptions",
        "pyrit.memory",
        "pyrit.message_normalizer",
        "pyrit.models",
        "pyrit.prompt_target.common",
        "pyrit.setup",
    ):
        cmd.extend(["--collect-submodules", pkg])

    for mod in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", mod])

    for mod in EXCLUDED_MODULES:
        cmd.extend(["--exclude-module", mod])

    cmd.append(str(entry))

    print("Running:", " ".join(cmd))
    subprocess.run(cmd, cwd=str(REPO_ROOT), check=True)

    ext = ".exe" if os.name == "nt" else ""
    binary = dist_dir / f"{output_name}{ext}"
    if not binary.is_file():
        raise FileNotFoundError(f"Expected built binary at {binary}")

    digest = _sha256_file(binary)
    sha_file = dist_dir / f"{binary.name}.sha256"
    sha_file.write_text(f"{digest}  {binary.name}\n", encoding="utf-8")
    print(f"Built {binary} ({binary.stat().st_size / (1024 * 1024):.1f} MiB) sha256={digest}")
    return binary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build standalone Spar instant MCP server binary.")
    ap.add_argument("--output-name", default=_default_output_name(), help="Output executable base name")
    ap.add_argument("--dist-dir", default=str(REPO_ROOT / "dist"), help="Output dist directory")
    ap.add_argument("--work-dir", default=str(REPO_ROOT / "build" / "pyinstaller-mcp"), help="Temporary build work dir")
    args = ap.parse_args(argv)
    build(args.output_name, Path(args.dist_dir).resolve(), Path(args.work_dir).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
