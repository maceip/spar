"""Spar CLI: 3-command interface (demo, run, replay)."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from .guard import GuardViolation, ScopeGuard
from .loop import ReplaySummary, RunSummary, _classify_pytest_result, run_campaign, run_replay
from .oracles import Outcome
from .policy import CampaignPolicy, ConfigError, CredentialStore, load_policy


def _print_summary(summary: RunSummary) -> None:
    plan = summary.plan or {}
    n_obj = len(plan.get("objectives", []))
    trials_n = int(plan.get("trials_n", 0) or 0)
    rejected_hits = sum(int(r.get("candidate_hits", 0) or 0) for r in summary.rejected)
    tools = summary.recon.get("tools", []) if isinstance(summary.recon, dict) else []
    side = sum(1 for t in tools if isinstance(t, dict) and t.get("side_effect"))
    snap = plan.get("snapshot_id", {}) if isinstance(plan.get("snapshot_id"), dict) else {}
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}

    print()
    print(
        f"Spar: {n_obj} objectives x {trials_n} trials, {len(summary.findings)} achieved, "
        f"{rejected_hits} candidate hits rejected by the critic"
    )
    print(
        f"Recon: {len(tools)} tools ({side} with side effects), "
        f"system prompt {'recovered' if snap.get('system_prompt_sha256') else 'not indexed'}, "
        f"{len((summary.recon or {}).get('retrieval_sources', []))} retrieval source(s)"
    )
    for f in sorted(summary.findings, key=lambda x: (sev_order.get(x.severity, 9), -x.success_rate)):
        ci = f"[{f.wilson_ci_low:.2f},{f.wilson_ci_high:.2f}]"
        print(f"  {f.severity:<5} {f.objective[:54]:<56} {f.k}/{f.n} {ci}  proof: {f.witness[:64]}")
    print()
    print(f"  report  {summary.report_path}")
    if summary.tests_path:
        print(f"  tests   {summary.tests_path}  ({len(summary.findings)} finding test(s))")
    b = summary.budget or {}
    print(
        f"  cost    ${float(b.get('usd_spent', 0.0)):.2f} in model calls ({int(b.get('llm_calls', 0) or 0)} LLM calls), "
        f"{float(b.get('elapsed_s', 0.0)) / 60:.1f} min, {int(b.get('requests', 0) or 0)} guarded requests"
    )
    print(f"  outcome {summary.overall_outcome.value} (integrity={'pass' if summary.integrity.passed else 'fail'})")
    if summary.findings:
        top = max(summary.findings, key=lambda x: x.success_rate)
        print()
        print(f"  first-screen proof: {top.objective} — {top.k}/{top.n} trials, {top.witness}")


def _print_replay_summary(summary: ReplaySummary) -> None:
    print()
    print(f"Spar replay: {summary.run_dir} -> {summary.overall_outcome.value}")
    for r in summary.results:
        print(
            f"  {str(r.get('finding_id', '')):<32} {str(r.get('label', '')):<13} "
            f"{int(r.get('k', 0))}/{int(r.get('n', 0))}  {str(r.get('reason', ''))[:64]}"
        )
    print(f"  pytest  {summary.pytest_status} (rc={summary.pytest_returncode})")
    print(f"  report  {summary.report_path}")
    print(f"  integrity {'pass' if summary.integrity.passed else 'fail'}")


def _run_demo_pytest(tests_path: Path, run_dir: Path) -> str:
    print("\nRunning the emitted regression suite (expected to FAIL while the target is vulnerable):")
    env = dict(os.environ)
    env.pop("SPAR_TARGET_URL", None)
    env["SPAR_POLICY_PATH"] = str((run_dir / "policy.json").resolve())
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests_path), "-q", "--no-header", "--tb=line"],
            env=env,
            cwd=Path.cwd(),
        )
    except (FileNotFoundError, OSError):
        print("Pytest unavailable: inconclusive.")
        return "inconclusive"

    status = _classify_pytest_result(proc.returncode, "", "")
    if status == "passed":
        print("Unexpected: suite passed — target does not exhibit the verified findings.")
    elif status == "reproduced":
        print(f"Suite failed as expected (exit {proc.returncode}): confirmed attacks reproduce.")
    else:
        print(f"Suite exited with status {proc.returncode} (inconclusive).")
    return status


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo_target import generate_ephemeral_tokens, run_server

    if args.trials is not None and args.trials < 1:
        print("error: --trials must be >= 1", file=sys.stderr)
        return 2

    ephemeral_tokens = generate_ephemeral_tokens()
    token_envs = {
        "alice": "SPAR_DEMO_TOKEN_ALICE",
        "bob": "SPAR_DEMO_TOKEN_BOB",
        "auditor": "SPAR_DEMO_TOKEN_AUDITOR",
    }
    overrides = {token_envs[name]: tok for name, tok in ephemeral_tokens.items()}

    srv, _thread, port, _target = run_server(port=0, tokens=ephemeral_tokens)
    base_url = f"http://127.0.0.1:{port}"
    print(f"spar demo: bundled vulnerable multi-user target live at {base_url}")
    print("           (ephemeral in-memory tokens, localhost only, synthetic data)")

    policy = CampaignPolicy.default_demo(
        base_url,
        token_envs,
        allow_risky=True,
        trials_n=args.trials if args.trials is not None else 20,
    )
    for acct in policy.accounts:
        if acct.name in ephemeral_tokens and not acct.token_fingerprint:
            acct.token_fingerprint = CredentialStore.fingerprint(ephemeral_tokens[acct.name])

    cred_store = CredentialStore(policy.accounts, overrides=overrides)
    repo = Path(__file__).resolve().parent / "demo_target"
    try:
        summary = run_campaign(
            policy,
            cred_store,
            spar_root=Path(args.spar_dir),
            repo=repo,
            tests_dir=Path("spar_tests"),
        )
    except (GuardViolation, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        srv.shutdown()
        srv.server_close()

    _print_summary(summary)
    if summary.tests_path and not args.no_pytest:
        _run_demo_pytest(summary.tests_path, summary.run_dir)

    if not summary.integrity.passed or summary.overall_outcome == Outcome.INCONCLUSIVE:
        return 3
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if args.trials is not None and args.trials < 1:
        print("error: --trials must be >= 1", file=sys.stderr)
        return 2

    cfg_path = Path(args.config)
    try:
        if cfg_path.exists():
            policy = load_policy(cfg_path, target_url=args.target)
        elif args.config != "spar.yaml":
            raise ConfigError(f"Config file not found: {cfg_path}")
        else:
            policy = CampaignPolicy(target_url=args.target)

        if args.allow_risky:
            policy.allow_risky = True
        if args.trials is not None:
            policy.trials_n = args.trials

        repo = Path(args.repo).resolve() if args.repo else None
        if repo is not None and not repo.exists():
            raise ConfigError(f"--repo path does not exist: {repo}")

        ScopeGuard(policy.allowlist_hosts, allow_risky=policy.allow_risky).check_url(policy.target_url)
        cred_store = CredentialStore(policy.accounts)
        summary = run_campaign(
            policy,
            cred_store,
            spar_root=Path(args.spar_dir),
            repo=repo,
            tests_dir=Path("spar_tests"),
        )
    except (GuardViolation, ConfigError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_summary(summary)
    if not summary.integrity.passed or summary.overall_outcome == Outcome.INCONCLUSIVE:
        return 3
    if summary.overall_outcome == Outcome.REPRODUCED:
        return 1
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    if args.trials is not None and args.trials < 1:
        print("error: --trials must be >= 1", file=sys.stderr)
        return 2

    if args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        latest_path = Path(args.spar_dir) / "latest"
        if not latest_path.is_file():
            print(
                f"error: no --run-dir provided and {latest_path} does not exist; run `spar demo` or `spar run` first",
                file=sys.stderr,
            )
            return 2
        run_id = latest_path.read_text(encoding="utf-8").strip()
        if not run_id:
            print(f"error: empty {latest_path}", file=sys.stderr)
            return 2
        run_dir = Path(args.spar_dir) / "runs" / run_id

    try:
        summary = run_replay(
            run_dir,
            finding_id=args.finding,
            apply_fix=bool(args.apply_fix),
            target_override=args.target,
            trials_override=args.trials,
            run_pytest=not args.no_pytest,
        )
    except (GuardViolation, ConfigError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_replay_summary(summary)
    if not summary.integrity.passed or summary.overall_outcome == Outcome.INCONCLUSIVE:
        return 3
    if summary.overall_outcome == Outcome.REPRODUCED:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="spar",
        description="Spar: autonomous AI red-team & verification system (demo, run, replay).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="launch and attack the bundled deliberately-vulnerable demo target")
    d.add_argument("--trials", type=int, default=None, help="trials per objective (default 20)")
    d.add_argument("--spar-dir", default=".spar", help="root directory for Spar run state (default .spar)")
    d.add_argument("--no-pytest", action="store_true", help="skip running the emitted regression suite")
    d.set_defaults(fn=cmd_demo)

    r = sub.add_parser("run", help="run a guarded campaign against a live target")
    r.add_argument("--target", required=True, help="target base URL")
    r.add_argument("--repo", default=None, help="target source repository path for white-box aiming")
    r.add_argument("--config", default="spar.yaml", help="policy YAML path (default spar.yaml)")
    r.add_argument("--trials", type=int, default=None, help="trials per objective")
    r.add_argument("--spar-dir", default=".spar", help="root directory for Spar run state (default .spar)")
    r.add_argument("--allow-risky", action="store_true", help="permit state-changing actions")
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("replay", help="replay saved findings and verify fixes under frozen policy")
    rp.add_argument("--run-dir", default=None, help="run directory (defaults to .spar/runs/<latest>)")
    rp.add_argument("--spar-dir", default=".spar", help="root directory for resolving latest run (default .spar)")
    rp.add_argument("--finding", default=None, help="replay a single finding id")
    rp.add_argument("--apply-fix", action="store_true", help="synthesize and apply patch diffs before replaying")
    rp.add_argument("--target", default=None, help="override target URL (must satisfy frozen allowlist)")
    rp.add_argument("--trials", type=int, default=None, help="override trials per finding")
    rp.add_argument("--no-pytest", action="store_true", help="skip running the emitted regression suite")
    rp.set_defaults(fn=cmd_replay)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:
        print("\nspar: kill switch activated — evidence ledger preserved.", file=sys.stderr)
        return 130


__all__ = ["build_parser", "cmd_demo", "cmd_replay", "cmd_run", "main"]
