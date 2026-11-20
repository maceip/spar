"""Spar CLI: one program, one job.

Commands:
  spar demo                       zero-config: launch + attack the bundled vulnerable target
  spar run --target URL [--repo P]  full campaign against your target
  spar reattack [--apply-fix]     independent re-attack of saved findings after a patch
  spar webhook [--port N]         wake re-attacks on git push / PR events
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .config import SparConfig
from .coordinator.run import Campaign, RunOptions


def _print_summary(summary, opts: RunOptions) -> None:
    plan = summary.plan
    n_obj = len(plan.get("objectives", []))
    trials_n = plan.get("trials_n", 0)
    rejected_hits = sum(int(r.get("candidate_hits", 0)) for r in summary.rejected)
    tools = summary.recon.get("tools", [])
    side = sum(1 for t in tools if t.get("side_effect"))
    snap = plan.get("snapshot_id", {})

    print()
    print(f"Spar: {n_obj} objectives x {trials_n} trials, {len(summary.findings)} achieved, "
          f"{rejected_hits} candidate hits rejected by the critic")
    print(f"Recon: {len(tools)} tools ({side} with side effects), "
          f"system prompt {'recovered' if snap.get('system_prompt_sha256') else 'not indexed'}, "
          f"{len(summary.recon.get('retrieval_sources', []))} retrieval source")
    for f in sorted(summary.findings, key=lambda x: ({"HIGH": 0, "MED": 1, "LOW": 2}[x.severity], -x.success_rate)):
        print(f"  {f.severity:<5} {f.objective[:58]:<60} {f.k}/{f.n}   proof: {f.witness[:70]}")
    print()
    print(f"  report  {summary.report_path}             proof, transcript and verified fix diff per finding")
    if summary.tests_path:
        print(f"  tests   {summary.tests_path}  {len(summary.findings)} failing (auto-reattacks on patch commit)")
    b = summary.budget
    print(f"  cost    ${b.get('usd_spent', 0):.2f} in model calls ({b.get('llm_calls', 0)} LLM calls), "
          f"{b.get('elapsed_s', 0) / 60:.0f} min, {b.get('requests', 0)} guarded requests")
    if summary.findings:
        top = max(summary.findings, key=lambda x: x.success_rate)
        print()
        print(f"  first-screen proof: {top.objective} — {top.k}/{top.n} trials, {top.witness}")


def _run_pytest(tests_path: Path) -> None:
    print("\nRunning the emitted regression suite (expected to FAIL while the target is vulnerable):")
    env = dict(os.environ)
    env.pop("SPAR_TARGET_URL", None)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_path), "-q", "--no-header", "-x", "--tb=line"],
        env=env, cwd=Path.cwd(),
    )
    if proc.returncode == 0:
        print("Unexpected: suite passed — target does not exhibit the verified findings.")
    else:
        print(f"Suite failed as expected (exit {proc.returncode}): the verified attacks reproduce.")


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo_target import run_server

    srv, _thread, port, _target = run_server(port=0)
    base_url = f"http://127.0.0.1:{port}"
    print(f"spar demo: bundled vulnerable multi-user target live at {base_url}")
    print("           (accounts alice/bob, 6 tools, shared memory — synthetic data, localhost only)")
    cfg = SparConfig.default_demo(base_url)
    if args.trials:
        cfg.trials_n = args.trials
    repo = Path(__file__).parent / "demo_target"
    run_dir = Path(args.run_dir)
    opts = RunOptions(target_url=base_url, config=cfg, run_dir=run_dir, repo=repo,
                      demo_mode=True, trials_n=args.trials)
    _write_run_meta(run_dir, opts)
    try:
        campaign = Campaign(opts)
        summary = campaign.run()
    finally:
        srv.shutdown()
    _print_summary(summary, opts)
    if summary.tests_path and not args.no_pytest:
        _run_pytest(summary.tests_path)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from urllib.parse import urlparse

    cfg_path = Path(args.config)
    cfg = SparConfig.from_file(cfg_path) if cfg_path.exists() else SparConfig()
    if args.target:
        cfg.base_url = args.target
    host = (urlparse(cfg.base_url).hostname or "").lower()
    if host not in {h.lower() for h in cfg.allowlist_hosts}:
        print(f"error: target host {host!r} is not in scope. Add it to {cfg_path}'s "
              "scope.allowlist_hosts (scope is code-enforced, never prompt-enforced).", file=sys.stderr)
        return 2
    if args.allow_risky:
        cfg.allow_risky = True
    if args.trials:
        cfg.trials_n = args.trials
    repo = Path(args.repo).resolve() if args.repo else None
    if repo and not repo.exists():
        print(f"error: --repo {repo} does not exist", file=sys.stderr)
        return 2
    opts = RunOptions(target_url=cfg.base_url, config=cfg, run_dir=Path(args.run_dir),
                      repo=repo, demo_mode=False, trials_n=args.trials)
    _write_run_meta(opts.run_dir, opts)
    campaign = Campaign(opts)
    summary = campaign.run()
    _print_summary(summary, opts)
    return 0 if summary.findings else 1


def _write_run_meta(run_dir: Path, opts: RunOptions) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_meta.json").write_text(json.dumps({
        "target_url": opts.target_url,
        "repo": str(opts.repo) if opts.repo else None,
        "demo_mode": opts.demo_mode,
        "trials_n": opts.trials_n or opts.config.trials_n,
        "accounts": {a.name: a.token for a in opts.config.accounts},
        "budget": {"max_usd": opts.config.max_usd, "max_requests": opts.config.max_requests,
                   "max_duration_s": opts.config.max_duration_s, "rate_per_min": opts.config.rate_per_min},
        "allowlist_hosts": opts.config.allowlist_hosts,
        "started": time.time(),
    }, indent=2), encoding="utf-8")


def cmd_reattack(args: argparse.Namespace) -> int:
    """Independent re-attacker: wakes after a patch lands, rotates
    identifiers, and verifies the fix cannot be bypassed."""
    from .prove.trials import TrialRunner
    from .report.fixdiff import apply_fix, synthesize_fix
    from .fire.tools import ToolKit
    from .guard import Budget, HookContext, KillSwitch, ScopeGuard
    from .coordinator.ledger import Ledger

    run_dir = Path(args.run_dir)
    meta_path = run_dir / "run_meta.json"
    plan_path = run_dir / "plan.json"
    if not meta_path.exists() or not plan_path.exists():
        print("error: no previous run found (need .spar/run_meta.json and .spar/plan.json); run `spar demo` or `spar run` first", file=sys.stderr)
        return 2
    meta = json.loads(meta_path.read_text())
    plan = json.loads(plan_path.read_text())
    findings_dir = run_dir / "findings"
    finding_files = sorted(findings_dir.glob("*.json"))
    if args.finding:
        finding_files = [findings_dir / f"{args.finding}.json"]
        if not finding_files[0].exists():
            print(f"error: finding {args.finding} not found", file=sys.stderr)
            return 2
    if not finding_files:
        print("no saved findings to re-attack")
        return 0

    repo = Path(meta["repo"]) if meta.get("repo") else None
    target_url = args.target or meta["target_url"]
    srv = None
    if args.apply_fix:
        if repo is None:
            print("error: --apply-fix needs a recorded repo (demo run or `spar run --repo`)", file=sys.stderr)
            return 2
        applied = []
        for fp in finding_files:
            fdata = json.loads(fp.read_text())
            diff, pairs, guidance = synthesize_fix(fdata["technique"], repo)
            if pairs:
                applied.extend(apply_fix(pairs, run_dir / "fix_backups"))
                print(f"applied fix for {fdata['id']} ({fdata['technique']})")
            else:
                print(f"no auto-fix recipe matched for {fdata['id']}: {guidance}")
        if not applied:
            print("nothing applied; re-attacking current target state anyway")
    if meta.get("demo_mode") and not args.target:
        # relaunch the (possibly patched) demo target in a subprocess so the
        # patched source is loaded fresh; parse the printed port.
        proc = subprocess.Popen(
            [sys.executable, "-m", "spar.demo_target", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        line = proc.stdout.readline()  # type: ignore[union-attr]
        port = line.strip().rsplit(":", 1)[-1].split(" ")[0]
        target_url = f"http://127.0.0.1:{port}"
        print(f"re-attack target (patched source, fresh process): {target_url}")
        srv = proc

    cfg = SparConfig(base_url=target_url, allowlist_hosts=meta.get("allowlist_hosts", ["127.0.0.1", "localhost"]),
                     allow_risky=True, trials_n=meta.get("trials_n", 20))
    from .config import Account
    cfg.accounts = [Account(n, t, "auditor" if n == "auditor" else "user") for n, t in (meta.get("accounts") or {}).items()]
    budget_cfg = meta.get("budget", {})
    ledger = Ledger(run_dir)
    kill = KillSwitch(run_dir / "STOP")
    budget = Budget(budget_cfg.get("max_usd", 10.0), budget_cfg.get("max_requests", 5000),
                    budget_cfg.get("max_duration_s", 1800), budget_cfg.get("rate_per_min", 600))
    scope = ScopeGuard(cfg.allowlist_hosts, True)
    hook_ctx = HookContext(scope=scope, budget=budget, kill=kill, ledger=ledger, sandboxed_target=meta.get("demo_mode", False))
    tk = ToolKit(hook_ctx, {a.name: a.token for a in cfg.accounts}, repo=repo)
    runner = TrialRunner(tk, target_url, ledger, kill, n_default=cfg.trials_n)

    exit_code = 0
    try:
        for fp in finding_files:
            fdata = json.loads(fp.read_text())
            obj = next((o for o in plan["objectives"] if o["id"] == fdata["objective_id"]), None)
            if obj is None:
                print(f"skip {fdata['id']}: objective not in plan.json")
                continue
            obj = dict(obj)
            obj["trials"] = args.trials or meta.get("trials_n", 20)
            outcome = runner.run(obj)
            label = "hardened" if outcome.k == 0 else "bypassed"
            note = ("fix holds: independent re-attack with rotated identifiers achieved 0/"
                    f"{outcome.n}" if outcome.k == 0 else
                    f"FIX BYPASSED: re-attack still achieves {outcome.k}/{outcome.n} — root cause not closed")
            fdata["reattack"] = {"label": label, "k": outcome.k, "n": outcome.n, "note": note,
                                 "at": time.time(), "target": target_url}
            fp.write_text(json.dumps(fdata, indent=2, default=str))
            ledger.append("reattack.verdict", {"finding_id": fdata["id"], "label": label,
                                               "k": outcome.k, "n": outcome.n}, origin_id=fdata["objective_id"])
            sev = fdata["severity"]
            print(f"  {sev:<5} {fdata['id']:<34} {label:<9} {outcome.k}/{outcome.n}   {note}")
            if label == "bypassed":
                exit_code = 1
    finally:
        if srv is not None:
            srv.terminate()
            srv.wait(timeout=5)
    return exit_code


def cmd_webhook(args: argparse.Namespace) -> int:
    from .skills.webhook import serve_webhook

    return serve_webhook(port=args.port, run_dir=Path(args.run_dir), host=args.host)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="spar", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="attack the bundled deliberately-vulnerable multi-user target (zero config)")
    d.add_argument("--trials", type=int, default=None, help="trials per objective (default 20)")
    d.add_argument("--run-dir", default=".spar")
    d.add_argument("--no-pytest", action="store_true", help="skip running the emitted regression suite")
    d.set_defaults(fn=cmd_demo)

    r = sub.add_parser("run", help="run a campaign against a live target")
    r.add_argument("--target", required=True, help="base URL, e.g. http://localhost:8000/chat")
    r.add_argument("--repo", default=None, help="target source repo for white-box aiming (omit for black-box recon)")
    r.add_argument("--config", default="spar.yaml")
    r.add_argument("--trials", type=int, default=None)
    r.add_argument("--run-dir", default=".spar")
    r.add_argument("--allow-risky", action="store_true", help="permit state-changing techniques outside sandboxed doubles")
    r.set_defaults(fn=cmd_run)

    ra = sub.add_parser("reattack", help="independently re-attack saved findings after a patch (verify the fix holds)")
    ra.add_argument("--run-dir", default=".spar")
    ra.add_argument("--finding", default=None, help="re-attack a single finding id")
    ra.add_argument("--apply-fix", action="store_true", help="apply Spar's synthesized fix diff before re-attacking")
    ra.add_argument("--target", default=None, help="re-attack against this URL instead of the recorded target")
    ra.add_argument("--trials", type=int, default=None)
    ra.set_defaults(fn=cmd_reattack)

    w = sub.add_parser("webhook", help="listen for git push / PR events and wake the re-attacker")
    w.add_argument("--port", type=int, default=8787)
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--run-dir", default=".spar")
    w.set_defaults(fn=cmd_webhook)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("\nspar: kill switch — all active leases revoked, evidence ledger intact.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
