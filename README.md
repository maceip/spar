<p align="center">
  <img src="assets/logo/spar-hero.gif" alt="Spar — Autonomous AI Red-Teaming & Penetration Testing" width="320">
</p>

<p align="center">
  <strong>Pentest on commit.</strong><br>
  Autonomous AI red-teaming and penetration testing. Read the code, attack the live target, prove every finding with evidence, and hand back a failing test and SARIF report.
</p>

<p align="center">
  <img src="assets/spar-demo.gif" alt="spar demo proving real attacks and emitting a failing test suite" width="820">
</p>

## Quickstart

Requires Python 3.11–3.14.

```bash
pip install -e ".[dev]"
spar demo
```

`spar demo` starts a safe, local practice AI with fake users and breaks it right in your terminal—no setup or API keys needed.

## What Spar tests

- **Tool abuse** — Tricking an AI into emailing another user's private invoice or issuing an unauthorized refund.
- **Shared memory poisoning** — Planting hidden instructions in memory so a different user's later chat leaks data.
- **Hidden prompt injections** — Sneaking commands inside shared documents, images, non-English messages, or connected tools.
- **False completions** — Catching an AI that claims it deleted or updated a record when no tool ever ran.

## How it works

1. **Aim** — Reads your codebase (or probes your live AI) to map what tools, data, and permissions it can reach.
2. **Prove** — Runs repeated trials and only reports a finding when hard evidence confirms the exploit and an independent replay reproduces it.
3. **Hand off** — Outputs a report, a failing test suite, and remediation context for your engineers or external fix tools, then re-tests after a patch lands with `spar replay`.

## Measured results

- **Demo AI (`5 × 20` trials):** `11/11` vulnerabilities proven across all 5 runs (`$0.00` model cost) — [recorded report](evals/recorded_demo_run/report.md).
- **AgentDojo (`gpt-4o-mini`):** `$0.176421` (`~$0.18`) across `458` model calls with `17` false alarms caught before reporting — [full evaluation](evals/RESULTS.md).
- **Human audit:** `0%` disagreement (`0/20`) across 20 randomly sampled verdicts spanning both Demo AI and AgentDojo runs.

## Run against your own target

```bash
spar run --target http://localhost:8000 --repo .   # with source code
spar run --target http://localhost:8000          # black-box (no source code)
spar replay                                      # re-attack after a patch lands
```

## Safety by default

Spar only contacts `localhost` and hosts explicitly allowlisted in [spar.yaml](spar.yaml), keeps state-changing actions disabled unless you opt in, and never writes account tokens or API keys into reports or generated tests.
