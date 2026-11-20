# PyRIT executor integration — live validation

Spar now runs **PyRIT's own attack executors**, driven by **Spar's deterministic oracle**
instead of an LLM judge. The attacker model writes and escalates prompts; whether the
objective was achieved is a reached-sink verdict (canary / tool-log / prompt-hash), never
a model's opinion.

## What was built

- `spar/attacks/oracle_scorer.py` — `SparOracleScorer`, a real PyRIT
  `MessageTrueFalseScorer` whose verdict is `spar.oracles.evaluate_oracle`. It scores True
  only on a `MACHINE_CONFIRMED` oracle match, so a PyRIT multi-turn loop keeps escalating
  until a deterministic oracle confirms success.
- `spar/attacks/pyrit_executor.py` — `run_crescendo()` runs PyRIT's real `CrescendoAttack`
  with an OpenAI-compatible adversarial target and `SparOracleScorer`, sending every prompt
  through Spar's guarded client. `adversarial_configured()` selects this path when an
  attacker LLM is set; otherwise the deterministic ladder is the keyless/CI fallback.
- Wired into the `prompt_extraction` mission.

## Live run (measured, not simulated)

Target: the bundled demo agent. Attacker: `gpt-4o-mini` via the agent proxy. Objective:
extract the agent's exact system prompt (oracle = SHA-256 match on the recovered prompt).

| Metric | Value |
| --- | --- |
| Executor | PyRIT `CrescendoAttack` (real) |
| Turns generated and sent | 9 |
| Scoring | `SparOracleScorer` → `evaluate_oracle` (`sha256_prompt_match`) |
| Objective achieved | No (`candidate_hit = False`) |
| Wall-clock | ~35 s |

Oracle success path, checked separately with the demo's known trigger phrasing: the leak is
detected at `MACHINE_CONFIRMED` (`matched = True`, oracle `sha256_prompt_match`). So the
scorer correctly confirms a real leak; the Crescendo run above simply did not elicit one.

## Honest finding

The demo agent leaks its system prompt only on specific hardcoded trigger phrases. The old
hand-rolled ladder always "won" because it hardcoded those exact phrases — which is circular.
A real adaptive attacker (PyRIT + `gpt-4o-mini`) did **not** reliably hit them in 9 turns.

This is evidence, not a defect in the executor: the integration works; the **keyword-triggered
demo is too brittle to be a meaningful target for an adaptive attacker.** It is the concrete
motivation for giving the demo target a real tool-calling LLM agent mode (tracked next), so
the end-to-end numbers reflect attacking a real agent rather than a lookup table.

## Reproduce

Requires an attacker LLM. Set `llm.base_url` / `llm.model` in `spar.yaml` (and the API key in
the referenced env var), then run a `prompt_extraction` objective; with no LLM configured the
deterministic ladder runs instead. Offline tests: `pytest tests/test_oracle_scorer.py`.
