# C2Trace

Source code, eight-case evaluation artifacts, and manuscript sources for **C2Trace: Evidence-Grounded Investigation and Verified Response to Command-and-Control Alerts**.

C2Trace starts with a network alert, investigates a Windows endpoint through constrained tools, audits proposed responses, and checks the host again after execution. This release covers the original eight cases and the baseline selection used in the October 15 manuscript. Subsequent case expansion and additional agent baselines are outside this release.

## Repository contents

| Path | Contents |
|---|---|
| `src/c2trace/` | Planner, Auditor, Executor, MCP service, authorization, tool backend, knowledge/history, evaluators and experiment adapters |
| `run_case.py` | C2Trace command-line entry point |
| `kb/`, `prompts/` | Generic investigation knowledge and prompt templates |
| `experiments/case_index.json` | Index of the eight evaluated cases and their public sources |
| `experiments/c2trace_bench_v4/` | Case contracts, evidence/cleanup plans, Ground Truth templates and neutral baseline task specification |
| `archives/` | Compressed, sanitized experiment records and historical ablation sources |
| `data/inventory.json` | Exact selection of 96 retained evaluation records |
| `data/protocol/` | Experimental protocol and population selection records |
| `data/paper_reference_metrics.json` | Reference values for the manuscript populations |
| `scripts/recompute_results.py` | Offline checks, aggregation and per-trial cost export |
| `paper/` | Complete LaTeX manuscript, bibliography, figures and template dependencies |
| `tests/` | Offline application, authorization, transport, scoring and baseline-contract checks |

## Reproduce the reported arithmetic

Python 3.11 or later is sufficient; these commands do not install packages or contact models/hosts:

```shell
python scripts/extract_artifacts.py
python scripts/recompute_results.py
```

Results are written under `results/recomputed/`: `summary.json`, `per_case.json`, `trials.json` and `per_trial_metrics.csv`. The CSV contains TP, FP, FN, precision, recall, F1, stage durations, LLM/tool calls and token counts for every selected record. Missing or undefined measurements remain empty/null, not zero.

| Evaluation population | Retained records | Interpretation |
|---|---:|---|
| Effectiveness | 8 | One selected execution per original case |
| Paired baseline | 48 | 8 cases × 3 repetitions × C2Trace/ReAct, arranged in 24 logical pairs |
| Ablation | 32 | 8 cases × 4 variants, one smoke execution per cell |
| LLM-Direct SetB | 8 | One model call per case, zero host tools; action proposals only |

Resource measurements come from these populations; they are not an additional independent experimental sample. Time and token measurements are not electrical-energy measurements.

Recomputed pooled Trace F1 is **0.769231** for effectiveness and **0.843750 / 0.618182** for C2Trace / ReAct in the paired baseline. C2Trace's baseline response counts are **TP=51, FP=0, FN=0**. Action matching, complete trial classification and independent post-response validation are distinct outcomes.

## Install and inspect the implementation

From the repository root:

```shell
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,baseline]"
python -m pytest -q
python run_case.py --help
```

On Linux/macOS, activate with `source .venv/bin/activate`. Offline scoring and most mocked tests are portable; live host tools require Windows. MCP transport tests start a local service with mocked or denied mutation paths, not an attack scenario.

Copy `.env.example` to `.env` locally and fill in your own API key only if running a model. The historical requested model alias was `deepseek-chat`; returned model identities must be read from the retained run metadata. Set this alias explicitly: the inspected source snapshot includes a later LLM-client default, and a requested alias does not guarantee the same provider backend today.

The `--alert` and `--suricata-eve` inputs are mutually exclusive. Response execution is off by default. `--execute-response` additionally requires `--protected-processes` and `--reviewed-target-from`; the latter refers to the reviewed rehearsal output. See `python run_case.py --help` for the full interface. A new VM execution requires provisioning the experiment-specific external services and actual runtime identities; archived identifiers must not be used as current targets.

The repository does not bundle VM images, API keys, SSH credentials, third-party implant binaries or external C2 servers. It supports inspection and offline reproduction of the supplied observations; it is not a one-command recreation of the original two-VM environment.

## Knowledge and experience implementation

* `src/c2trace/kb.py` loads the generic files under `kb/`. The knowledge pack describes tools, investigation patterns and safety/evidence rules. It does not supply current PIDs or file paths and is not a vector-search/RAG service.
* `src/c2trace/experience.py` stores eligible historical cases and sanitizes reusable patterns. Matching uses alert/protocol/port/source features. `agents/planner.py` consumes the resulting context.
* Inspected evaluation configurations had empty history inputs and disabled history updates. The reported results do **not** measure a benefit from experience reuse.

## Evaluation boundaries and version provenance

* The baseline data uses the final selected v5 population. The protocol records identify the service/setup-validity amendment. Valid evaluation failures remain included; selection does not mean choosing the highest score.
* Ablation is descriptive smoke-mode evidence. The four intended variants remove auditing (A1), target binding (A2), precheck (A3), or internal post-verification (A4). Existing downstream gates and incomplete provenance prevent treating every row as a fully isolated causal intervention.
* LLM-Direct measures proposed actions, not performed response or cleanup success.
* Historical Ground Truth has documented limitations, including the Aurora-002 connection identity ambiguity and PlugX file-identity discrepancies. Reproducing an old score does not resolve these validity limitations. See the manuscript discussion and `data/paper_reference_metrics.json` caveats.
* `data/source_version_checks.json` compares included source with retained protocol fingerprints. The inspected application snapshot and archived variant snapshots are not certified byte-identical whole-stack source freezes for every historical run. Protocol amendments and subsequent adapter/client changes are explicitly distinguished from the recorded observations.
* Exported records have credentials and personal profile roots redacted. Lab network addresses, process identities, object hashes, outcomes and numeric measurements are retained for interpretation. Historical receipt hashes describe original bytes; use `SOURCE_MANIFEST.json` and `RELEASE_MANIFEST.json` to verify this export. Redacted artifacts cannot reproduce historical signatures or original prompt-body hashes.

## Manuscript

Upload the contents of `paper/` to Overleaf, keep `main.tex` at the project root, and use pdfLaTeX. All figures referenced by that manuscript are supplied. The paper is the existing October 15 baseline-updated source; this release does not silently substitute later figure drafts or new experimental results. Figure source scripts, where retained, are under `paper/figure_sources/`.

## Attribution and licensing

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for source attribution and template notices. No new project-wide open-source license is granted by this export. Third-party components retain their own terms. A public release should carry the license selected by the authors/rights holders.

For a Chinese overview, see [README.zh-CN.md](README.zh-CN.md).
