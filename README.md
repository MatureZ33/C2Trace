# C2Trace

Source code and evaluation artifacts for **C2Trace: Evidence-Grounded Investigation and Verified Response to Command-and-Control Alerts**.

C2Trace investigates Windows hosts from network alerts, uses domain-guided planning and a shared CaseFile to organize evidence, audits proposed responses, and verifies the host after execution.

## Repository contents

| Path | Contents |
|---|---|
| `src/c2trace/`, `run_case.py` | Application, tools, authorization and evaluators |
| `kb/`, `prompts/` | Domain knowledge and prompt templates |
| `experiments/` | Eight scenario definitions and baseline task specifications |
| `archives/` | Experiment records and RQ3 source packages |
| `data/inventory.json` | Selected runs, organized by experiment, scenario and repetition |
| `data/protocol/ablation/` | RQ3 configuration mapping and reference results |
| `scripts/recompute_results.py` | Offline aggregation of recorded scores and resource measurements |
| `scripts/recompute_direct_adapter.py` | Offline Direct LLM output-adapter verification |
| `paper/` | Locally supplied manuscript, bibliography and referenced figures |
| `tests/` | Offline application, authorization, scoring and transport tests |

## Reproduce the results offline

Python 3.11 or later is required. Extract the records, then aggregate their scores:

```shell
python scripts/extract_artifacts.py
python scripts/recompute_results.py
python scripts/rescore_rq3.py
```

The extraction script automatically joins archive parts and verifies their checksums. These commands do not call a model or operate on a host. Aggregated results are written to `results/recomputed/`: `summary.json`, `per_case.json`, `trials.json` and `per_trial_metrics.csv`. The RQ3 rescorer independently checks all 96 saved scoring inputs against the retained score records. Undefined measurements remain null.

| Evaluation | Trials | Design |
|---|---:|---|
| RQ1 effectiveness | 8 | One trial per scenario |
| RQ2 live comparison | 48 | Eight scenarios, three repetitions, C2Trace and Public ReAct |
| RQ2 Offline Direct LLM | 8 | One inference per scenario; findings and action proposals |
| RQ3 component analysis | 96 | Eight scenarios, three repetitions, full system and three variants |

The four populations contain 160 selected records. RQ3 uses its own full-system trials. The offline baseline produces action proposals; it does not execute host actions.

## RQ3 configurations

| Paper label | Configuration | Original record identifier |
|---|---|---|
| Full | Complete C2Trace | `FULL` |
| A1 | Without domain knowledge and domain-specific Planner guidance | `B1-GENERIC-PLANNER` |
| A2 | Without automatic command-line payload-path extraction during investigation | `B4-NO-CMDLINE-PAYLOAD` |
| A3 | Without independent evidence auditing; execution safeguards remain | `B3-NO-AUDITOR` |

Each configuration has 24 trials. A1 retains the Planner model. A3 retains authorization and execution safeguards. A2 was collected in a subsequent batch using the same scenario definitions and scorer. Its four first-request transport failures remain in the 24-trial population; token usage for these requests is undefined.

| Configuration | Pooled Trace F1 | Pooled Action F1 | Independent host checks passed |
|---|---:|---:|---:|
| Full | 0.875 | 1.000 | 24/24 |
| A1 | 0.379 | 0.111 | 1/24 |
| A2 | 0.697 | 0.756 | 12/24 |
| A3 | 0.875 | N/A | 0/24 |

Original run identifiers are preserved inside experiment records. The inventory maps them to the paper labels. Extraction also provides `variants/rq3_core/` for Full/A1/A3 and `variants/rq3_payload/` for A2. Use the paper labels with the common entry point:

```shell
python scripts/run_ablation.py --variant A1 --help
```

The source packages retain the corresponding component switches. Release source checksums and original-record checksums identify different objects: exported application code is not a byte-identical reconstruction of every historical execution environment.

## Installation and application

```shell
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,baseline]"
python -m pytest -q
python run_case.py --help
```

On Linux/macOS, activate with `source .venv/bin/activate`. Live host tools require Windows. Copy `.env.example` to a local `.env` and supply your own credentials when using a model. The evaluation used DeepSeek v4.1 Flash; archived requests use the provider alias `deepseek-chat`. Configure the provider/model explicitly for new executions.

The `--alert` and `--suricata-eve` inputs are mutually exclusive. Response execution is off by default. `--execute-response` additionally requires `--protected-processes` and `--reviewed-target-from`. Provision current host identities and the scenario's external services before a live run. VM images, credentials, third-party implant binaries and C2 servers are not included.

## Records and scoring

Scores measure agreement with the scenario references. Action matches, trial completion and independent host checks are distinct measurements. The Direct LLM export includes the previously corrected output adaptation: process/file findings are mapped to the scorer's expected types and explicit file paths are carried into the expected field. The saved model outputs and action-proposal scores are unchanged; pooled Trace F1 is 0.730 and Action F1 is 0.444.

Credentials and personal profile roots are redacted in exported records. Numeric results, trial identifiers and scoring objects are retained. After extraction, `SOURCE_MANIFEST.json` records source/export checksums. `RELEASE_MANIFEST.json` and `archives/manifest.json` verify the distributed files.

## Manuscript and attribution

Upload `paper/` to Overleaf with `main.tex` at the project root and select pdfLaTeX. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for third-party attribution and template notices. No new project-wide license is granted by this update.

[中文说明](README.zh-CN.md)
