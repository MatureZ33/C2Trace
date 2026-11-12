# Offline Direct LLM scoring

The eight retained model outputs are evaluated after aligning the prediction
adapter with the trace scorer. The prompt's `process` and `file` entities map to
`process_detail` and `file_metadata`. For a file entity, an existing `details.path`
is retained; otherwise its explicit `value` supplies that path. The adapter never
reads ground truth. Process fields and action arguments are unchanged.

This is an offline scoring correction of the existing runs. The same scorer,
one-to-one matching, deduplication rules, and 35 reference entries are retained.
There are no new model requests or host actions. Trace micro precision, recall,
and F1 are **0.821429 / 0.657143 / 0.730159** (TP/FP/FN: **23/5/12**).
Action-proposal micro F1 remains **0.444444** (8/11/9); this measures proposed
actions, not successful execution or cleanup.

Run from the repository root, with Python 3.11 or newer:

```shell
python scripts/recompute_direct_adapter.py
python scripts/recompute_direct_adapter.py --output results/direct_adapter_replay.json
```

The command reads `archives/llm_direct.zip` directly and requires no extraction or
third-party dependencies. It verifies the original scores, corrected scores,
action-proposal scores, and exported member hashes. Comparisons ignore only the
replay timestamp and the case of the fixed `LAB_USER` redaction token in paths.

Each archived case includes the unchanged `prediction_ir.json`, original
`casefile.json`, evaluation input `adapted_casefile.json`, and `ground_truth.json`.
The current result is `score.json`. Historical scores and manifests are retained
as `score_before_adapter_alignment.json` and
`formal_result_manifest_before_adapter_alignment.json`; their historical trace
F1 is not the current baseline result. `formal_result_manifest.json` identifies
the current exported inputs and scoring command with repository-relative paths.

`llm_direct_per_case_aggregate.json` and `llm_direct_macro_micro_aggregate.json`
contain current results. `adapter_alignment_metrics.json` records the replay
checks, per-case changes, and old/current comparison. Export provenance and
original source digests are in `adapter_alignment_provenance.json`.
