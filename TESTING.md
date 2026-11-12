# Release verification

Verified offline on Windows for the November 12, 2026 update:

* 150 application, planning, authorization, transport, scoring and adapter tests passed. One existing Pydantic settings forward-reference warning was reported by the MCP transport test.
* Offline aggregation verified 160 selected records: 8 RQ1, 48 live RQ2, 8 offline RQ2 and 96 RQ3 trials.
* All 96 RQ3 scoring inputs were rescored against their saved scenario references; TP/FP/FN, precision, recall and F1 matched the retained records.
* All eight Direct LLM original scores, corrected scores and action-proposal scores were reproduced. The original model outputs are preserved.
* The FULL/A1/A2/A3 command-line help entries and mocked Planner/profile checks passed. Python source syntax was checked across the main application and the two RQ3 source packages.
* Archive integrity, file checksums and credential-pattern scans passed. Local caches and test fixtures generated during release verification are excluded from the distribution.

To repeat the offline checks:

```shell
python scripts/extract_artifacts.py
python scripts/recompute_results.py
python scripts/rescore_rq3.py
python scripts/recompute_direct_adapter.py
python -m pytest -q
```

No new model inference, VM deployment or live response experiment was performed during release verification. The manuscript source and its referenced graphics were checked for file availability; LaTeX compilation was not part of this verification.
