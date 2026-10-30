# Release verification

Verified locally on Windows with Python 3.12, MCP 1.28.1 and cryptography 49.0.0. Historical evaluation metadata records Python 3.11.9 on Windows 10; the release check is not a rerun of those experiments.

* Editable package installation and `run_case.py --help` succeeded.
* 161 included offline tests passed. One dependency warning concerns a Pydantic settings forward reference in the local MCP test; it did not fail the test suite.
* Offline aggregation verified all 96 selected records and their reported per-case metrics; baseline pooled counts match the final v5 reference. Undefined metrics remain null.
* All eight graphics referenced by `paper/main.tex`, the bibliography, class and supplied style files are present. The existing manuscript was not rewritten or recompiled as part of packaging.
* The included figure drawing source was checked for Python syntax; figure regeneration was not included in this validation. Existing paper PDFs are the authoritative graphics.

The three Planner dependency-repair test fixtures were updated to use an unknown dependency: a missing evidence-gate edge is already fixed by deterministic gate insertion and no longer invokes LLM repair. These test-only changes preserve bounded-repair assertions and do not change the application implementation. A legacy regression test depending on unrelated internal July trial directories is outside the public test selection. A scorer's static contract fixture is supplied under `tests/fixtures/` and does not count as an additional evaluated case.

No model API, VM deployment or live response experiment was executed for this release. Passing offline tests does not establish historical whole-stack identity or eliminate the empirical validity limitations described in the manuscript.
