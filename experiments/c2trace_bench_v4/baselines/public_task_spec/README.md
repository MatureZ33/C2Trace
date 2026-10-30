# Public ReAct Task Specification

This directory is the frozen, model-visible contract for the independent
LangGraph ReAct baseline. It is deliberately separate from C2Trace's private
knowledge base and from every case's ground truth.

The contract describes capabilities and safety boundaries only:

- `task_spec.json` defines the task and the canonical alert fields.
- `tool_schema.json` defines the read-only and response interfaces.
- `system_safety.json` defines target-agnostic system protections.
- `output_schema.json` defines the neutral final report.

No file in this directory contains a case target, expected response, process
identity, payload hash, post-state, or scoring answer. The files are copied or
hashed into a formal baseline manifest before a run. They are not generated
from a case ground-truth file.
