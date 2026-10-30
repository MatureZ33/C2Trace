# Third-party sources and notices

This export does not relicense third-party material or assert ownership of upstream attack-emulation plans, figures, frameworks or LaTeX components.

## Public case sources

The original cases are bounded Windows-endpoint projections of public sources, not full reproductions of every campaign behavior. Source revisions and source-span mappings are retained in the per-case JSON contracts and `experiments/case_index.json`.

* Aurora demonstrations: https://github.com/LexusWang/Aurora-demos
* MITRE ATT&CK Evaluations Library: https://github.com/attackevals/ael
* Center for Threat-Informed Defense adversary emulation library: https://github.com/center-for-threat-informed-defense/adversary_emulation_library

Locally authored adapters and case mappings are included. Complete third-party repositories and executable payload binaries are not vendored. Upstream components must be obtained under their respective upstream terms.

## Runtime frameworks

* MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
* LangGraph (public ReAct baseline framework): https://github.com/langchain-ai/langgraph
* LangChain OpenAI-compatible client integration: https://github.com/langchain-ai/langchain
* MITRE CALDERA (external experiment service): https://github.com/mitre/caldera
* Suricata (external alert source): https://github.com/OISF/suricata

These packages/services are dependencies or upstream resources, not components authored by C2Trace. Installations retain their upstream licenses.

## Manuscript and graphics

The supplied `sn-jnl.cls`, `sn-basic.bst`, `cuted.sty` and `paper/third_party/` files preserve the template/distribution notices available in the manuscript package. Consult the notices embedded in those files for their terms. Third-party visual elements in the supplied architecture figure retain their original ownership.

## Project license

The authors have not selected a new project-wide distribution license as part of this packaging task. This file is an attribution inventory, not a substitute for an author-approved license.
