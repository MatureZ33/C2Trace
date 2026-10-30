from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c2trace.bench_v3 import ScoreValidationError, score_files, write_score_outputs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministically score one C2Trace Bench v3 CaseFile."
    )
    parser.add_argument("--ground-truth", required=True, help="Ground Truth v3 JSON path")
    parser.add_argument("--casefile", required=True, help="C2Trace casefile.json path")
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory that receives score.json and score.md",
    )
    args = parser.parse_args()
    output_dir = Path(args.output_dir).resolve()
    try:
        score = score_files(args.ground_truth, args.casefile)
        write_score_outputs(
            score,
            output_dir / "score.json",
            output_dir / "score.md",
        )
    except ScoreValidationError as exc:
        parser.error(str(exc))
    print(f"score_json={output_dir / 'score.json'}")
    print(f"score_markdown={output_dir / 'score.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
