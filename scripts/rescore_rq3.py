"""Re-score all 96 RQ3 trials from retained ground truth and scoring CaseFiles.

This offline check replays the original v3 trace/action matching core after the
original v4 input normalization. It neither queries hosts nor invokes models.
Q6 and Q7 used identical copies of both scorer modules. Host-state measurements
and environment recovery receipts are retained observations, not reconstructed.
"""
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    for relative in ('bench_v3/scorer.py', 'bench_v4/scorer.py'):
        core = ROOT/'variants/rq3_core/src/c2trace'/relative
        payload = ROOT/'variants/rq3_payload/src/c2trace'/relative
        if not core.is_file() or not payload.is_file():
            raise FileNotFoundError('Run python scripts/extract_artifacts.py first.')
        assert hashlib.sha256(core.read_bytes()).digest() == hashlib.sha256(payload.read_bytes()).digest(), relative
    sys.path.insert(0, str(ROOT/'variants/rq3_core/src'))
    from c2trace.bench_v3.scorer import score_case
    from c2trace.bench_v4.scorer import normalize_casefile, normalize_ground_truth

    entries = [e for e in read(ROOT/'data/inventory.json') if e['experiment']=='ablation']
    assert len(entries)==96
    for entry in entries:
        folder = ROOT/entry['path']
        score = score_case(normalize_ground_truth(read(folder/'ground_truth.json')),
                           normalize_casefile(read(folder/'scoring_casefile.json')))
        retained = read(folder/'score.json')
        for field in ('trace_metrics', 'response_action_metrics'):
            for key in ('tp','fp','fn','precision','recall','f1'):
                got, expected = score[field][key], retained[field][key]
                equal = got is None and expected is None or (
                    isinstance(got,(int,float)) and isinstance(expected,(int,float))
                    and math.isclose(got,expected,rel_tol=1e-9,abs_tol=1e-9))
                assert equal,(entry['run_id'],field,key,got,expected)
    print('Re-scored 96 RQ3 trials from retained Ground Truth and scoring CaseFiles; all trace/action counts and metrics match.')


if __name__=='__main__':
    main()
