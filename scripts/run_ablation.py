"""Run an RQ3 configuration using the paper labels, preserving original treatment IDs."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIGURATIONS = {
    'FULL': ('rq3_core', 'FULL'),
    'A1': ('rq3_core', 'B1-GENERIC-PLANNER'),
    'A2': ('rq3_payload', 'B4-NO-CMDLINE-PAYLOAD'),
    'A3': ('rq3_core', 'B3-NO-AUDITOR'),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--variant', choices=CONFIGURATIONS, required=True)
    args, forwarded = parser.parse_known_args()
    folder, original = CONFIGURATIONS[args.variant]
    entry = ROOT / 'variants' / folder / 'run_case.py'
    if not entry.is_file():
        parser.error('Run python scripts/extract_artifacts.py first.')
    env = dict(os.environ)
    env.setdefault('C2TRACE_PROJECT_ROOT', str(ROOT))
    return subprocess.call([sys.executable, str(entry), '--variant', original, *forwarded], env=env)

if __name__ == '__main__':
    raise SystemExit(main())
