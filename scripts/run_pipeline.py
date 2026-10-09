"""Rebuild every analysis stage from the public demo inputs and verify the results."""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEPS = [
    'run_all.py', '03_apply_event_action.py', '99_verify_event_action.py',
    '04_integrate.py', '99_verify_integrated.py', '05_enrich.py', '06_link_classify.py',
    '07_sessionize.py', '08_baseline.py', '09_detect.py', '10_risk.py',
    '11_investigate.py', '12_stat_tests.py', '13_compare_baselines.py',
    'verify_portfolio.py', 'make_figures.py',
]

def main():
    for dirname in ('01_raw','02_parsed','03_normalized','04_integrated','05_enriched',
                    '06_classified','07_sessions','08_baseline','09_detections','10_risk',
                    '11_investigation','12_stats','13_baseline_variants'):
        (ROOT / 'data' / dirname).mkdir(parents=True, exist_ok=True)
    (ROOT / 'results').mkdir(exist_ok=True)
    (ROOT / 'assets').mkdir(exist_ok=True)
    for source in sorted((ROOT / 'data/demo').glob('*_raw.csv')):
        shutil.copyfile(source, ROOT / 'data/01_raw' / source.name)
    if len(list((ROOT / 'data/demo').glob('*_raw.csv'))) != 4:
        raise SystemExit('Expected four public demo CSV inputs.')
    for step in STEPS:
        print(f'\n>>> {step}', flush=True)
        subprocess.run([sys.executable, str(ROOT / 'scripts' / step)], cwd=ROOT, check=True)
    print('\nComplete: results/metrics.json, verified figures, and dashboard input CSVs.')

if __name__ == '__main__':
    main()
