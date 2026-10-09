"""Validate source counts, keys, past-only histories, scores, comparisons and demo identifiers."""
import hashlib
import ipaddress
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from common import ROOT, read_rows

checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

raw_counts = {}
for name, n in {'sshd':1364, 'nginx':2223, 'sysmon':5082, 'audit':456}.items():
    raw = read_rows(ROOT / f'data/01_raw/{name}_raw.csv')
    parsed = read_rows(ROOT / f'data/02_parsed/{name}_parsed.csv')
    normal = read_rows(ROOT / f'data/03_normalized/{name}_normalized_event_action.csv')
    check(f'{name}: raw/parsed/normalized row conservation', len(raw) == len(parsed) == len(normal) == n)
    raw_counts[name] = n
timeline = read_rows(ROOT / 'data/07_sessions/timeline_sessions.csv')
sessions = read_rows(ROOT / 'data/07_sessions/sessions.csv')
baseline = read_rows(ROOT / 'data/08_baseline/session_baseline.csv')
signals = read_rows(ROOT / 'data/09_detections/detections.csv')
risk = read_rows(ROOT / 'data/10_risk/session_risk.csv')
events = read_rows(ROOT / 'data/10_risk/risk_events.csv')
comparison = read_rows(ROOT / 'data/13_baseline_variants/summary.csv')
check('9,125 unique source event keys', len(timeline) == 9125 and len({(r['log_source'],r['source_row']) for r in timeline}) == 9125)
ids = {r['work_session_id'] for r in sessions}
check('146 unique sessions and valid event session references', len(ids) == len(sessions) == 146 and all(not r['work_session_id'] or r['work_session_id'] in ids for r in timeline))
check('baseline and risk tables cover the same sessions', {r['work_session_id'] for r in baseline} == {r['work_session_id'] for r in risk} == ids)
check('76 signals with unique IDs and valid session references', len(signals) == 76 and len({r['detection_id'] for r in signals}) == 76 and all(not r['work_session_id'] or r['work_session_id'] in ids for r in signals))

# Reconstruct history selection independently and compare its sample size.
accounts = read_rows(ROOT / 'data/05_enriched/account_inventory.csv')
home = {r['person_candidate']:r['home_host'] for r in accounts if r['account_system']=='linux' and r['account_type']=='human'}
for b in baseline:
    past = [s for s in sessions if datetime.fromisoformat(s['end_utc']) < datetime.fromisoformat(b['start_utc'])]
    own = [s for s in past if s['person_candidate'] == b['person_candidate']]
    group = {p for p,h in home.items() if h==home.get(b['person_candidate'],'')}
    peer = [s for s in past if s['person_candidate'] in group]
    expected = ('person', own) if len(own)>=5 else ('peer',peer) if len(peer)>=5 else ('global',past) if len(past)>=5 else ('none',[])
    check(f"{b['work_session_id']}: completed-past history level and size", (b['baseline_level'],int(b['baseline_n'])) == (expected[0],len(expected[1])))

alert_ids = sorted(r['work_session_id'] for r in risk if r['alert']=='true')
check('four reference alert sessions retained', alert_ids == ['S122','S132','S137','S142'])
for r in risk:
    by_type = {}
    for e in events:
        if e['work_session_id'] == r['work_session_id']:
            by_type[e['detection_type']] = max(by_type.get(e['detection_type'],0),float(e['signal_score']))
    points = sum(by_type.values())
    check(f"{r['work_session_id']}: risk equals sum of per-type maximum evidence scores", abs(points-float(r['risk_score'])) < 0.05)
check('three baseline variants and exploratory counts reproduced',
      [(r['variant'],int(r['normal_sessions_flagged']),int(r['alert_count'])) for r in comparison] == [('V0',7,4),('V1',4,4),('V2',5,4)])

doc_networks = [ipaddress.ip_network(x) for x in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')]
for f in (ROOT / 'data/demo').glob('*.csv'):
    text = f.read_text(encoding='utf-8-sig')
    emails = re.findall(r'[\w.+-]+@[\w.-]+', text)
    check(f'{f.name}: email aliases only', all(e.endswith('@demo.example') for e in emails))
    for addr in set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text)):
        ip = ipaddress.ip_address(addr)
        check(f'{f.name}: demo IP {addr}', str(ip).startswith(('10.77.1.','10.88.10.')) or any(ip in n for n in doc_networks))
    tenants = re.findall(r'"tenancy"\s*:\s*"([^"]+)"',text)
    check(f'{f.name}: tenant alias only', all(x=='demo-tenant-0001' for x in tenants))

metrics = {'input':'public pseudonymized demo; identifier changes preserve sequence and relationships',
           'raw_rows':raw_counts, 'events':len(timeline), 'sessions':len(sessions), 'signals':len(signals),
           'alert_sessions':len(alert_ids), 'alert_ids':alert_ids,
           'baseline_variants':[{k:r[k] for k in ('variant','label','behavior_signals','normal_sessions_flagged','alert_count')} for r in comparison],
           'interpretation':'Exploratory investigation priority, not independently measured detection accuracy.'}
(ROOT / 'results/metrics.json').write_text(json.dumps(metrics,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
report = {'status':'passed','checks':len(checks),'categories':['row conservation','key integrity','past-only session history','score reconciliation','baseline variants','demo identifiers'],
          'inputs_sha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted((ROOT/'data/demo').glob('*.csv'))}}
(ROOT / 'results/validation_summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for source, dest in [('data/13_baseline_variants/summary.csv','baseline_comparison.csv'),
                     ('data/12_stats/summary.csv','statistical_tests.csv')]:
    shutil.copyfile(ROOT/source,ROOT/'results'/dest)
print(f'PASS: {len(checks)} checks. Metrics and validation report saved.')
