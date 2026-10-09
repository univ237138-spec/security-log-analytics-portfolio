"""대체 기준선 방식 3가지를 같은 기준으로 비교한다 (파이프라인은 바꾸지 않는다).
  V0 현재          : 본인 과거 ≥ 5 → 본인, 아니면 동료(peer). 모든 항목 같은 기준선
  V1 peer 제거     : 본인 과거 ≥ 5 → 본인, 아니면 전체(global)
  V2 시간만 global : V0과 같되, 시작 시각(B01)만 모든 세션을 전체 과거와 비교

같은 기준
- 행위 탐지를 거는 세션: 현재 비교 대상(person·peer) 126개로 고정
- 임계값: 방식마다 같은 "드문 정도 5%" 규칙으로 다시 계산 (B01 거리, B08 항목)
- 점수·경보: 6단계 고정값 (룰 60/30/10, 행위 20, 자산·신뢰도 계수, 경보 100점 또는 전술 3개)
- 룰 탐지(R01~R16)와 B09(시스템 패턴)는 기준선과 무관해 세 방식 모두 그대로 쓴다

입력: data/07_sessions/*, data/08_baseline/session_baseline.csv, data/09_detections/detections.csv, data/10_risk/*
출력: data/13_baseline_variants/
설명: docs/03_세션과기준선.md
"""
import re
from collections import Counter, defaultdict
from datetime import datetime

from common import BASELINE, DETECTIONS, RISK, ROOT, SESSIONS, read_rows, write_rows

OUT = ROOT / "data" / "13_baseline_variants"
N_MIN, RARE = 5, 0.05
VOLUME = ["duration_min", "process_count", "nginx_count", "api_count", "non_get_count"]
SCENARIO = {"S122": "A", "S132": "B", "S137": "C", "S142": "D"}  # 07_분석기획 기록으로 찾은 세션 (참고용)

sessions = read_rows(SESSIONS / "sessions.csv")
timeline = read_rows(SESSIONS / "timeline_sessions.csv")
sb_cur = {r["work_session_id"]: r for r in read_rows(BASELINE / "session_baseline.csv")}
dets = read_rows(DETECTIONS / "detections.csv")
revents = read_rows(RISK / "risk_events.csv")
srisk = {r["work_session_id"]: r for r in read_rows(RISK / "session_risk.csv")}
home = {a["person_candidate"]: a["home_host"] for a in read_rows(ROOT / "data" / "05_enriched" / "account_inventory.csv")
        if a["account_system"] == "linux" and a["account_type"] == "human"}
peers = defaultdict(set)
for p, h in home.items():
    peers[h].add(p)

norm = lambda t: re.sub(r"\d+", "N", t)
split = lambda v: {x.split(":")[0] for x in v.split("|") if x}
cmds = defaultdict(set)
for r in timeline:
    if r["work_session_id"] and r["event_action"] == "process_create":
        cmds[r["work_session_id"]].add(norm(r["CommandLine"]))
S = [{"id": s["work_session_id"], "person": s["person_candidate"], "start": datetime.fromisoformat(s["start_utc"]),
      "end": datetime.fromisoformat(s["end_utc"]), "hour": int(s["start_hour_kst"]), "ip": s["client_ip"],
      "type": s["session_type"], "logins": split(s["web_login_types"]), "failed": int(s["failed_before_login"]),
      "cmds": cmds[s["work_session_id"]], "sensitive": split(s["sensitive_actions"]),
      "vol": {c: float(s[c]) for c in VOLUME}} for s in sessions]
COMPARABLE = {sid for sid, r in sb_cur.items() if r["baseline_level"] in ("person", "peer")}  # 126개 고정


def base_sets(x, variant):
    """(시간 비교용 과거, 나머지 항목 비교용 과거, 전체 과거)"""
    past = [h for h in S if h["end"] < x["start"]]
    own = [h for h in past if h["person"] == x["person"]]
    peer = [h for h in past if h["person"] in peers.get(home.get(x["person"], ""), set())]
    main = own if len(own) >= N_MIN else (past if variant == "V1" else peer)
    hour = past if variant == "V2" else main
    return hour, main, past


def compare(variant):
    rows = {}
    for x in S:
        if x["id"] not in COMPARABLE:
            continue
        H_hour, H, past = base_sets(x, variant)
        hours = [h["hour"] for h in H_hour]
        seen = lambda k: set().union(*(h[k] for h in H))
        rows[x["id"]] = {
            "hour_distance": max(min(hours) - x["hour"], x["hour"] - max(hours), 0),
            "hour_range": f"{min(hours)}~{max(hours)}", "n_main": len(H), "n_hour": len(H_hour),
            "ip_new": x["ip"] not in {h["ip"] for h in H},
            "type_ratio": sum(h["type"] == x["type"] for h in H) / len(H),
            "login_new": x["logins"] - seen("logins"), "sens_new": x["sensitive"] - seen("sensitive"),
            "cmd_global_new": x["cmds"] - set().union(*(h["cmds"] for h in past)),
            "fail_first": x["failed"] > 0 and not any(h["failed"] > 0 for h in H),
            "above": {c: x["vol"][c] > max(h["vol"][c] for h in H) for c in VOLUME},
        }
    n = len(rows)
    dist = [r["hour_distance"] for r in rows.values()]
    d_thr = min(d for d in range(1, max(dist) + 2) if sum(v >= d for v in dist) / n <= RARE)
    share = {c: sum(r["above"][c] for r in rows.values()) / n for c in VOLUME}
    items = [c for c in VOLUME if share[c] <= RARE]
    beh = defaultdict(set)
    for sid, r in rows.items():
        if r["hour_distance"] >= d_thr: beh[sid].add("B01")
        if r["ip_new"]: beh[sid].add("B02")
        if r["type_ratio"] == 0: beh[sid].add("B03")
        if r["login_new"]: beh[sid].add("B04")
        if r["sens_new"]: beh[sid].add("B05")
        if r["cmd_global_new"]: beh[sid].add("B06")
        if r["fail_first"]: beh[sid].add("B07")
        if any(r["above"][c] for c in items): beh[sid].add("B08")
    return rows, beh, d_thr, items, share


# 룰·B09 신호는 기준선과 무관: 6단계 risk_events에서 세션·종류별 최고 점수를 그대로 가져온다
fixed = defaultdict(dict)  # 세션 → {종류: (점수, 전술)}
for e in revents:
    if e["method"] == "rule" or e["detection_type"] == "B09":
        k, sc = e["detection_type"], float(e["signal_score"])
        if sc > fixed[e["work_session_id"]].get(k, (0, ""))[0]:
            fixed[e["work_session_id"]][k] = (sc, e["tactics"])


def score(beh):
    out = {}
    for s in S:
        parts = dict(fixed.get(s["id"], {}))
        for b in beh.get(s["id"], ()):
            parts[b] = (20.0, "")  # 행위 탐지 기본 20 × 계수 1.0 (세션 직접 소속, 서버 없음)
        sc = sum(v for v, _ in parts.values())
        tac = {t for _, ts in parts.values() for t in ts.split("|") if t}
        out[s["id"]] = (round(sc, 1), len(tac), sc >= 100 or len(tac) >= 3)
    return out


results, summary, per_session = {}, [], []
for v, label in [("V0", "현재 (peer)"), ("V1", "peer 제거 (global)"), ("V2", "시간만 global")]:
    rows, beh, d_thr, items, share = compare(v)
    sc = score(beh)
    results[v] = (rows, beh, sc)
    normal = [sid for sid in COMPARABLE if sid not in SCENARIO]
    fp = sorted(sid for sid in normal if beh.get(sid))
    cnt = Counter(b for sid in COMPARABLE for b in beh.get(sid, ()))
    alerts = sorted(sid for sid, (_, _, a) in sc.items() if a)
    ranked = sorted(sc, key=lambda sid: -sc[sid][0])
    max_normal = max(sc[sid][0] for sid in sc if sid not in SCENARIO)
    summary.append({
        "variant": v, "label": label, "B01_threshold_h": d_thr, "B08_items": "|".join(items),
        "behavior_signals": sum(cnt.values()), "by_type": " ".join(f"{k}:{cnt[k]}" for k in sorted(cnt)),
        "normal_sessions_flagged": len(fp), "normal_flagged_ids": "|".join(fp),
        "scenario_behavior": " ".join(f"{sid}:{'/'.join(sorted(beh.get(sid, ())))}" for sid in sorted(SCENARIO)),
        "alerts": "|".join(alerts), "alert_count": len(alerts),
        "scenario_scores": " ".join(f"{sid}:{sc[sid][0]:g}" for sid in sorted(SCENARIO)),
        "max_normal_score": max_normal, "top4": "|".join(sorted(ranked[:4])),
        "peer_sessions_flagged": len([sid for sid in fp if sb_cur[sid]["baseline_level"] == "peer"]),
    })
    for sid in sorted(COMPARABLE):
        r = rows[sid]
        per_session.append({"variant": v, "work_session_id": sid, "level_current": sb_cur[sid]["baseline_level"],
                            "hour_range": r["hour_range"], "hour_distance": r["hour_distance"],
                            "behavior": "|".join(sorted(beh.get(sid, ()))), "score": sc[sid][0],
                            "alert": str(sc[sid][2]).lower()})

# ---------------------------------------------------------------- 재현 확인: V0 = 기존 결과
cur_beh = defaultdict(set)
for d in dets:
    if d["method"] == "behavior" and d["detection_type"] != "B09" and d["work_session_id"]:
        cur_beh[d["work_session_id"]].add(d["detection_type"])
_, beh0, sc0 = results["V0"]
assert {k: v for k, v in beh0.items() if v} == dict(cur_beh), "V0 행위 탐지가 기존 결과와 다르다"
assert all(abs(sc0[sid][0] - float(srisk[sid]["risk_score"])) < 0.05 for sid in srisk), "V0 점수가 기존과 다르다"
assert {sid for sid, x in sc0.items() if x[2]} == {sid for sid, r in srisk.items() if r["alert"] == "true"}
print("재현 확인 통과: V0 = 기존 5·6단계 결과\n")

OUT.mkdir(parents=True, exist_ok=True)
write_rows(OUT / "summary.csv", list(summary[0].keys()), summary)
write_rows(OUT / "per_session.csv", list(per_session[0].keys()), per_session)

for s in summary:
    print(f"[{s['variant']} {s['label']}]")
    print(f"  임계값: B01 ≥ {s['B01_threshold_h']}시간, B08 항목 {s['B08_items']}")
    print(f"  행위 신호 {s['behavior_signals']}건 ({s['by_type']})")
    print(f"  정상 세션 중 행위 탐지 걸림 {s['normal_sessions_flagged']}개 (그중 현재 peer 세션 {s['peer_sessions_flagged']}): {s['normal_flagged_ids']}")
    print(f"  시나리오 세션 행위 탐지: {s['scenario_behavior']}")
    print(f"  경보 {s['alert_count']}개 {s['alerts']} | 시나리오 점수 {s['scenario_scores']} | 정상 최고 {s['max_normal_score']:g}")
diff = defaultdict(dict)
for p in per_session:
    diff[p["work_session_id"]][p["variant"]] = p
print("\n방식 간 행위 탐지가 다른 세션:")
for sid, d in sorted(diff.items()):
    if len({d[v]["behavior"] for v in d}) > 1:
        print(f"  {sid} ({d['V0']['level_current']}) " + " | ".join(
            f"{v}: {d[v]['behavior'] or '-'} (시간범위 {d[v]['hour_range']}, 거리 {d[v]['hour_distance']})" for v in ("V0", "V1", "V2")))
