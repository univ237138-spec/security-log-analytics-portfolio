# 분석 코드

[프로젝트 소개](../README.md) · [실행](../docs/08_실행가이드.md)

| 단계 | 코드 |
|---|---|
| 전체 실행 | [run_pipeline.py](run_pipeline.py) |
| 파싱 | [audit](01_parse_audit.py), [nginx](01_parse_nginx.py), [sshd](01_parse_sshd.py), [sysmon](01_parse_sysmon.py) |
| 정규화 | [audit](02_normalize_audit.py), [nginx](02_normalize_nginx.py), [sshd](02_normalize_sshd.py), [sysmon](02_normalize_sysmon.py) |
| 행위 분류·통합 | [03](03_apply_event_action.py), [04](04_integrate.py) |
| 보강·연결·세션 | [05](05_enrich.py), [06](06_link_classify.py), [07](07_sessionize.py) |
| 기준선·탐지·점수 | [08](08_baseline.py), [09](09_detect.py), [10](10_risk.py) |
| 조사 | [11](11_investigate.py) |
| 통계·기준선 비교 | [12](12_stat_tests.py), [13](13_compare_baselines.py) |
| 자동 검증 | [전체](verify_portfolio.py), [화면](99_verify_dashboard_v2.py), [문서](verify_docs.py) |
| 차트·캡처 | [차트](make_figures.py), [브라우저 캡처](capture_screenshots.py) |

공통 경로·CSV 입출력은 [common.py](common.py)에 정의한다. 코드의 입력·생성 결과는 각 파일의 상단 설명과 실행 가이드에서 확인한다. 분석 출력과 대시보드 읽기 기능을 분리했다.
