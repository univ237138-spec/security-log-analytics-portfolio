# Snowflake SQL 예시

[프로젝트 소개](../../README.md) · [처리 기준](../../docs/02_데이터품질.md)

| 로그 | 파싱 | 정규화 |
|---|---|---|
| sshd | [01](01_sshd_parse.sql) | [11](11_sshd_normalize.sql) |
| nginx | [02](02_nginx_parse.sql) | [12](12_nginx_normalize.sql) |
| sysmon | [03](03_sysmon_parse.sql) | [13](13_sysmon_normalize.sql) |
| audit | [04](04_audit_parse.sql) | [14](14_audit_normalize.sql) |

기업 제공 `security_logs.raw` 스키마를 가정한 SQL 구현 예시다. 공개 데모는 Python 파이프라인으로 로컬 재현하며 Snowflake 접속 정보는 포함하지 않는다.

실제 환경에서는 읽기 권한이 있는 입력 테이블을 준비하고 스키마 이름을 조정해야 한다. 정규화 출력은 공통 이벤트의 의미를 맞추는 것이 목적이다.

파싱·정규화 결과 비교 코드는 [파싱 비교](../../scripts/98_compare_snowflake_export.py), [정규화 비교](../../scripts/98_compare_snowflake_normalized.py)에 있다. 이번 공개 버전의 검증은 로컬 Python 분석을 대상으로 했으며 Snowflake SQL을 다시 실행한 결과는 아니다.
