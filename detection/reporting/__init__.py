"""기간 보고서 생성 - 대시보드 이벤트·판정 기록(RDS)을 집계해 HTML 보고서를 만든다.

설계: docs/design/llm-report-2026-10-12.md (v2, 집계 기준은 v1 llm-report-2026-10-12-v1.md)

원칙: **숫자·사건 묶기·순위 후보·링크는 코드가 만들고 LLM은 고르기·순서·서술·분류만 한다.**
LLM 문장은 번호 붙은 사실을 인용하고 숫자는 자리표시로만 쓴다. 검사기(verify)가 어긴 문장을 버리고, 빈 섹션은 집계 문장.
원문(prompt 열)은 읽지 않는다. 가린 글(masked_text)은 내용 경향을 켰을 때만 읽어 사설 GPU에서 고정 범주로 분류한다.

모듈: aggregate(집계) → incidents(사건·사용자) → facts(사실·렌더러) → content(내용 경향) → llm·compose(작업·합치기)
      → verify·wording(검사·금지 목록) → render·charts·template.html(HTML, 그래프는 정적 SVG).
      frame(보고서 틀 v3 - 한 장 요약 상태·깔때기·관측 범위·차단 뒤 재요청, 코드만). jobs(생성 작업), gpu(켜기·끄기),
      local_api(로컬 API 읽기), provenance(문장 출처 기록 - HTML에는 안 쓰고 생성 기록 JSON에만).

실행(Detection EC2): python -m reporting --from 2026-10-01 --to 2026-10-13 --out /opt/detection/reports/x.html
"""
