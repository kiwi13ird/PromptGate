# AWS 8081 / Detection 동기화 기준

## 단일 기준 디렉터리

`aws_sync/current/`가 2026-10-01 배포 뒤 AWS 소스와 일치하는 로컬 기준본이다.

- Gateway 8081: `aws_sync/current/gateway/`
- Detection 8000: `aws_sync/current/detection/`
- 파일 체크섬: `aws_sync/current/manifests/source-sha256.txt`
- `snapshots/`는 과거 읽기 전용 사본이며 현재 기준본이 아니다.

새 날짜 폴더를 계속 만들지 않는다. AWS에서 소스를 다시 받을 때는 임시 디렉터리에서
체크섬과 비밀정보 제외 여부를 확인한 뒤 `aws_sync/current/`만 갱신한다.
환경 파일, 인증서, 로그, DB, 업로드/출력 파일과 자격증명 문자열이 든 운영 점검 스크립트는
동기화 대상에서 제외한다.

## 배포 범위

- 변경: `llm-gateway-8081.service`, `detection.service`
- 미변경: 포트 8080 프로덕션 Gateway, Security Group, 인증서, 환경 파일, WindowHash 코드
- Gateway 백업: `/home/ubuntu/llm-gateway/backups/signature-v2-20261001T104406Z`
- Detection 백업: `/opt/detection/backups/signature-v2-20261001T104205Z`

Detection의 기존 `action` 열과 CHECK 제약은 유지한다. 새 5종 정책은 `action_v2`에 저장하고,
기존 열에는 `ALLOW/MASK/BLOCK` 호환값을 함께 기록한다.

## 관리자 정책 값

```text
allow
allow_notify
block_notify
mask_partial
mask_full
```

기존 `ALLOW`, `MASK`, `BLOCK` 행은 각각 `allow`, `mask_full`, `block_notify`로 읽힌다.
Credential(`GITHUB_TOKEN`, `GENERIC_API_KEY`, `PASSWORD`)의 `mask_partial` 요청은
항상 `mask_full`로 강화한다.

## 검증 명령

```bash
E2E_GATEWAY_DIR=aws_sync/current/gateway \
E2E_DETECTION_DIR=aws_sync/current/detection \
../.venv/bin/python scripts/e2e_prompt_roundtrip.py

E2E_GATEWAY_DIR=aws_sync/current/gateway \
E2E_DETECTION_DIR=aws_sync/current/detection \
../.venv/bin/python scripts/e2e_file_roundtrip.py
```

검증 범위는 prompt, OpenAI multipart DOCX/XLSX, ChatGPT raw PUT DOCX, 미지원 파일
fail-closed이다. PDF secure redaction은 아직 구현하지 않았으므로 마스킹이 필요한 PDF는 차단한다.

## 롤백

Gateway와 Detection 모두 배포 직전 백업을 먼저 만들었다. 롤백 시 8081과 Detection만
정지하고 위 백업의 소스(Detection은 정책 DB 포함)를 원위치에 복원한 뒤 해당 서비스만
재시작한다. 8080은 롤백 작업에도 포함하지 않는다.

## review 파일

지원 파일이 재구성되면 응답 헤더에 아래 값이 추가된다.

```text
X-LLMSGW-Review-ID
X-LLMSGW-Review-URL: http://llm-gateway.local/__llmsgw/review/{id}
```

URL은 Gateway 프록시를 사용하는 브라우저에서 열 수 있고 DOCX/XLSX 검토본을 내려받는다.
검토본은 무작위 ID로 조회되며 `Cache-Control: no-store`로 응답한다. 별도 보존기간 삭제 작업은
아직 구현하지 않았으므로 운영 적용 전 보존기간을 정해야 한다.
