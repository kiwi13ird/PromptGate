"""기밀문서 저장소 - RDS `documents` 등록·조회(registry)와 Redis 색인 인덱서(indexer).

설계: docs/pipelines/confidential-document-store-design.md §9, §10(2026-09-15 확정: 관리 API는 대시보드 인스턴스에서 나중에,
지금은 Detection EC2의 인덱서 + 등록 명령).
"""
