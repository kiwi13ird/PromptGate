# Future Gateway-specific adapters

현재 `POST /api/events/ingest`는 [Security Event Contract v1](../../docs/security-event-contract-v1.md)의 canonical payload만 받습니다. 실제 Gateway/Detection JSON을 아직 받지 않았으므로 이 디렉터리에는 추측 mapper를 구현하지 않습니다.

향후 흐름은 다음으로 고정합니다.

```text
REAL GATEWAY PAYLOAD
        ↓
Gateway-specific Mapper (이 디렉터리)
        ↓
Canonical Security Event v1
        ↓
validateCanonicalEvent()
        ↓
Event Store
```

Mapper를 추가하기 전에 실제 payload fixture, field ownership, enum, null/omission 규칙, versioning을 [Gateway Integration Checklist](../../docs/gateway-integration-checklist.md)에서 확정해야 합니다. 기존 canonical ingest endpoint의 의미를 Gateway별 payload에 맞춰 임의 변경하지 않습니다.
