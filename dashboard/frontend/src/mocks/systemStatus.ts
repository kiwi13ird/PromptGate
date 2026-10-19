// 시스템 상태 화면 시험용 가짜 데이터. 단위 시험에서만 불러온다(운영 번들에 들어가지 않는다).
// 인스턴스 ID·이름·DB 이름은 모두 꾸며낸 값이다.
import type { SystemComponent, SystemInstance, SystemStatus } from '@/src/services/systemStatusService';

export const FIXTURE_CHECKED_AT = '2026-10-12T03:00:00Z';

const component = (key: string, label: string, status: SystemComponent['status'], summary: string, details: Record<string, unknown> = {}): SystemComponent => ({
  key, label, status, summary, details, checked_at: FIXTURE_CHECKED_AT,
});

export const fixtureComponents: SystemComponent[] = [
  component('dashboard', '대시보드', 'ok', '정상 · 가동 3시간', { 시작: '2026-10-12T00:00:00Z', 'Node 버전': 'v22.13.0' }),
  component('rds', 'RDS', 'slow', 'DB 응답 420ms', { '응답 시간(ms)': 420, '최근 이벤트 저장': '2026-10-12T02:59:30Z' }),
  component('gateway', 'Gateway', 'ok', '마지막 보고 8초 전', {
    '마지막 보고': '2026-10-12T02:59:52Z', '연결된 IP': 3, '활성 클라이언트': 2, '전달 대기': 0, '설정 반영': true,
  }),
  component('relay', 'Relay', 'down', '연결 정보를 받지 못했습니다', { 연결: 0, 등록: 0 }),
  component('detection', 'Detection', 'ok', '응답 120ms', { '민감 문서': 19, 정책: 6, 'PDF 가림': false }),
  component('redis', 'Redis', 'unknown', '확인하지 못했습니다'),
  component('log_shipping', '판정 기록 전송', 'ok', '대기 없음', { '대기 용량(B)': 0 }),
  component('keyword_jobs', '키워드 추출 작업', 'ok', '대기 0 · 진행 0 · 실패 0'),
  component('gpu', 'GPU', 'unknown', 'GPU 꺼짐(필요할 때 켜집니다)', { '인스턴스 상태': 'stopped' }),
];

export const fixtureInstances: SystemInstance[] = [
  { role: 'gateway', instance_id: 'i-00000000000000001', name: 'sample-gateway', state: 'running', system_status: 'ok', instance_status: 'ok' },
  { role: 'detection', instance_id: 'i-00000000000000002', name: 'sample-detection', state: 'running', system_status: 'ok', instance_status: 'impaired' },
  { role: 'dashboard', instance_id: 'i-00000000000000003', name: null, state: 'pending', system_status: 'initializing', instance_status: 'insufficient-data' },
  { role: 'gpu', instance_id: 'i-00000000000000004', name: 'sample-gpu', state: 'stopped', system_status: 'not-applicable', instance_status: 'not-applicable' },
];

export function systemStatusFixture(overrides: Partial<SystemStatus> = {}): SystemStatus {
  return {
    checked_at: FIXTURE_CHECKED_AT,
    components: fixtureComponents,
    instances: { ok: true, error: null, status_checks: 'ok', items: fixtureInstances },
    rds_instance: { ok: true, error: null, identifier: 'sample-db', status: 'available', engine: 'postgres' },
    ...overrides,
  };
}

/** 서버가 보내는 JSON 그대로의 모양(서비스 시험용) */
export function systemStatusWire() {
  return JSON.parse(JSON.stringify(systemStatusFixture())) as Record<string, unknown>;
}
