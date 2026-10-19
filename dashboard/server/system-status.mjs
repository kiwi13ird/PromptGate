// 시스템 상태 화면용 점검 결과 조립 (2026-10-12).
// 구성 요소마다 status(ok·slow·down·unknown)와 한 줄 요약, 평평한 details(문자열·숫자만)를 만든다.
// 비밀·접속 문자열·사설 호스트 이름은 응답에 싣지 않는다: Detection이 준 글자는 scrubText를 거치고, 모르는 칸은 버린다.

export const SYSTEM_STATUS_CACHE_MS = 5_000;
export const DETECTION_STATUS_TIMEOUT_MS = 2_500;
// GPU 조회는 기존 /api/system/gpu와 같은 3초(Detection이 꺼진 GPU를 2초까지 기다린다)
const GPU_STATUS_TIMEOUT_MS = 3_000;
export const DB_TIMEOUT_MS = 2_000;
const DB_SLOW_MS = 300;
const DETECTION_SLOW_MS = 1_000;
// Gateway 지표가 '지금 값'인 기준(2026-10-15 감사 15번: 시스템 상태 30초 · 트래픽 120초 · 연결 IP 30초로 달랐다 → 하나로).
// Gateway는 10초마다 보낸다. app.mjs(트래픽·보안 현황·연결 IP·설정 반영)도 이 값을 쓴다
export const GATEWAY_METRICS_FRESH_MS = 30_000;
const GATEWAY_FRESH_MS = GATEWAY_METRICS_FRESH_MS;
const SHIPPING_FAILURES_DOWN = 3;
const SHIPPING_STALE_MS = 10 * 60_000;
const PROCESS_STARTED_AT_MS = Date.now() - process.uptime() * 1000;

const INSTANCE_ROLES = ['gateway', 'detection', 'dashboard', 'gpu'];
const INSTANCES_ERRORS = [null, 'permission_missing', 'unavailable'];
const RDS_ERRORS = [null, 'permission_missing', 'unavailable', 'not_configured'];
const SETTINGS_STATE_LABELS = {
  APPLIED: '반영됨',
  PENDING: '반영 대기',
  REJECTED: '거부됨',
  NOT_REPORTING: '보고 없음',
  REPORT_INVALID: '보고 형식 오류',
  LEGACY_GATEWAY: '지원 안 함(옛 Gateway)',
};

const iso = (ms) => new Date(ms).toISOString();
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const finite = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : null);
const wholeCount = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : null);

function isoOrNull(value) {
  if (typeof value !== 'string' || value.length > 40) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : iso(parsed);
}

// Detection이 준 글자를 화면에 내보내기 전에 접속 주소·사설 IP·호스트·비밀 값 모양을 지운다(최선의 방어선)
export function scrubText(value, max = 120) {
  if (typeof value !== 'string') return null;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S*/gi, '[주소]')
    .replace(/\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+/gi, '$1=[숨김]')
    .replace(/\b[\w-]+(?:\.[\w-]+)*\.(?:amazonaws\.com|internal|local|lan)\b/gi, '[주소]')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g, '[주소]')
    .trim()
    .slice(0, max);
  return cleaned || null;
}

function duration(seconds) {
  const total = Math.max(0, Math.floor(seconds));
  if (total < 60) return `${total}초`;
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return `${minutes}분`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return minutes % 60 ? `${hours}시간 ${minutes % 60}분` : `${hours}시간`;
  const days = Math.floor(hours / 24);
  return hours % 24 ? `${days}일 ${hours % 24}시간` : `${days}일`;
}

function withTimeout(promise, ms) {
  let timer;
  const limit = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'CHECK_TIMEOUT' })), ms);
  });
  return Promise.race([promise, limit]).finally(() => clearTimeout(timer));
}

function component(key, label, status, summary, details, checkedAt) {
  return {
    key,
    label,
    status,
    summary,
    details: Object.fromEntries(Object.entries(details).filter(([, value]) => value !== null && value !== undefined)),
    checked_at: checkedAt,
  };
}

export const instancesUnavailable = () => ({ ok: false, error: 'unavailable', items: [] });
export const rdsUnavailable = () => ({ ok: false, error: 'unavailable', identifier: null, status: null, engine: null });

// Detection이 준 EC2 목록: 아는 칸만 옮기고 역할이 네 가지가 아닌 항목은 버린다
function instancesView(raw) {
  if (!isObject(raw) || typeof raw.ok !== 'boolean') return instancesUnavailable();
  const items = (Array.isArray(raw.items) ? raw.items : [])
    .slice(0, 20)
    .filter((item) => isObject(item) && INSTANCE_ROLES.includes(item.role))
    .map((item) => ({
      role: item.role,
      instance_id: scrubText(item.instance_id, 40),
      name: scrubText(item.name, 80),
      state: scrubText(item.state, 30),
      system_status: scrubText(item.system_status, 30),
      instance_status: scrubText(item.instance_status, 30),
    }));
  return {
    ok: raw.ok,
    error: INSTANCES_ERRORS.includes(raw.error) ? raw.error : 'unavailable',
    ...(raw.status_checks === 'ok' || raw.status_checks === 'permission_missing' ? { status_checks: raw.status_checks } : {}),
    items,
  };
}

// RDS 식별자는 DNS 이름이 아니라 첫 칸(영문·숫자·하이픈)만 받는다
function rdsView(raw) {
  if (!isObject(raw) || typeof raw.ok !== 'boolean') return rdsUnavailable();
  return {
    ok: raw.ok,
    error: RDS_ERRORS.includes(raw.error) ? raw.error : 'unavailable',
    identifier: typeof raw.identifier === 'string' && /^[A-Za-z][A-Za-z0-9-]{0,62}$/.test(raw.identifier) ? raw.identifier : null,
    status: scrubText(raw.status, 40),
    engine: scrubText(raw.engine, 40),
  };
}

function dashboardComponent(nowMs) {
  const uptime = process.uptime();
  return component('dashboard', '대시보드', 'ok', `가동 ${duration(uptime)}`, {
    '시작 시각': iso(PROCESS_STARTED_AT_MS),
    '가동 시간(초)': Math.floor(uptime),
    'Node 버전': process.version,
  }, iso(nowMs));
}

async function databaseComponent(store, now) {
  const label = '데이터베이스';
  if (typeof store?.ping !== 'function') {
    return component('rds', label, 'unknown', '로컬 저장소', { 저장소: '로컬 JSON 파일' }, iso(now()));
  }
  const started = performance.now();
  try {
    await withTimeout(store.ping(), DB_TIMEOUT_MS);
  } catch (error) {
    // 오류 문장에는 접속 주소가 들어 있을 수 있어 코드만 남긴다
    console.error('System status: database check failed:', error?.code ?? error?.name ?? 'error');
    const timedOut = error?.code === 'CHECK_TIMEOUT';
    return component('rds', label, 'down', timedOut ? '응답 없음(2초 초과)' : '연결 실패', { 저장소: 'PostgreSQL' }, iso(now()));
  }
  const latency = performance.now() - started;
  const status = latency < DB_SLOW_MS ? 'ok' : latency < DB_TIMEOUT_MS ? 'slow' : 'down';
  let latest = null;
  if (status !== 'down' && typeof store.latestEventStoredAt === 'function') {
    try {
      latest = isoOrNull(await withTimeout(store.latestEventStoredAt(), 1_000));
    } catch {
      latest = null;
    }
  }
  return component('rds', label, status, `응답 ${Math.round(latency)}ms`, {
    '지연 시간(ms)': Math.round(latency),
    저장소: 'PostgreSQL',
    '마지막 이벤트 저장': latest,
  }, iso(now()));
}

// liveState = app.mjs liveGatewayState() 결과(트래픽·보안 현황과 같은 판정, 2026-10-15). DEGRADED면 '느림'(주의)으로 같은 근거를 적는다
function gatewayComponent(metrics, settingsState, nowMs, liveState = null) {
  if (!metrics) return component('gateway', 'Gateway', 'down', '지표를 받은 적 없음', {}, iso(nowMs));
  const ageMs = nowMs - Date.parse(metrics.received_at);
  const summary = `마지막 보고 ${duration(ageMs / 1000)} 전`;
  if (!(ageMs < GATEWAY_FRESH_MS))
    return component('gateway', 'Gateway', 'down', summary, { '마지막 보고': metrics.received_at }, iso(nowMs));
  const delivery = isObject(metrics.event_delivery) ? metrics.event_delivery : null;
  const ready = delivery?.storage_ready !== false;
  const degraded = liveState?.status === 'DEGRADED';
  return component('gateway', 'Gateway', degraded ? 'slow' : 'ok', degraded ? `오류 기록 있음 · ${summary}` : summary, {
    '마지막 보고': metrics.received_at,
    // 이름을 산식에 맞춤(2026-10-15 감사 14번): 열린 연결이 있는 IP 수(트래픽 연결 IP 표 '연결 중'과 같은 수), 지금 응답을 기다리는 요청이 있는 IP 수
    '연결 중인 IP': Array.isArray(metrics.clients) ? new Set(metrics.clients.filter((client) => client.connections > 0).map((client) => client.ip)).size : null,
    '응답 대기 요청이 있는 IP': metrics.active_clients,
    '판정 근거': degraded ? liveState.reason ?? null : null,
    '이벤트 저장소': delivery && !ready ? '준비 안 됨' : null,
    '이벤트 전송 대기': delivery && ready ? delivery.pending : null,
    '이벤트 전송 막힘': delivery && ready ? delivery.blocked : null,
    '설정 반영': SETTINGS_STATE_LABELS[settingsState?.state] ?? null,
    '반영된 설정 버전': settingsState?.applied_version ?? null,
  }, iso(nowMs));
}

function relayComponent(metrics, nowMs) {
  const label = '확장 알림 중계';   // 2026-10-16 화면 점검: 내부 이름 '릴레이' 대신 하는 일(확장 프로그램 알림 중계, websocket_server.py)
  if (!metrics || !(nowMs - Date.parse(metrics.received_at) < GATEWAY_FRESH_MS))
    return component('relay', label, 'unknown', 'Gateway 지표가 없어 알 수 없음', {}, iso(nowMs));
  const relay = metrics.relay;
  if (!relay) {
    const summary = metrics.relay_rejected ? '중계 보고 형식이 맞지 않음' : '중계 상태를 보고하지 않음';
    return component('relay', label, 'unknown', summary, {}, iso(nowMs));
  }
  const details = { '연결 수': relay.connected, '등록된 클라이언트': relay.registered };
  if (!relay.ok) return component('relay', label, 'down', '중계에 연결하지 못함', details, iso(nowMs));
  return component('relay', label, 'ok', `연결 ${relay.connected} · 등록 ${relay.registered}`, details, iso(nowMs));
}

async function callDetection(fetchDetection, pathname, timeoutMs) {
  const started = performance.now();
  try {
    const payload = await fetchDetection(pathname, { timeoutMs });
    return { ok: true, payload, elapsed: performance.now() - started };
  } catch (error) {
    return { ok: false, error };
  }
}

// 실패 종류: 주소 미설정 → 알 수 없음, 길이 없음(404 = 옛 Detection) → 알 수 없음, 그 밖 → 끊김
function detectionFailure(error) {
  if (error?.code === 'POLICY_INTEGRATION_UNAVAILABLE') return ['unknown', '탐지 서버 주소가 설정되지 않음'];
  if (error?.code === 'POLICY_UPSTREAM_UNAVAILABLE') return ['down', '응답 없음(연결 실패 또는 2.5초 초과)'];
  if (error?.statusCode === 404) return ['unknown', '상태 조회를 지원하지 않음(탐지 서버 업데이트 필요)'];
  if (Number.isInteger(error?.statusCode)) return ['down', `오류 응답(HTTP ${error.statusCode})`];
  return ['down', '응답 형식 오류'];
}

// 응답 시간(2026-10-15 감사 16번): /admin/system-status 왕복에는 Detection이 30초마다 AWS(EC2·RDS) 조회를 기다리는 시간(최대 2초)이
// 섞여 탐지 서버가 정상이어도 '느림'이 됐다 → 같이 부른 /health 왕복으로 잰다. /health를 못 받으면 상태 조회 왕복(AWS 조회 포함일 수 있음)
function detectionComponent(result, nowMs, health = null) {
  const label = '탐지 서버';
  if (!result.ok) {
    const [status, summary] = detectionFailure(result.error);
    return component('detection', label, status, summary, {}, iso(nowMs));
  }
  const section = result.payload.detection;
  const healthOk = Boolean(health?.ok);
  const elapsed = healthOk ? health.elapsed : result.elapsed;
  const ms = Math.round(elapsed);
  const status = elapsed < DETECTION_SLOW_MS && (!isObject(section) || section.status === 'ok') ? 'ok' : 'slow';
  const signatures = isObject(section?.signatures) ? section.signatures : {};
  const uptime = finite(section?.uptime_s);
  return component('detection', label, status, uptime === null ? `응답 ${ms}ms` : `응답 ${ms}ms · 가동 ${duration(uptime)}`, {
    '응답 시간(ms)': ms,
    '응답 시간 기준': healthOk ? '상태 확인(/health) 왕복' : '상태 조회 왕복(AWS 조회 포함일 수 있음)',
    '시작 시각': isoOrNull(section?.started_at),
    '가동 시간(초)': uptime === null ? null : Math.floor(uptime),
    '시그니처(내장)': wholeCount(signatures.builtin),
    '시그니처(DB)': wholeCount(signatures.database),
    '시그니처(키워드)': wholeCount(signatures.keywords),
    '등록 문서': wholeCount(section?.documents),
    정책: wholeCount(section?.policies),
    'PDF 가림': typeof section?.redact_pdf === 'boolean' ? (section.redact_pdf ? '사용' : '사용 안 함') : null,
  }, isoOrNull(result.payload.checked_at) ?? iso(nowMs));
}

// Detection이 보고한 칸을 그대로 옮기는 구성 요소(Redis·판정 기록 전송·키워드 작업)의 공통 틀
function reportedComponent(key, label, detection, nowMs, build) {
  if (!detection.ok) return component(key, label, 'unknown', '탐지 서버를 확인하지 못해 알 수 없음', {}, iso(nowMs));
  const checkedAt = isoOrNull(detection.payload.checked_at) ?? iso(nowMs);
  const section = detection.payload[key];
  if (!isObject(section)) return component(key, label, 'unknown', '탐지 서버가 보고하지 않음', {}, checkedAt);
  const [status, summary, details] = build(section);
  return component(key, label, status, summary, details, checkedAt);
}

function redisComponent(detection, nowMs) {
  return reportedComponent('redis', 'Redis', detection, nowMs, (section) => {
    const latency = finite(section.latency_ms);
    const details = { '지연 시간(ms)': latency === null ? null : Math.round(latency * 10) / 10, 오류: scrubText(section.error) };
    if (section.ok === true) return ['ok', latency === null ? '연결됨' : `응답 ${Math.round(latency * 10) / 10}ms`, details];
    return ['down', '연결 실패', details];
  });
}

function logShippingComponent(detection, nowMs) {
  const startedAt = isoOrNull(detection.payload?.detection?.started_at);
  return reportedComponent('log_shipping', '판정 기록 전송', detection, nowMs, (section) => {
    const pending = wholeCount(section.pending_bytes) ?? 0;
    const failures = wholeCount(section.consecutive_failures) ?? 0;
    const lastOkAt = isoOrNull(section.last_ok_at);
    // 대기분이 있는데 10분 넘게 성공이 없으면 끊김. 성공 기록이 없으면 Detection 시작 시각부터 센다
    const since = lastOkAt ?? startedAt;
    const stale = pending > 0 && since !== null && nowMs - Date.parse(since) > SHIPPING_STALE_MS;
    const details = {
      '대기 크기(바이트)': pending,
      '마지막 성공': lastOkAt,
      '연속 실패': failures,
      '거부 누계': wholeCount(section.rejected_total),
      '마지막 오류': scrubText(section.last_error),
    };
    if (failures >= SHIPPING_FAILURES_DOWN) return ['down', `연속 ${failures}회 실패`, details];
    if (stale) return ['down', '10분 넘게 전송되지 않음', details];
    if (section.ok === true) return ['ok', pending > 0 ? `대기 ${pending}바이트` : '대기 없음', details];
    return ['slow', failures > 0 ? `최근 ${failures}회 실패` : '전송 확인 필요', details];
  });
}

function keywordJobsComponent(detection, nowMs) {
  return reportedComponent('keyword_jobs', '키워드 추출 작업', detection, nowMs, (section) => {
    const queued = wholeCount(section.queued) ?? 0;
    const running = wholeCount(section.running) ?? 0;
    const failed = wholeCount(section.failed) ?? 0;
    const details = { 대기: queued, 실행: running, 실패: failed };
    return [failed > 0 ? 'slow' : 'ok', `대기 ${queued} · 실행 ${running} · 실패 ${failed}`, details];
  });
}

// GPU는 Detection이 대신 확인한다(/admin/gpu, 읽기 전용). 꺼진 GPU는 고장이 아니라 대기 상태라 '알 수 없음'으로 둔다
const GPU_OFF_SUMMARY = { stopped: '꺼져 있음', stopping: '끄는 중', pending: '켜는 중', shutting_down: '끄는 중' };

async function gpuComponent(fetchDetection, now) {
  const label = 'GPU';
  const result = await callDetection(fetchDetection, '/admin/gpu', GPU_STATUS_TIMEOUT_MS);
  if (!result.ok || !isObject(result.payload) || typeof result.payload.connected !== 'boolean')
    return component('gpu', label, 'unknown', 'GPU 상태를 조회하지 못함', {}, iso(now()));
  const payload = result.payload;
  const checkedAt = isoOrNull(payload.checked_at) ?? iso(now());
  const latency = finite(payload.latency_ms);
  const instanceState = scrubText(payload.instance_state, 30);
  const models = Array.isArray(payload.models) ? payload.models.slice(0, 5).map((model) => scrubText(model, 60)).filter(Boolean) : [];
  const details = {
    모델: models.length ? models.join(', ') : null,
    '지연 시간(ms)': latency === null ? null : Math.round(latency),
    '인스턴스 상태': instanceState,
    오류: scrubText(payload.error),
  };
  if (payload.connected) return component('gpu', label, 'ok', latency === null ? '연결됨' : `응답 ${Math.round(latency)}ms`, details, checkedAt);
  const off = GPU_OFF_SUMMARY[instanceState];
  if (off) return component('gpu', label, 'unknown', off, details, checkedAt);
  return component('gpu', label, 'down', '연결되지 않음', details, checkedAt);
}

// 전체 점검. 느린 점검(DB·Detection·GPU)은 한꺼번에 시작해 가장 느린 것만큼만 걸린다. 어떤 점검이 실패해도 던지지 않는다
export async function collectSystemStatus({ store, getGateway, fetchDetection, now = Date.now }) {
  const [database, detection, gpu, health] = await Promise.all([
    databaseComponent(store, now),
    callDetection(fetchDetection, '/admin/system-status', DETECTION_STATUS_TIMEOUT_MS).then((result) =>
      result.ok && !isObject(result.payload) ? { ok: false, error: new Error('invalid payload') } : result),
    gpuComponent(fetchDetection, now),
    callDetection(fetchDetection, '/health', DETECTION_STATUS_TIMEOUT_MS),
  ]);
  const nowMs = now();
  const { metrics, settingsState, liveState } = getGateway();
  const payload = detection.ok ? detection.payload : null;
  return {
    checked_at: iso(nowMs),
    components: [
      dashboardComponent(nowMs),
      database,
      gatewayComponent(metrics, settingsState, nowMs, liveState),
      relayComponent(metrics, nowMs),
      detectionComponent(detection, nowMs, health),
      redisComponent(detection, nowMs),
      logShippingComponent(detection, nowMs),
      keywordJobsComponent(detection, nowMs),
      gpu,
    ],
    instances: payload ? instancesView(payload.instances) : instancesUnavailable(),
    rds_instance: payload ? rdsView(payload.rds) : rdsUnavailable(),
  };
}
