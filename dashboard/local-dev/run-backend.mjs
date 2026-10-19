// 화면 확인용 로컬 백엔드 (127.0.0.1:9100) - 수정한 app.mjs + 메모리 문서 목록 + 가짜 Detection(18000).
// 로그인 계정은 이 실행에서만 쓰는 시험 값(local-test-account.json). 운영 계정·운영 DB와 무관하다.
// 보안 이벤트 원문 보기: 예시 이벤트 5건을 넣고, 개인정보 가림을 끈 채(EVIDENCE_SHOW_RAW=1) 원문 비교를 돌려준다.
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAppServer } from './server/app.mjs';
import { JsonEventStore } from './server/event-store.mjs';
import { createHash } from 'node:crypto';
import { buildMatchEvidence, buildOwnEvidence } from './server/match-evidence.mjs';
import { DOCUMENTS, buildSamples } from './sample-events.mjs';
import { buildFileSamples } from './sample-file-upload.mjs';

process.env.EVIDENCE_SHOW_RAW ??= '1'; // 로컬 확인용 - 운영 기본값은 가림

const here = path.dirname(fileURLToPath(import.meta.url));
const account = JSON.parse(readFileSync(path.join(here, 'local-test-account.json'), 'utf8'));
const doc = (doc_id, filename, ready = true) => ({
  document_id: doc_id, document_name: filename, registered_at: '2026-10-01T00:00:00.000Z', status: 'ACTIVE',
  processing_status: ready ? 'READY' : 'PROCESSING', file_type: filename.split('.').pop().toUpperCase(),
  exact_fingerprint_status: 'NOT_AVAILABLE', similarity_fingerprint_status: 'NOT_AVAILABLE',
  chunk_index_status: ready ? 'READY' : 'PROCESSING', chunk_count: ready ? 120 : 0, version: '1', owner: 'local-admin',
  active_detectors: ready ? ['WINDOW_HASH'] : [], exact_detection_count: 0, modified_partial_detection_count: 0,
});
const samples = [...buildSamples(), ...buildFileSamples()];   // 파일 업로드 + 질문 한 쌍(10/9)
// 내 요청 기록(10/9): 확장 프로그램 열람 키(시험 값, local-test-account.json)의 지문을 예시 이벤트에 붙인다.
// 'hash-edit' 한 건은 다른 브라우저 요청으로 두어 본인 것만 보이는지 확인한다
const viewerKeyHash = createHash('sha256').update(account.viewerKey).digest('hex');
for (const sample of samples)
  sample.event.viewerKeyHash = sample.event.eventId === 'evt-local-hash-edit' ? createHash('sha256').update('other-browser').digest('hex') : viewerKeyHash;
const byRequest = new Map(samples.map((sample) => [sample.event.requestId, sample]));

class LocalStore extends JsonEventStore {
  async listDocuments() {
    return [
      doc('01_사업전략_방향_보고서', '01_사업전략_방향_보고서.docx'),
      doc('05_투자유치_자료', '05_투자유치_자료.docx'),
      doc('09_아키텍처_설계서', '09_아키텍처_설계서.docx'),
      doc('13_파트너사협상자료', '13_파트너사협상자료.docx'),
      doc('20_장애대응보고서', '20_장애대응보고서.docx', false),
    ];
  }

  // 운영 PostgresEventStore.getEvidence와 같은 계산(buildMatchEvidence) - 판정 기록·문서는 예시 데이터에서 찾는다
  async getEvidence(event, pageRequest) {
    const sample = byRequest.get(event.request_id);
    return buildMatchEvidence(event, sample ? [sample.decision] : [], DOCUMENTS, pageRequest, sample?.gatewayEvidence, sample?.segments);
  }

  // 운영 PostgresEventStore.getOwnEvidence와 같은 계산(buildOwnEvidence)
  async getOwnEvidence(event) {
    const sample = byRequest.get(event.request_id);
    return buildOwnEvidence(event, sample?.decision ?? null, sample?.segments ?? null);
  }
}

const root = mkdtempSync(path.join(tmpdir(), 'dash-local-'));
const server = createAppServer({
  store: new LocalStore(path.join(root, 'events.json')),
  allowedOrigin: 'http://127.0.0.1:5173',
  adminEmail: account.email,
  adminPassword: account.password,
  ingestToken: account.ingestToken,
  policyBaseUrl: 'http://127.0.0.1:18000',
});
server.listen(9100, '127.0.0.1', async () => {
  console.log('local backend on http://127.0.0.1:9100');
  // Gateway와 같은 경로로 예시 이벤트를 넣는다(형식 검증을 그대로 거침)
  for (const { event, gatewayEvidence } of samples) {
    const body = gatewayEvidence ? { ...event, maskEvidence: gatewayEvidence } : event;
    const response = await fetch('http://127.0.0.1:9100/api/events/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${account.ingestToken}` },
      body: JSON.stringify(body),
    });
    if (!response.ok) console.error('sample ingest failed', event.eventId, response.status, await response.text());
  }
  console.log(`sample events: ${samples.length}`);
});
