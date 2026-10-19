// 2026-10-11 HWP·HWPX 보호 문서 등록(PDF·HWP 마스킹 명세 1단계 §2.4). 시험 파일은 모두 가짜 내용으로 여기서 만든다.
// 판별 규칙은 Detection·Gateway 공통 모듈 hwpdoc.sniff와 같음(실파일·변형 대조는 인계 자료에 기록).
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { crc32, deflateRawSync } from 'node:zlib';
import { createAppServer } from '../app.mjs';
import { JsonEventStore } from '../event-store.mjs';
import { sniffHangulDocument } from '../hwp-format.mjs';
import { PostgresEventStore } from '../postgres-event-store.mjs';

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const NOSTREAM = 0xffffffff;

function hwpFileHeader({ signature = 'HWP Document File', flags = 0 } = {}) {
  const header = Buffer.alloc(256);
  header.write(signature, 0, 'latin1');
  header.writeUInt32LE(0x05010100, 32);
  header.writeUInt32LE(flags, 36);
  return header;
}

// 512바이트 구역 CFB. entries: [{ name, data }] 스트림, [{ name, children }] 저장소, type·size로 강제 가능
function buildCfb(entries) {
  const nodes = [{ name: 'Root Entry', type: 5 }];
  const flatten = (list) => list.map((entry) => {
    const node = { ...entry, type: entry.type ?? (entry.children ? 1 : 2) };
    nodes.push(node);
    const id = nodes.length - 1;
    if (entry.children) node.childIds = flatten(entry.children);
    return id;
  });
  nodes[0].childIds = flatten(entries);
  const streams = nodes.filter((node) => node.type === 2 && node.data);
  const mini = streams.filter((node) => node.data.length < 4096);
  const regular = streams.filter((node) => node.data.length >= 4096);
  const miniFat = [];
  const miniChunks = [];
  for (const node of mini) {
    const count = Math.ceil(node.data.length / 64);
    node.start = miniFat.length;
    for (let index = 0; index < count; index += 1) miniFat.push(index === count - 1 ? ENDOFCHAIN : miniFat.length + 1);
    const padded = Buffer.alloc(count * 64);
    node.data.copy(padded);
    miniChunks.push(padded);
  }
  const ministream = Buffer.concat(miniChunks);
  const sectorsFor = (bytes) => Math.ceil(bytes / 512);
  const counts = [sectorsFor(nodes.length * 128), sectorsFor(miniFat.length * 4), sectorsFor(ministream.length),
    ...regular.map((node) => sectorsFor(node.data.length))];
  const payload = counts.reduce((sum, count) => sum + count, 0);
  let fatSectors = 1;
  while (fatSectors * 128 < fatSectors + payload) fatSectors += 1;
  const fat = new Array(fatSectors * 128).fill(FREESECT).fill(0xfffffffd, 0, fatSectors);
  let next = fatSectors;
  const starts = counts.map((count) => {
    if (!count) return ENDOFCHAIN;
    const start = next;
    for (let index = 0; index < count; index += 1) fat[next + index] = index === count - 1 ? ENDOFCHAIN : next + index + 1;
    next += count;
    return start;
  });
  const [dirStart, miniFatStart, ministreamStart] = starts;
  regular.forEach((node, index) => { node.start = starts[3 + index]; });
  const body = Buffer.alloc(next * 512);
  fat.forEach((value, index) => body.writeUInt32LE(value, index * 4));
  nodes.forEach((node, id) => {
    const at = dirStart * 512 + id * 128;
    const name = Buffer.from(node.name, 'utf16le');
    name.copy(body, at);
    body.writeUInt16LE(name.length + 2, at + 64);
    body[at + 66] = node.type;
    body.writeUInt32LE(NOSTREAM, at + 68);
    body.writeUInt32LE(NOSTREAM, at + 72);
    body.writeUInt32LE(node.childIds?.[0] ?? NOSTREAM, at + 76);
    const isRoot = node.type === 5;
    body.writeUInt32LE(isRoot ? ministreamStart : node.data ? node.start : ENDOFCHAIN, at + 116);
    body.writeUInt32LE(isRoot ? ministream.length : node.size ?? node.data?.length ?? 0, at + 120);
  });
  // 형제는 오른쪽 사슬로 잇는다(olefile·hwp-format 모두 균형을 검사하지 않음)
  for (const node of nodes) {
    const ids = node.childIds ?? [];
    for (let index = 0; index + 1 < ids.length; index += 1) body.writeUInt32LE(ids[index + 1], dirStart * 512 + ids[index] * 128 + 72);
  }
  if (miniFat.length) {
    body.fill(0xff, miniFatStart * 512, (miniFatStart + counts[1]) * 512);
    miniFat.forEach((value, index) => body.writeUInt32LE(value, miniFatStart * 512 + index * 4));
    ministream.copy(body, ministreamStart * 512);
  }
  for (const node of regular) node.data.copy(body, node.start * 512);
  const header = Buffer.alloc(512);
  Buffer.from('d0cf11e0a1b11ae1', 'hex').copy(header);
  header.writeUInt16LE(0x3e, 24);
  header.writeUInt16LE(3, 26);
  header.writeUInt16LE(0xfffe, 28);
  header.writeUInt16LE(9, 30);
  header.writeUInt16LE(6, 32);
  header.writeUInt32LE(fatSectors, 44);
  header.writeUInt32LE(dirStart, 48);
  header.writeUInt32LE(4096, 56);
  header.writeUInt32LE(miniFatStart, 60);
  header.writeUInt32LE(counts[1], 64);
  header.writeUInt32LE(ENDOFCHAIN, 68);
  for (let index = 0; index < 109; index += 1) header.writeUInt32LE(index < fatSectors ? index : FREESECT, 76 + index * 4);
  return Buffer.concat([header, body]);
}

// entries: [{ name, data, method = 0|8, flags = 0, crc }]
function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const data = Buffer.from(entry.data);
    const method = entry.method ?? 0;
    const stored = method === 8 ? deflateRawSync(data) : data;
    const fields = (buffer, at) => {
      buffer.writeUInt16LE(entry.flags ?? 0, at);
      buffer.writeUInt16LE(method, at + 2);
      buffer.writeUInt32LE(entry.crc ?? crc32(data), at + 8);
      buffer.writeUInt32LE(stored.length, at + 12);
      buffer.writeUInt32LE(data.length, at + 16);
      buffer.writeUInt16LE(name.length, at + 20);
    };
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    fields(local, 6);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    fields(central, 8);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, stored);
    centrals.push(central, name);
    offset += 30 + name.length + stored.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

const hwpEntries = (fileHeader = hwpFileHeader()) => [
  { name: 'FileHeader', data: fileHeader },
  { name: 'DocInfo', data: Buffer.alloc(600, 1) },
  { name: 'BodyText', children: [{ name: 'Section0', data: Buffer.alloc(5000, 2) }] },
  { name: '\u0005HwpSummaryInformation', data: Buffer.alloc(300, 3) },
];
const hwpxEntries = (mimetype = {}) => [
  { name: 'mimetype', data: 'application/hwp+zip', ...mimetype },
  { name: 'version.xml', data: '<hv:HCFVersion xmlns:hv="http://www.hancom.co.kr/hwpml/2011/version"/>' },
  { name: 'Contents/content.hpf', data: '<opf:package xmlns:opf="http://www.idpf.org/2007/opf/"/>', method: 8 },
  { name: 'Contents/section0.xml', data: '<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section"/>', method: 8 },
];
const docxBytes = () => buildZip([
  { name: '[Content_Types].xml', data: '<Types/>' },
  { name: 'word/document.xml', data: '<w:document/>', method: 8 },
]);

void test('HWP is recognized by the FileHeader signature, other CFB files are not', () => {
  assert.equal(sniffHangulDocument(buildCfb(hwpEntries())), 'hwp');
  // olefile처럼 이름은 대소문자 구분 없음, 머리 스트림이 4096바이트 이상(일반 구역)이어도 같음
  assert.equal(sniffHangulDocument(buildCfb([{ name: 'FILEHEADER', data: hwpFileHeader() }])), 'hwp');
  assert.equal(sniffHangulDocument(buildCfb([{ name: 'FileHeader', data: Buffer.concat([hwpFileHeader(), Buffer.alloc(5000)]) }])), 'hwp');
  // 암호·배포용 플래그는 등록 단계에서 막지 않음(인덱서가 hwp_encrypted 등으로 오류 처리)
  assert.equal(sniffHangulDocument(buildCfb(hwpEntries(hwpFileHeader({ flags: 2 })))), 'hwp');

  const notHwp = {
    'Word 97 DOC': buildCfb([{ name: 'WordDocument', data: Buffer.alloc(4200, 7) }, { name: '1Table', data: Buffer.alloc(900) }]),
    'encrypted OOXML': buildCfb([{ name: 'EncryptionInfo', data: Buffer.alloc(300) }, { name: 'EncryptedPackage', data: Buffer.alloc(9000) }]),
    'wrong signature': buildCfb(hwpEntries(hwpFileHeader({ signature: 'HWP Document Filx' }))),
    'signature with trailing space': buildCfb(hwpEntries(hwpFileHeader({ signature: 'HWP Document File ' }))),
    'FileHeader is a storage': buildCfb([{ name: 'FileHeader', children: [{ name: 'Inner', data: hwpFileHeader() }] }]),
    'FileHeader only below root': buildCfb([{ name: 'Sub', children: [{ name: 'FileHeader', data: hwpFileHeader() }] }]),
    'FileHeader shorter than 32 bytes': buildCfb([{ name: 'FileHeader', data: hwpFileHeader().subarray(0, 31) }]),
    'FileHeader size larger than the file': buildCfb([{ name: 'FileHeader', data: hwpFileHeader(), size: 50_000_000 }]),
    'shorter than 1536 bytes': buildCfb(hwpEntries()).subarray(0, 1535),
    'CFB magic only': Buffer.concat([Buffer.from('d0cf11e0a1b11ae1', 'hex'), Buffer.alloc(4096)]),
  };
  for (const [label, data] of Object.entries(notHwp)) assert.equal(sniffHangulDocument(data), null, label);
});

void test('HWPX is recognized by mimetype or content.hpf, other ZIP files are not', () => {
  assert.equal(sniffHangulDocument(buildZip(hwpxEntries())), 'hwpx');
  assert.equal(sniffHangulDocument(buildZip(hwpxEntries({ method: 8 }))), 'hwpx');
  assert.equal(sniffHangulDocument(buildZip(hwpxEntries({ data: 'application/hwp+zip\r\n' }))), 'hwpx');
  assert.equal(sniffHangulDocument(buildZip(hwpxEntries().slice(1))), 'hwpx');

  const notHwpx = {
    DOCX: docxBytes(),
    'EPUB-like mimetype with content.hpf': buildZip(hwpxEntries({ data: 'application/epub+zip' })),
    'mimetype CRC mismatch': buildZip(hwpxEntries({ crc: 1 })),
    'encrypted mimetype': buildZip(hwpxEntries({ flags: 1 })),
    'mimetype longer than 64 bytes': buildZip(hwpxEntries({ data: `application/hwp+zip${' '.repeat(50)}` })),
    'unsupported compression': buildZip(hwpxEntries({ method: 99 })),
    'no HWPX entries': buildZip([{ name: 'Contents/section0.xml', data: '<x/>' }]),
    'ZIP magic only': Buffer.concat([Buffer.from('PK\u0003\u0004'), Buffer.alloc(100)]),
    'truncated central directory': buildZip(hwpxEntries()).subarray(0, -30),
  };
  for (const [label, data] of Object.entries(notHwpx)) assert.equal(sniffHangulDocument(data), null, label);
});

void test('cyclic sector chains with an oversized declared size are refused quickly', () => {
  const data = buildCfb(hwpEntries());
  const fatAt = 512;
  const dirAt = (data.readUInt32LE(48) + 1) * 512;
  const rootStart = data.readUInt32LE(dirAt + 116);
  let sector = rootStart;
  while (data.readUInt32LE(fatAt + sector * 4) !== ENDOFCHAIN) sector = data.readUInt32LE(fatAt + sector * 4);
  data.writeUInt32LE(rootStart, fatAt + sector * 4);
  data.writeUInt32LE(0xffffffff, dirAt + 120);
  const started = performance.now();
  assert.equal(sniffHangulDocument(data), null);
  assert.ok(performance.now() - started < 1000);
});

function documentPool() {
  const calls = [];
  const client = {
    async query(sql, parameters) {
      calls.push({ sql: sql.trim(), parameters });
      if (/INSERT INTO documents/.test(sql)) {
        return {
          rowCount: 1,
          rows: [{
            doc_id: parameters[0], filename: parameters[1], format: parameters[4], version: '1', status: 'active',
            index_status: 'pending', index_windows: 0, registered_at: new Date('2026-10-11T00:00:00Z'), registered_by: parameters[3],
          }],
        };
      }
      return { rowCount: 0, rows: [] };
    },
    release() {},
  };
  return { pool: { connect: async () => client }, calls };
}

void test('document registration stores hwp and hwpx as the format and refuses look-alike files', async () => {
  for (const [filename, data, format] of [
    ['가짜 보고서.hwp', buildCfb(hwpEntries()), 'hwp'],
    ['가짜 보고서.HWPX', buildZip(hwpxEntries()), 'hwpx'],
  ]) {
    const { pool, calls } = documentPool();
    const result = await new PostgresEventStore({ pool }).registerDocument({ filename, data, registeredBy: 'admin-test' });
    assert.equal(result.outcome, 'created');
    assert.equal(result.document.file_type, format);
    const insert = calls.find(({ sql }) => /INSERT INTO documents/.test(sql));
    assert.equal(insert.parameters[4], format);
  }
  for (const [filename, data] of [
    ['doc renamed.hwp', buildCfb([{ name: 'WordDocument', data: Buffer.alloc(4200) }])],
    ['docx renamed.hwpx', docxBytes()],
    ['hwpx renamed.hwp', buildZip(hwpxEntries())],
    ['hwp renamed.hwpx', buildCfb(hwpEntries())],
    ['text.hwp', Buffer.from('HWP Document File')],
  ]) {
    const { pool, calls } = documentPool();
    await assert.rejects(
      new PostgresEventStore({ pool }).registerDocument({ filename, data, registeredBy: 'admin-test' }),
      (error) => error.statusCode === 422 && error.code === 'UNSUPPORTED_DOCUMENT' && /HWP, and HWPX/.test(error.message),
      filename,
    );
    assert.equal(calls.length, 0, filename);
  }
  // 기존 형식 판별은 그대로(DOCX 확장자는 ZIP 머리만 봄)
  const { pool } = documentPool();
  const docx = await new PostgresEventStore({ pool }).registerDocument({ filename: 'plan.docx', data: buildZip(hwpxEntries()), registeredBy: 'admin-test' });
  assert.equal(docx.document.file_type, 'docx');
});

void test('HTTP upload of an HWP keeps the 20 MiB limit and returns 422 for a renamed DOC', async () => {
  const config = {
    allowedOrigin: 'http://127.0.0.1:4173',
    adminEmail: 'local-admin-hwp@example.test',
    adminPassword: 'local-password-hwp-tests',
    ingestToken: 'local-ingest-token-hwp-tests',
  };
  const root = await mkdtemp(path.join(tmpdir(), 'llm-backend-hwp-'));
  const { pool, calls } = documentPool();
  const postgres = new PostgresEventStore({ pool });
  class HwpUploadStore extends JsonEventStore {
    registerDocument(input) {
      return postgres.registerDocument(input);
    }
  }
  const server = createAppServer({ ...config, store: new HwpUploadStore(path.join(root, 'events.json')) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: config.adminEmail, password: config.adminPassword }),
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const upload = (data, name) => {
      const form = new FormData();
      form.append('file', new Blob([data]), name);
      return fetch(`${baseUrl}/api/documents`, { method: 'POST', headers: { Cookie: cookie }, body: form });
    };
    const limit = 20 * 1024 * 1024;
    const hwp = buildCfb(hwpEntries());
    const created = await upload(Buffer.concat([hwp, Buffer.alloc(limit - hwp.length)]), '가짜 큰 문서.hwp');
    assert.equal(created.status, 201);
    assert.equal((await created.json()).file_type, 'hwp');
    const tooLarge = await upload(Buffer.concat([hwp, Buffer.alloc(limit + 1 - hwp.length)]), '가짜 큰 문서.hwp');
    assert.equal(tooLarge.status, 413);
    const renamed = await upload(buildCfb([{ name: 'WordDocument', data: Buffer.alloc(4200) }]), 'renamed.hwp');
    assert.equal(renamed.status, 422);
    assert.equal((await renamed.json()).error.code, 'UNSUPPORTED_DOCUMENT');
    assert.equal(calls.filter(({ sql }) => /INSERT INTO documents/.test(sql)).length, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
