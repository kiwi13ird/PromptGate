import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/src/api/errors';
import { httpClient } from '@/src/api/httpClient';
import { detectionOpsMessage, detectionOpsService, reportFileUrl } from './detectionOpsService';

const keyword = { id: 7, keyword: 'PRJ-2026-07', doc_id: '13_파트너사협상자료', status: 'pending', source: 'llm', reason: '프로젝트 코드', doc_hits: 1, neg_hits: 0, created_at: '2026-10-04T05:00:00Z', created_by: null, decided_at: null, decided_by: null };
const job = { id: 5, doc_id: '13_파트너사협상자료', doc_version: 1, status: 'queued', attempts: 0, error: null, created_at: '2026-10-04T05:00:00Z', finished_at: null };
afterEach(() => vi.restoreAllMocks());

describe('detection ops service paths and payloads', () => {
  it('reads keywords and keyword jobs without query parameters', async () => {
    const get = vi.spyOn(httpClient, 'get')
      .mockResolvedValueOnce({ keywords: [keyword] })
      .mockResolvedValueOnce({ jobs: [job], counts: { queued: 1, running: 0, done: 0, failed: 0 } });
    await expect(detectionOpsService.getKeywords()).resolves.toEqual([keyword]);
    await expect(detectionOpsService.getKeywordJobs()).resolves.toMatchObject({ counts: { queued: 1 } });
    expect(get.mock.calls.map(call => call[0])).toEqual(['/api/keywords', '/api/keyword-jobs']);
  });
  it('sends keyword changes to the backend routes that reload detection', async () => {
    const post = vi.spyOn(httpClient, 'post')
      .mockResolvedValueOnce({ ...keyword, id: 8, status: 'approved', source: 'manual', applied: true })
      .mockResolvedValueOnce({ ...keyword, status: 'approved', applied: false, apply_error: 'reload failed' })
      .mockResolvedValueOnce({ id: 7, rejected: true, applied: true });
    await expect(detectionOpsService.addKeyword('NeoBoard 3.0', '13_파트너사협상자료', true)).resolves.toMatchObject({ applied: true });
    await expect(detectionOpsService.approveKeyword(7)).resolves.toMatchObject({ status: 'approved', applied: false });
    await expect(detectionOpsService.rejectKeyword(7)).resolves.toMatchObject({ applied: true });
    expect(post.mock.calls).toEqual([
      ['/api/keywords', { keyword: 'NeoBoard 3.0', doc_id: '13_파트너사협상자료', approve: true }],
      ['/api/keywords/7/approve'],
      ['/api/keywords/7/reject'],
    ]);
  });
  it('edits a pending keyword with PATCH and only the keyword field', async () => {
    const patch = vi.spyOn(httpClient, 'patch').mockResolvedValue({ ...keyword, keyword: '24억원', doc_hits: null, neg_hits: null });
    await expect(detectionOpsService.updateKeyword(7, '24억원')).resolves.toMatchObject({ keyword: '24억원', doc_hits: null });
    expect(patch).toHaveBeenCalledWith('/api/keywords/7', { keyword: '24억원' });
  });
  it('encodes document ids for extraction and retries by job id', async () => {
    const post = vi.spyOn(httpClient, 'post').mockResolvedValue(job);
    await detectionOpsService.requestExtraction('doc/#1 문서');
    await detectionOpsService.retryJob(5);
    expect(post.mock.calls.map(call => call[0])).toEqual(['/api/documents/doc%2F%231%20%EB%AC%B8%EC%84%9C/extract-keywords', '/api/keyword-jobs/5/retry']);
  });
  it('creates reports with the inclusive period and the analysis flag (use_llm on the wire)', async () => {
    const post = vi.spyOn(httpClient, 'post').mockResolvedValue({ report_id: 'report_2026-09-15_2026-09-30_20261006T000000', status: 'running', stage: null, from: '2026-09-15', to: '2026-09-30', use_llm: true, elapsed_seconds: 0 });
    await expect(detectionOpsService.createReport('2026-09-15', '2026-09-30', false)).resolves.toMatchObject({ status: 'running' });
    expect(post).toHaveBeenCalledWith('/api/reports', { from: '2026-09-15', to: '2026-09-30', use_llm: false });
  });
  it('sends content_trend only when it is given, so an older detection server never sees the field', async () => {
    const post = vi.spyOn(httpClient, 'post').mockResolvedValue({ report_id: 'report_2026-09-15_2026-09-30_20261006T000000', status: 'running' });
    await detectionOpsService.createReport('2026-09-15', '2026-09-30', true, { contentTrend: true });
    await detectionOpsService.createReport('2026-09-15', '2026-09-30', true, { contentTrend: false });
    await detectionOpsService.createReport('2026-09-15', '2026-09-30', true, {});
    await detectionOpsService.createReport('2026-09-15', '2026-09-30', true);
    expect(post.mock.calls.map(call => call[1])).toEqual([
      { from: '2026-09-15', to: '2026-09-30', use_llm: true, content_trend: true },
      { from: '2026-09-15', to: '2026-09-30', use_llm: true, content_trend: false },
      { from: '2026-09-15', to: '2026-09-30', use_llm: true },
      { from: '2026-09-15', to: '2026-09-30', use_llm: true },
    ]);
  });
  it('reads the report list with the global content trend switch', async () => {
    const get = vi.spyOn(httpClient, 'get');
    get.mockResolvedValueOnce({ reports: [], content_trend_enabled: true });
    await expect(detectionOpsService.getReports()).resolves.toEqual({ reports: [], contentTrendEnabled: true });
    get.mockResolvedValueOnce({ reports: [], content_trend_enabled: false });
    await expect(detectionOpsService.getReports()).resolves.toEqual({ reports: [], contentTrendEnabled: false });
    // 옛 탐지 서버는 칸이 없다 -> null(모름)
    get.mockResolvedValueOnce({ reports: [] });
    await expect(detectionOpsService.getReports()).resolves.toEqual({ reports: [], contentTrendEnabled: null });
    // 모양이 틀린 값도 목록을 막지 않는다
    get.mockResolvedValueOnce({ reports: [], content_trend_enabled: 'yes' });
    await expect(detectionOpsService.getReports()).resolves.toEqual({ reports: [], contentTrendEnabled: null });
    expect(get).toHaveBeenCalledWith('/api/reports', undefined);
  });
  it('keeps the list fields of a finished report and of a running one, and drops how it was written', async () => {
    const finished = {
      report_id: 'report_2026-10-01_2026-10-12_20261012T060000', status: 'done', from: '2026-10-01', to: '2026-10-12', compare_from: '2026-09-19', compare_to: '2026-09-30',
      use_llm: true, generated_at: '2026-10-12T06:03:00+00:00', rows: 25241, items: 242, llm_used: true, mode: 'partial', writer: 'qwen3-8b · LLM 41문장 · 버림 3 · 일부 집계 문장',
      llm_error: null, llm_ms: 96000, agg_ms: 900, lines_kept: 41, lines_dropped: 3, llm_lines: 41, llm_dropped: 3, content_trend: true, content_trend_state: 'on',
      incidents: { total: 62, narrated: 12, by_grade: { '1': 11, '2': 5, '3': 7, '4': 4, '5': 35 } }, users_high: 2, gpu_started: true, gpu_waited_s: 152.5, gpu_auto_stop: { stopped: true }, blind: false, file: '/admin/reports/x/file',
    };
    const running = { report_id: 'report_2026-10-01_2026-10-12_20261012T070000', status: 'running', stage: 'llm', llm_progress: '5/15', from: '2026-10-01', to: '2026-10-12', use_llm: true, content_trend: true, elapsed_seconds: 41 };
    vi.spyOn(httpClient, 'get').mockResolvedValue({ reports: [finished, running], content_trend_enabled: true });
    const { reports } = await detectionOpsService.getReports();
    expect(reports[0]).toEqual({
      report_id: finished.report_id, status: 'done', from: '2026-10-01', to: '2026-10-12', compare_from: '2026-09-19', compare_to: '2026-09-30',
      generated_at: '2026-10-12T06:03:00+00:00', rows: 25241, items: 242,
      incidents: { total: 62, by_grade: { '1': 11, '2': 5, '3': 7, '4': 4, '5': 35 } }, users_high: 2,
    });
    expect(reports[1]).toEqual({ report_id: running.report_id, status: 'running', stage: 'llm', from: '2026-10-01', to: '2026-10-12', elapsed_seconds: 41 });
    // 작성 방식·문장 수·LLM/GPU 시간·진행 횟수는 화면 모델에 남기지 않는다
    for (const report of reports) {
      for (const field of ['use_llm', 'llm_used', 'mode', 'writer', 'llm_lines', 'llm_dropped', 'llm_error', 'llm_ms', 'agg_ms', 'gpu_waited_s', 'content_trend', 'content_trend_state', 'llm_progress', 'lines_kept']) {
        expect(report).not.toHaveProperty(field);
      }
    }
  });
  it('reads a report written before 2026-10-12 and a failed one that has no period', async () => {
    const old = { report_id: 'report_2026-09-15_2026-09-30_20261004T000000', status: 'done', from: '2026-09-15', to: '2026-09-30', use_llm: true, generated_at: '2026-10-04T00:00:30+00:00', rows: 1234, llm_used: false, llm_error: 'URLError', lines_kept: null, lines_dropped: 0 };
    const failed = { report_id: 'report_2026-10-01_2026-10-12_20261012T080000', status: 'failed', error: '합계 불일치' };
    vi.spyOn(httpClient, 'get').mockResolvedValue({ reports: [old, failed] });
    const { reports } = await detectionOpsService.getReports();
    expect(reports[0]).toMatchObject({ rows: 1234 });
    expect(reports[0].items).toBeUndefined();
    expect(reports[0].incidents).toBeUndefined();
    expect(reports[1]).toMatchObject({ status: 'failed', error: '합계 불일치' });
  });
  it('drops only the new field whose shape is wrong instead of failing the whole list', async () => {
    const odd = { report_id: 'report_2026-10-01_2026-10-12_20261012T060000', status: 'done', from: '2026-10-01', to: '2026-10-12', items: 242, incidents: 'many', users_high: -1, compare_from: 20260919 };
    vi.spyOn(httpClient, 'get').mockResolvedValue({ reports: [odd] });
    const { reports } = await detectionOpsService.getReports();
    expect(reports).toHaveLength(1);
    expect(reports[0]).toMatchObject({ report_id: odd.report_id, items: 242 });
    for (const field of ['incidents', 'users_high', 'compare_from'] as const) expect(reports[0][field]).toBeUndefined();
  });
  it('still rejects a list whose required fields are wrong', async () => {
    vi.spyOn(httpClient, 'get').mockResolvedValue({ reports: [{ report_id: 'x', status: 'finished' }] });
    await expect(detectionOpsService.getReports()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
  it('reads gpu status and rejects malformed responses', async () => {
    const get = vi.spyOn(httpClient, 'get').mockResolvedValueOnce({ connected: true, models: ['qwen3-8b'], latency_ms: 6, error: null, checked_at: '2026-10-06T12:00:00+00:00' });
    await expect(detectionOpsService.getGpuStatus()).resolves.toMatchObject({ connected: true, models: ['qwen3-8b'] });
    expect(get).toHaveBeenCalledWith('/api/system/gpu', undefined);
    get.mockResolvedValueOnce({ connected: 'yes' });
    await expect(detectionOpsService.getGpuStatus()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
  it('builds report file links that open inline or download', () => {
    expect(reportFileUrl('report_a')).toBe(`${window.location.origin}/api/reports/report_a/file`);
    expect(reportFileUrl('report_a', true)).toBe(`${window.location.origin}/api/reports/report_a/file?download=1`);
  });
});

describe('detection ops messages', () => {
  it.each([
    [new ApiError('x', 'CONFLICT', 409), 'report', '이미 만들고 있는 리포트'],
    [new ApiError('x', 'NOT_FOUND', 404), 'extract', '색인이 끝나지 않은 문서'],
    [new ApiError('x', 'CONFLICT', 409), 'keyword', '이미 등록된 키워드'],
    [new ApiError('x', 'VALIDATION', 400), 'keyword', '2~100자'],
    [new ApiError('x', 'SERVER', 503), 'report', '탐지 서버에 연결할 수 없습니다'],
    [new ApiError('x', 'CONFLICT', 409), 'edit', '그사이 승인된 키워드'],
    [new ApiError('x', 'NOT_FOUND', 404), 'edit', '이미 삭제된 키워드'],
  ] as const)('maps %s for %s', (error, context, expected) => {
    expect(detectionOpsMessage(error, context)).toContain(expected);
  });
});
