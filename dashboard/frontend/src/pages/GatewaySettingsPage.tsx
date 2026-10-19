import { LockKeyhole } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { liveQueryOptions } from '@/src/components/AutoRefreshBar';
import { PgBadge, PgError, PgPageHeader, PgRefresh, PgSkeleton, PgStatusStrip, type StripLevel } from '@/src/components/pg';
import { maxCharsForWait } from '@/src/constants/detectionSpeed';
import { auditKeys } from '@/src/queries/keys';
import {
  SETTINGS_CONFLICT_MESSAGE,
  fromDraft,
  gatewaySettingsErrorMessage,
  gatewaySettingsLoadMessage,
  gatewaySettingsKeys,
  gatewaySettingsService,
  gatewayStateText,
  isSettingsConflict,
  parseWaitSeconds,
  savedSettingsText,
  toDraft,
  type GatewaySettingsDocument,
  type GatewaySettingsDraft,
  type GatewaySettingsValues,
} from '@/src/services/gatewaySettingsService';
import { notifySuccess } from '@/src/utils/feedback';
import { changedSettingsFields } from '@/src/utils/gatewaySettingsText';
import { canRetainQueryData } from '@/src/utils/queryPresentation';
import { uiMode } from '@runtime/ui-mode';
import '@/src/gateway-settings.css';
import { formatCount } from '@/src/utils/format';

// 저장 직후에는 Gateway 반영을 2초마다 확인한다(반영되거나 30초가 지나면 평소 10초 주기로)
const FAST_POLL_MS = 2_000;
const FAST_POLL_WINDOW_MS = 30_000;

const valuesOf = (document: GatewaySettingsDocument): GatewaySettingsValues => ({
  timeout: document.timeout,
  uninspectable: document.uninspectable,
  notify_on_allow: document.notify_on_allow,
});
const sameDocument = (left: GatewaySettingsDocument, right: GatewaySettingsDocument) =>
  left.version === right.version && left.revision === right.revision;
const chars = (seconds: number) => maxCharsForWait(seconds).toLocaleString('ko-KR');
const uninspectablePatch = (key: 'image' | 'scannedPdf' | 'other', value: 'allow' | 'block') => {
  const patch: Partial<GatewaySettingsDraft> = {};
  patch[key] = value;
  return patch;
};

// Gateway 처리(재설계 3f, 설계 5.7): 머리 → 상태 띠(저장 판·Gateway 반영, 반영 전이면 주의) → 설정 카드 3개
// (한 행 = [항목][처리 선택][대기 초][결과 "약 120,967자 검사 가능" 굵게]) → 아래 고정 저장 줄([기본값 채우기] 조용한 버튼 · 바뀐 칸 수 · [저장]).
// 저장 확인창·알림 문구 'Gateway 처리 설정'은 그대로(설계 2.2). 기능·API 호출은 그대로.
const STATE_LEVEL: Readonly<Record<'ok' | 'pending' | 'warn', StripLevel>> = { ok: 'ok', pending: 'progress', warn: 'warn' };
const STATE_WORD = { ok: '반영 완료', pending: '반영 대기', warn: '확인 필요' } as const;

function WaitNotes({ text, kind, action }: { text: string; kind: 'prompt' | 'file'; action: 'block' | 'forward' }) {
  const seconds = parseWaitSeconds(text);
  if (seconds === null)
    return <div className="gws-notes"><p className="gws-input-error" role="alert">대기 시간은 0.05~30초 사이로 입력하세요.</p></div>;
  return <div className="gws-notes">
    <p className="gws-result">약 <strong>{chars(seconds)}</strong>자 검사 가능 <span className="gws-result-note">이 대기 시간 · 실측 최악 속도 기준</span></p>
    {kind === 'file' && <p>이보다 긴 파일은 Detection에 보내지 않고 {action === 'block' ? '차단' : '검사 없이 전송'}</p>}
  </div>;
}

export function GatewaySettingsPage() {
  const client = useQueryClient();
  const canManage = uiMode.canManagePolicies;
  const [fastUntil, setFastUntil] = useState<number | null>(null);
  const [base, setBase] = useState<GatewaySettingsDocument | null>(null);
  const [draft, setDraft] = useState<GatewaySettingsDraft | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [notice, setNotice] = useState('');

  const query = useQuery({
    ...liveQueryOptions,
    queryKey: gatewaySettingsKeys.detail(),
    queryFn: ({ signal }) => gatewaySettingsService.get(signal),
    refetchInterval: (current) =>
      fastUntil !== null && Date.now() < fastUntil && current.state.data?.gateway.state !== 'APPLIED'
        ? FAST_POLL_MS : liveQueryOptions.refetchInterval,
  });
  const latest = query.data?.settings;
  const gatewayState = query.data?.gateway.state;

  const draftValues = draft ? fromDraft(draft) : null;
  const baseValues = base ? valuesOf(base) : null;
  const changes = draftValues && baseValues ? changedSettingsFields(baseValues, draftValues) : [];
  const dirty = Boolean(draft && base && (!draftValues || changes.length > 0));
  // 편집을 시작한 뒤 다른 관리자가 저장함: 입력을 덮지 않고 알린다(저장은 최신 값을 불러온 뒤)
  const stale = Boolean(latest && base && !sameDocument(base, latest));

  useEffect(() => {
    if (!latest) return;
    if (!base || (!sameDocument(base, latest) && !dirty)) {
      setBase(latest);
      setDraft(toDraft(latest));
    }
  }, [latest, base, dirty]);
  useEffect(() => {
    if (fastUntil !== null && gatewayState === 'APPLIED') setFastUntil(null);
  }, [fastUntil, gatewayState]);
  useEffect(() => {
    if (fastUntil === null) return;
    const timer = window.setTimeout(() => setFastUntil(null), Math.max(0, fastUntil - Date.now()));
    return () => window.clearTimeout(timer);
  }, [fastUntil]);

  const adopt = (document: GatewaySettingsDocument) => {
    setBase(document);
    setDraft(toDraft(document));
  };
  const save = useMutation({
    mutationFn: ({ values, expectedVersion }: { values: GatewaySettingsValues; expectedVersion: number }) =>
      gatewaySettingsService.save(values, expectedVersion),
    onSuccess: async (response) => {
      client.setQueryData(gatewaySettingsKeys.detail(), response);
      adopt(response.settings);
      setConfirmOpen(false);
      setNotice('');
      setFastUntil(response.gateway.state === 'APPLIED' ? null : Date.now() + FAST_POLL_WINDOW_MS);
      notifySuccess('Gateway 처리 설정을 저장했습니다.', `v${response.settings.version} · 반영 상태는 위 상태 줄에서 확인하세요.`);
      await client.invalidateQueries({ queryKey: auditKeys.all });
    },
    onError: async (error) => {
      if (!isSettingsConflict(error)) return;
      // 409: 최신 값을 다시 읽어 입력 칸에 채우고 알린다
      setConfirmOpen(false);
      const fresh = await query.refetch();
      if (fresh.data) adopt(fresh.data.settings);
      setNotice(SETTINGS_CONFLICT_MESSAGE);
    },
  });

  const update = (patch: Partial<GatewaySettingsDraft>) => {
    setNotice('');
    setDraft(current => (current ? { ...current, ...patch } : current));
  };
  const busy = save.isPending;
  const locked = !canManage || busy;
  const canSave = canManage && !busy && !stale && !query.isError && Boolean(draftValues) && changes.length > 0;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canSave) return;
    save.reset();
    setConfirmOpen(true);
  };
  const confirmSave = () => {
    if (!canSave || !draftValues || !base) return;
    save.mutate({ values: draftValues, expectedVersion: base.version });
  };

  const loadFailed = query.isError && (!query.data || !canRetainQueryData(query.error));
  const defaults = query.data?.defaults;
  const state = query.data ? gatewayStateText(query.data.gateway) : null;
  return (
    <div className="pg-screen pg-gws gws-page">
      <PgPageHeader
        title="Gateway 처리"
        description="검사 지연·검사할 수 없는 파일·사용자 알림 처리"
        secondary={canManage ? undefined : <PgBadge variant="tag" className="pg-readonly"><LockKeyhole aria-hidden="true" />읽기 전용</PgBadge>}
        refresh={<PgRefresh updatedAt={query.dataUpdatedAt} fetching={query.isFetching} failed={query.isError} onRefresh={() => query.refetch()} />}
      />
      {query.isError && query.data && canRetainQueryData(query.error) && (
        <p className="pg-stale" role="status">갱신 실패 · 아래는 마지막 성공 조회 결과입니다. 저장은 조회가 회복되면 할 수 있습니다.</p>
      )}
      {query.isLoading ? (
        <PgSkeleton shape="table" rows={4} />
      ) : loadFailed ? (
        <PgError message={gatewaySettingsLoadMessage(query.error)} onRetry={() => query.refetch()} />
      ) : query.data && draft && base && state ? (
        <>
          <PgStatusStrip level={STATE_LEVEL[state.tone]} word={STATE_WORD[state.tone]} label="저장·반영 상태"
            facts={[<span key="s" className="pg-strip-main">{savedSettingsText(query.data.settings)}</span>, <span key="g" className="pg-strip-sub">{state.text}</span>]} />
          {notice && <p className="gws-alert" role="alert">{notice}</p>}
          {stale && dirty && (
            <div className="gws-alert" role="alert">
              <span>{SETTINGS_CONFLICT_MESSAGE}</span>
              <Button size="sm" variant="outline" onClick={() => { if (latest) adopt(latest); }}>최신 값 불러오기</Button>
            </div>
          )}
          <form className="gws-form" onSubmit={submit} aria-label="Gateway 처리 설정">
            <section className="pg-card gws-card" aria-labelledby="gws-timeout-title">
              <header className="pg-card-head"><h2 id="gws-timeout-title" className="pg-card-title">검사 지연·실패 시</h2><span className="pg-card-note pg-card-head-end">대기 시간 0.05~30초</span></header>
              <div className="gws-body">
                <div className="gws-row">
                  <span className="gws-row-label">질문</span>
                  <div className="gws-fields">
                    <label className="gws-field">처리
                      <select aria-label="질문 지연 시 처리" value={draft.promptAction} disabled={locked} onChange={event => update({ promptAction: event.target.value as GatewaySettingsDraft['promptAction'] })}>
                        <option value="forward">원본 전송</option>
                        <option value="block">차단</option>
                      </select>
                    </label>
                    <label className="gws-field">대기
                      <Input type="number" step="any" min="0.05" max="30" inputMode="decimal" aria-label="질문 대기 시간(초)" value={draft.promptSeconds} disabled={locked} onChange={event => update({ promptSeconds: event.target.value })} />
                      초
                    </label>
                  </div>
                  <WaitNotes text={draft.promptSeconds} kind="prompt" action={draft.promptAction} />
                </div>
                <div className="gws-row">
                  <span className="gws-row-label">파일</span>
                  <div className="gws-fields">
                    <label className="gws-field">처리
                      <select aria-label="파일 지연 시 처리" value={draft.fileAction} disabled={locked} onChange={event => update({ fileAction: event.target.value as GatewaySettingsDraft['fileAction'] })}>
                        <option value="block">차단</option>
                        <option value="forward">원본 전송</option>
                      </select>
                    </label>
                    <label className="gws-field">대기
                      <Input type="number" step="any" min="0.05" max="30" inputMode="decimal" aria-label="파일 대기 시간(초)" value={draft.fileSeconds} disabled={locked} onChange={event => update({ fileSeconds: event.target.value })} />
                      초
                    </label>
                  </div>
                  <WaitNotes text={draft.fileSeconds} kind="file" action={draft.fileAction} />
                </div>
                <p className="gws-fixed-note">대기하는 동안 Gateway를 지나는 다른 요청도 함께 기다립니다.</p>
              </div>
            </section>
            <section className="pg-card gws-card" aria-labelledby="gws-uninspectable-title">
              <header className="pg-card-head"><h2 id="gws-uninspectable-title" className="pg-card-title">검사할 수 없는 파일</h2><span className="pg-card-note pg-card-head-end">허용해도 관리자 기록에 남음</span></header>
              <div className="gws-body">
                {/* 설명은 운영 Gateway 파일 분류(gateway_file_classes.py, 2026-10-11 반영본 md5 0a19c40f)와 맞춘다.
                    PDF·DOCX·XLSX·HWP·HWPX·텍스트는 글자를 뽑아 검사하므로 여기 들지 않는다(암호·배포용·손상 등 못 읽는 경우만 기타 형식) */}
                {([
                  ['image', '이미지', 'PNG·JPEG·GIF·WEBP, 그림만 든 DOCX·XLSX'],
                  ['scannedPdf', '스캔 PDF', '글자 없이 이미지만 있는 PDF'],
                  ['other', '기타 형식', 'PPT·옛 DOC·XLS·RTF·압축 파일, 암호·배포용·손상 문서(HWP·PDF 포함), 글자 없는 문서, 그 밖 형식 등'],
                ] as const).map(([key, label, hint]) => (
                  <div className="gws-row" key={key}>
                    <span className="gws-row-label">{label}</span>
                    <div className="gws-fields">
                      <label className="gws-field">처리
                        <select aria-label={`${label} 처리`} value={draft[key]} disabled={locked} onChange={event => update(uninspectablePatch(key, event.target.value as 'allow' | 'block'))}>
                          <option value="allow">허용·기록</option>
                          <option value="block">차단</option>
                        </select>
                      </label>
                    </div>
                    <div className="gws-notes"><p>{hint}</p></div>
                  </div>
                ))}
                <p className="gws-fixed-note">PDF·DOCX·XLSX·HWP·HWPX·텍스트 파일은 내용을 검사합니다.</p>
              </div>
            </section>
            <section className="pg-card gws-card" aria-labelledby="gws-notify-title">
              <header className="pg-card-head"><h2 id="gws-notify-title" className="pg-card-title">사용자 알림</h2><span className="pg-card-note pg-card-head-end">차단·마스킹은 항상 알림</span></header>
              <div className="gws-body">
                <label className="gws-check">
                  <input type="checkbox" checked={draft.notifyOnAllow} disabled={locked} onChange={event => update({ notifyOnAllow: event.target.checked })} />
                  검사 없이 전송된 경우에도 알림
                </label>
              </div>
            </section>
            {canManage && (
              <div className="gws-actions pg-gws-savebar">
                <Button type="button" variant="ghost" disabled={locked} onClick={() => { if (defaults) update(toDraft(defaults)); }}>기본값 채우기</Button>
                <small className={changes.length > 0 ? 'is-changed' : undefined}>{!draftValues ? '대기 시간을 확인하세요.' : changes.length === 0 ? '바뀐 값 없음' : `바뀐 칸 ${formatCount(changes.length)}개`}</small>
                <Button type="submit" disabled={!canSave}>{busy ? '저장 중…' : '저장'}</Button>
              </div>
            )}
          </form>
        </>
      ) : null}
      <Dialog open={confirmOpen} onOpenChange={open => { if (!open && !busy) setConfirmOpen(false); }}>
        <DialogContent className="admin-dialog confirm-dialog console-dialog">
          <DialogHeader>
            <DialogTitle>Gateway 처리 설정 저장</DialogTitle>
            <DialogDescription>
              {base ? `${base.version === 0 ? '기본값' : `v${base.version}`} → v${base.version + 1} · 다음 Gateway 보고 때 반영됩니다(최대 약 11초).` : ''}
            </DialogDescription>
          </DialogHeader>
          <dl className="gws-changes" aria-label="변경 전·후">
            {changes.map(row => <div key={row.field}><dt>{row.label}</dt><dd>{row.before} → {row.after}</dd></div>)}
          </dl>
          {draftValues?.timeout.prompt.action === 'forward' && (
            <p className="gws-warning" role="note">대기 시간을 넘긴 질문은 검사 없이 전송됩니다. 지금 값으로는 약 {chars(draftValues.timeout.prompt.seconds)}자보다 긴 질문은 검사되지 않을 수 있습니다(탐지 서버 처리 시간 기준 · 네트워크·Gateway 추출 시간은 빠짐).</p>
          )}
          {draftValues?.timeout.file.action === 'forward' && (
            <p className="gws-warning" role="note">대기 시간을 넘긴 파일은 검사 없이 전송됩니다. 지금 값으로는 약 {chars(draftValues.timeout.file.seconds)}자보다 긴 파일은 Gateway가 탐지 서버에 보내지 않아 검사되지 않습니다.</p>
          )}
          {stale && <p className="form-error" role="alert">{SETTINGS_CONFLICT_MESSAGE}</p>}
          {save.isError && !isSettingsConflict(save.error) && (
            <p className="form-error" role="alert">저장 실패 · {gatewaySettingsErrorMessage(save.error)}</p>
          )}
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={() => setConfirmOpen(false)}>취소</Button>
            <Button disabled={!canSave} onClick={confirmSave}>{busy ? '저장 중…' : '저장'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
