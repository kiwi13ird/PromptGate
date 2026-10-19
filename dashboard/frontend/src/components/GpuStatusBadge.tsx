import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { toast } from '@/components/ui/toast';
import {
  detectionOpsKeys,
  detectionOpsMessage,
  detectionOpsService,
  type GpuStatus,
} from '@/src/services/detectionOpsService';
import { notifySuccess } from '@/src/utils/feedback';
import { formatDateTime } from '@/src/utils/format';
import { uiMode } from '@runtime/ui-mode';
import { PgBadge, type BadgeTone } from '@/src/components/pg';
import '@/src/detection-ops.css';

type Phase = 'connected' | 'booting' | 'starting' | 'stopping' | 'stopped' | 'unreachable';

const PHASE_TEXT: Record<Phase, string> = {
  connected: 'GPU 연결됨',
  booting: 'GPU 모델 준비 중',
  starting: 'GPU 켜는 중',
  stopping: 'GPU 끄는 중',
  stopped: 'GPU 꺼짐',
  unreachable: 'GPU 응답 없음',
};
const TRANSITIONAL: ReadonlySet<Phase> = new Set(['booting', 'starting', 'stopping']);
// 배지 계열(재설계 2단계, 설계 4.4): 연결됨 = 정상 · 준비·켜는·끄는 중 = 진행 · 꺼짐 = 중립(필요할 때 켜짐) · 응답 없음 = 차단(끊김)
const PHASE_TONE: Record<Phase, BadgeTone> = {
  connected: 'allow',
  booting: 'info',
  starting: 'info',
  stopping: 'info',
  stopped: 'neutral',
  unreachable: 'block',
};

function phaseOf(gpu: GpuStatus): Phase {
  if (gpu.connected) return 'connected';
  if (gpu.instance_state === 'pending') return 'starting';
  if (gpu.instance_state === 'running') return 'booting';
  if (gpu.instance_state === 'stopping' || gpu.instance_state === 'shutting-down') return 'stopping';
  if (gpu.instance_state === 'stopped') return 'stopped';
  return 'unreachable';
}

function titleOf(gpu: GpuStatus, phase: Phase) {
  const checked = `확인 ${formatDateTime(gpu.checked_at)}`;
  if (phase === 'connected') return `${gpu.models.join(', ') || '모델 이름 미확인'} · 응답 ${gpu.latency_ms ?? '-'}ms · ${checked}`;
  if (phase === 'booting') return `GPU 서버는 켜졌고 모델을 불러오는 중입니다(켠 뒤 약 2~3분). ${checked}`;
  if (phase === 'starting') return `GPU 서버를 시작하고 있습니다. ${checked}`;
  if (phase === 'stopping') return `GPU 서버를 끄고 있습니다. ${checked}`;
  if (phase === 'stopped') return `GPU 서버가 꺼져 있습니다. 리포트를 만들면 자동으로 켜집니다. ${checked}`;
  return `LLM 서버가 응답하지 않습니다(꺼져 있거나 시작 중). ${checked}`;
}

/**
 * GPU(LLM 서버) 상태. Detection이 대신 확인한 결과를 30초마다(켜고 끄는 중에는 5초마다) 다시 묻는다.
 * 관리자에게는 켜기·끄기 버튼을 보인다 - 켜기는 꺼진 상태에서만, 끄기는 켜진 상태에서만. 자동으로 끄지는 않는다.
 */
export function GpuStatusBadge() {
  const client = useQueryClient();
  const [confirming, setConfirming] = useState<'start' | 'stop' | null>(null);
  const gpu = useQuery({
    queryKey: detectionOpsKeys.gpu(),
    queryFn: ({ signal }) => detectionOpsService.getGpuStatus(signal),
    refetchInterval: query => (query.state.data && TRANSITIONAL.has(phaseOf(query.state.data)) ? 5_000 : 30_000),
    refetchIntervalInBackground: false,
    retry: false,
  });
  const control = useMutation({
    mutationFn: (action: 'start' | 'stop') => detectionOpsService.controlGpu(action),
    onSuccess: (result, action) => {
      setConfirming(null);
      client.setQueryData<GpuStatus>(detectionOpsKeys.gpu(), previous => previous && {
        ...previous, connected: false, models: [], latency_ms: null, instance_state: result.instance_state,
      });
      void client.invalidateQueries({ queryKey: detectionOpsKeys.gpu() });
      if (action === 'start') notifySuccess('GPU를 켜고 있습니다.', '모델이 응답하기까지 약 2~3분 걸립니다. 다 쓰면 끄기를 눌러주세요.');
      else notifySuccess('GPU를 끄고 있습니다.', '리포트를 만들면 자동으로 다시 켜집니다.');
    },
    onError: (error, action) => {
      setConfirming(null);
      void client.invalidateQueries({ queryKey: detectionOpsKeys.gpu() });
      toast.add({
        title: action === 'start' ? 'GPU를 켜지 못했습니다.' : 'GPU를 끄지 못했습니다.',
        description: detectionOpsMessage(error, action === 'start' ? 'gpu-start' : 'gpu-stop'),
        type: 'error',
        priority: 'high',
      });
    },
  });

  if (gpu.isLoading)
    return <PgBadge variant="dot" tone="neutral" aria-live="polite">GPU 확인 중</PgBadge>;
  if (gpu.isError || !gpu.data)
    return (
      <PgBadge variant="dot" tone="neutral" aria-live="polite" title="탐지 서버에서 GPU 상태를 받아오지 못했습니다.">
        GPU 상태 확인 실패
      </PgBadge>
    );
  const phase = phaseOf(gpu.data);
  const { models } = gpu.data;
  const canControl = uiMode.canManagePolicies && gpu.data.controllable === true;
  const action = phase === 'stopped' ? 'start' : gpu.data.instance_state === 'running' ? 'stop' : null;
  return (
    <span className="dops-gpu-control">
      <PgBadge variant="dot" tone={PHASE_TONE[phase]} data-phase={phase} aria-live="polite" title={titleOf(gpu.data, phase)}>
        {PHASE_TEXT[phase]}
        {phase === 'connected' && models[0] && <small>· {models[0]}</small>}
      </PgBadge>
      {canControl && action && (
        <Button size="xs" variant="outline" disabled={control.isPending} onClick={() => setConfirming(action)}>
          {control.isPending ? '요청 중…' : action === 'start' ? 'GPU 켜기' : 'GPU 끄기'}
        </Button>
      )}
      <Dialog open={confirming !== null} onOpenChange={open => !control.isPending && !open && setConfirming(null)}>
        <DialogContent className="admin-dialog console-dialog">
          <DialogHeader>
            <DialogTitle>{confirming === 'start' ? 'GPU를 켜시겠습니까?' : 'GPU를 끄시겠습니까?'}</DialogTitle>
            <DialogDescription>
              {confirming === 'start'
                ? 'GPU 서버를 시작합니다. 모델이 응답하기까지 약 2~3분 걸리고, 켜져 있는 동안 요금이 나옵니다. 자동으로 꺼지지 않으니 다 쓰면 꺼주세요.'
                : '끄면 키워드 추출이 GPU를 다시 켤 때까지 대기합니다. 리포트를 만들면 자동으로 다시 켜집니다. 리포트 생성·키워드 추출이 진행 중이면 끌 수 없습니다.'}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" disabled={control.isPending} onClick={() => setConfirming(null)}>취소</Button>
            <Button disabled={control.isPending} onClick={() => confirming && control.mutate(confirming)}>
              {control.isPending ? '요청 중…' : confirming === 'start' ? '켜기' : '끄기'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </span>
  );
}
