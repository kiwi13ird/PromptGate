import { toast } from '@/components/ui/toast';
import { ApiError } from '@/src/api/errors';

let lastToast = { key: '', at: 0 };
function addOnce(key: string, options: Parameters<typeof toast.add>[0]) {
  const now = Date.now();
  if (lastToast.key === key && now - lastToast.at < 1200) return;
  lastToast = { key, at: now };
  toast.add(options);
}

export const notifySuccess = (title: string, description?: string) =>
  addOnce(`success:${title}`, {
    title,
    description,
    type: 'success',
    timeout: 3500,
  });
export const safeMessage = (error?: unknown) => {
  if (!(error instanceof ApiError)) return '잠시 후 다시 시도해주세요.';
  if (error.code === 'FORBIDDEN') return '이 작업을 수행할 권한이 없습니다.';
  if (error.code === 'CONFLICT')
    return '다른 관리자가 먼저 변경했습니다. 최신 상태를 다시 불러와주세요.';
  if (error.code === 'VALIDATION') return '입력값을 확인해주세요.';
  if (error.code === 'RATE_LIMITED')
    return '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.';
  if (error.code === 'TIMEOUT')
    return '서버 응답 시간이 초과되었습니다. 다시 시도해주세요.';
  if (error.code === 'NETWORK') return '서버에 연결할 수 없습니다. 네트워크나 프록시 설정을 확인해주세요.';
  if (error.code === 'UNAUTHORIZED') return '로그인이 만료되었습니다. 다시 로그인해주세요.';
  return '잠시 후 다시 시도해주세요.';
};
export const notifyError = (error?: unknown) =>
  addOnce(`error:${error instanceof ApiError ? error.code : 'generic'}`, {
    title: '작업을 완료하지 못했습니다.',
    description: safeMessage(error),
    type: 'error',
    priority: 'high',
  });
