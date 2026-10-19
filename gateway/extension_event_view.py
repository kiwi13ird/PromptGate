"""Metadata-only client notification. No fabricated severity or administrator proof."""
import re

from gateway_review_link import request_review_url

# 2026-10-10 (확장 프로그램 1.4.2): 사유 코드·내용 종류·알림 표시를 넘긴다. 형식이 틀리면 그 칸만 뺀다
_REASON_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,99}")


def extension_event_view(event):
    if not isinstance(event, dict) or not event.get('clientId'):
        return None
    action = event.get('finalAction')
    if action not in {'BLOCK', 'MASK', 'ALLOW'}:
        return None
    notification = {
        'type': 'SECURITY_EVENT', 'eventId': event.get('eventId'),
        'timestamp': event.get('timestamp'), 'clientId': event['clientId'],
        'targetLlm': event.get('targetLlm', 'Unknown'), 'action': action,
        'actionLabel': {'BLOCK':'차단','MASK':'마스킹','ALLOW':'허용'}[action],
        'detector': 'Gateway', 'matchType': 'POLICY',
        'severityRecorded': False,
    }
    if event.get('severity') in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        notification['severity'] = event['severity']
        notification['severityRecorded'] = True
    for key, allowed in [('detectionOutcome', {'MATCH','NO_MATCH','UNAVAILABLE'}),
                         ('failurePolicy', {'FAIL_OPEN','FAIL_CLOSED'}),
                         ('degradedReason', {'TIMEOUT','UNREACHABLE','PARSE_ERROR','OTHER'}),
                         ('contentType', {'prompt', 'file'})]:
        if event.get(key) in allowed:
            notification[key] = event[key]
    reason_code = event.get('reasonCode')
    if isinstance(reason_code, str) and _REASON_CODE_RE.fullmatch(reason_code):
        notification['reasonCode'] = reason_code
    if type(event.get('degraded')) is bool:
        notification['degraded'] = event['degraded']
    if type(event.get('notify')) is bool:
        notification['notify'] = event['notify']
    request_id = event.get('requestId')
    url = request_review_url(request_id)
    if url:
        notification.update(requestId=request_id, reviewUrl=url, reviewLabel='처리 근거 보기 · 관리자 로그인 필요')
    # 장애(검사 지연·실패)일 때만. 검사할 수 없는 파일·상한 초과(UNAVAILABLE, degraded 아님)에는 맞지 않는 안내라 붙이지 않는다
    if notification.get('degraded'):
        notification['inspectionMessage'] = '보안 검사를 완료하지 못했습니다. 장애 처리 결과를 확인하세요.'
    return notification
