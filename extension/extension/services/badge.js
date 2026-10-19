import { ACCESS_STATES, GATEWAY_STATES } from "../config/statuses.js";

// 확장 프로그램 아이콘 배지. 서비스 워커의 setBadge가 쓰던 표시를 그대로 옮겼고(1.4.5), 접속 제한 중이면 '차단'(빨강)으로 바꾼다.
// 차단 표시는 보호 중 상태(ON 계열)에서만 덧씌운다 - 프록시 충돌·연결 실패 등의 '!'와 보호 해제 표시는 그대로 둔다.
const ON_STATES = new Set([GATEWAY_STATES.HEALTHY, GATEWAY_STATES.DEGRADED, GATEWAY_STATES.UNSUPPORTED, GATEWAY_STATES.UNKNOWN]);

export function badgeFor(state, accessState) {
  if (accessState?.status === ACCESS_STATES.BLOCKED && ON_STATES.has(state)) return { text: "차단", color: "#b42318", title: "PromptGate — 사용이 제한되었습니다" };
  return state === GATEWAY_STATES.HEALTHY || state === GATEWAY_STATES.DEGRADED
    ? { text: "ON", color: "#16794a", title: "PromptGate — 보호 중" }
    : state === GATEWAY_STATES.UNSUPPORTED
      ? { text: "ON", color: "#b77900", title: "PromptGate — 보호 중 · 서버 상태 확인 안 됨" }
      : state === GATEWAY_STATES.UNKNOWN
        ? { text: "ON", color: "#667085", title: "PromptGate — 보호 중 · 상태 확인 중" }
        : state === GATEWAY_STATES.DISABLED
          ? { text: "", color: "#000000", title: "PromptGate — 보호 꺼짐" }
          : { text: "!", color: "#b42318", title: "PromptGate — 확인 필요" };
}
