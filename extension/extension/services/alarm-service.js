import { ACCESS_STATUS_ALARM, ACCESS_STATUS_PERIOD_MINUTES, HEALTH_ALARM, HEALTH_PERIOD_MINUTES } from "../config/defaults.js";

export async function ensureHealthAlarm(alarms = chrome.alarms) {
  const existing = await alarms.get(HEALTH_ALARM);
  if (existing && existing.periodInMinutes === HEALTH_PERIOD_MINUTES) return false;
  await alarms.create(HEALTH_ALARM, { delayInMinutes: HEALTH_PERIOD_MINUTES, periodInMinutes: HEALTH_PERIOD_MINUTES });
  return true;
}

// 1.4.5: 접속 제한 상태 조회 알람(1분). 보호가 꺼져 있으면 알람이 울려도 조회하지 않는다(조회 쪽에서 확인)
export async function ensureAccessStatusAlarm(alarms = chrome.alarms) {
  const existing = await alarms.get(ACCESS_STATUS_ALARM);
  if (existing && existing.periodInMinutes === ACCESS_STATUS_PERIOD_MINUTES) return false;
  await alarms.create(ACCESS_STATUS_ALARM, { delayInMinutes: ACCESS_STATUS_PERIOD_MINUTES, periodInMinutes: ACCESS_STATUS_PERIOD_MINUTES });
  return true;
}
