import { SECURITY_EVENT_LIMIT } from "../config/defaults.js";
import { STORAGE_KEYS } from "../config/statuses.js";
import { normalizeSecurityEvent } from "./event-validator.js";

export function normalizeStoredSecurityEvents(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const normalized = [];
  for (const candidate of value) {
    const event = normalizeSecurityEvent(candidate);
    if (!event || seen.has(event.eventId)) continue;
    seen.add(event.eventId);
    normalized.push(event);
    if (normalized.length >= SECURITY_EVENT_LIMIT) break;
  }
  return normalized;
}

export async function storeSecurityEvent(event, storage = chrome.storage.local) {
  const normalized = normalizeSecurityEvent(event);
  if (!normalized) return { stored: false, reason: "INVALID", events: [] };
  const raw = await storage.get([STORAGE_KEYS.RECENT_SECURITY_EVENTS]);
  const current = normalizeStoredSecurityEvents(raw[STORAGE_KEYS.RECENT_SECURITY_EVENTS]);
  if (current.some((saved) => saved.eventId === normalized.eventId)) return { stored: false, reason: "DUPLICATE", events: current };
  const events = [normalized, ...current].slice(0, SECURITY_EVENT_LIMIT);
  await storage.set({ [STORAGE_KEYS.RECENT_SECURITY_EVENTS]: events });
  return { stored: true, event: normalized, events };
}

export async function clearSecurityEvents(storage = chrome.storage.local) {
  await storage.set({ [STORAGE_KEYS.RECENT_SECURITY_EVENTS]: [] });
}
