"""Gateway 처리 설정(2026-10-10): 검사 지연·검사할 수 없는 파일·허용 알림.

대시보드가 저장한 설정 문서를 지표 전송(10초 주기) 응답의 gateway_settings 칸으로 받아 적용한다.
검증 규칙은 대시보드 백엔드 gateway-settings.mjs(parseGatewaySettings)·환경변수와 같다.
  - 칸이 정확히 같을 것(모르는 칸·빠진 칸 거부)
  - 대기 시간: 수(bool 제외)·유한·0.05~30초. 소수 자리 규칙 없음(0.125 통과)
  - 틀리면 칸 경로(timeout.file.seconds 등)를 담은 SettingsError(ValueError)

예비값 순서: 대시보드에서 받은 값 → (재시작 후) 디스크 사본 → 환경변수 기본값.
쓰는 쪽은 지표 작업 스레드 하나(offer 안 잠금), 읽는 쪽(mitmproxy 이벤트 루프)은 current()로 참조 하나만 읽는다.
GatewaySettings는 frozen이고 안쪽도 바꿀 수 없는 값만 들고 있어 한 판 전체가 늘 일관된다.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

# 실측 최악 속도(ms/천 자, 2026-09-10~10-09 판정 기록). 배포 전 왕복 측정(명세 §1.3)으로만 바꾼다.
# 대시보드 화면(src/constants/detectionSpeed.ts)도 같은 값을 쓴다.
DETECTION_WORST_MS_PER_1K_CHARS = 24.8
MIN_SECONDS = 0.05
MAX_SECONDS = 30.0
DEFAULT_FILE_MAX_BYTES = 20 * 1024 * 1024
MAX_SAFE_INTEGER = 2 ** 53 - 1

SETTINGS_FIELDS = ("timeout", "uninspectable", "notify_on_allow")
DOCUMENT_FIELDS = ("version", "revision", "updated_at", "updated_by") + SETTINGS_FIELDS
TIMEOUT_KINDS = ("prompt", "file")
TIMEOUT_ACTIONS = ("block", "forward")
UNINSPECTABLE_GROUPS = ("image", "scanned_pdf", "other")
UNINSPECTABLE_ACTIONS = ("block", "allow")
SOURCES = ("ENV_DEFAULT", "CACHE", "DASHBOARD")

REVISION_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FIELD_RE = re.compile(r"^[a-z_.]{1,100}$")
# 대시보드는 toISOString() 값(2026-10-10T05:12:00.000Z)을 준다. 시간대 없는 값은 받지 않는다
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$")
DOCUMENT_FIELD = "gateway_settings"   # 문서 전체 모양이 틀렸을 때 거부 칸 이름


class SettingsError(ValueError):
    """field = 틀린 칸 경로. 대시보드 rejected.field·details.path와 같은 이름."""

    def __init__(self, field: str):
        super().__init__(field)
        self.field = field if FIELD_RE.fullmatch(field or "") else DOCUMENT_FIELD


@dataclass(frozen=True)
class TimeoutRule:
    action: str     # block | forward
    seconds: float

    @property
    def failure_policy(self) -> str:
        # detection_client.check(failure_policy=)와 같은 이름
        return "FAIL_CLOSED" if self.action == "block" else "FAIL_OPEN"


@dataclass(frozen=True)
class GatewaySettings:
    prompt: TimeoutRule
    file: TimeoutRule
    image: str
    scanned_pdf: str
    other: str
    notify_on_allow: bool
    version: int = 0
    revision: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None
    source: str = "ENV_DEFAULT"
    applied_at: str | None = None

    def timeout_for(self, kind: str) -> TimeoutRule:
        """질문은 질문 규칙, 그 밖(파일·모르는 종류)은 더 엄격한 파일 규칙."""
        return self.prompt if kind == "prompt" else self.file

    def uninspectable_action(self, group: str) -> str:
        """'block' | 'allow'. 모르는 그룹은 기타 규칙."""
        return {"image": self.image, "scanned_pdf": self.scanned_pdf}.get(group, self.other)

    def effective(self) -> dict:
        """§1.1 설정 칸 3개(대시보드 parseGatewaySettings가 받는 모양)."""
        return {
            "timeout": {
                "prompt": {"action": self.prompt.action, "seconds": self.prompt.seconds},
                "file": {"action": self.file.action, "seconds": self.file.seconds},
            },
            "uninspectable": {"image": self.image, "scanned_pdf": self.scanned_pdf, "other": self.other},
            "notify_on_allow": self.notify_on_allow,
        }

    def document(self) -> dict:
        """대시보드 문서 모양(칸 7개). 디스크 사본에 쓴다."""
        return {"version": self.version, "revision": self.revision, "updated_at": self.updated_at,
                "updated_by": self.updated_by, **self.effective()}

    @property
    def key(self) -> tuple:
        return (self.version, self.revision)


def file_max_chars(seconds: float) -> int:
    """대기 시간 안에 Detection이 끝낼 수 있는 글자 수(실측 최악 속도 기준). 2.0초 = 80,645자."""
    return math.floor(seconds * 1_000_000 / DETECTION_WORST_MS_PER_1K_CHARS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ------------------------------------------------------------------ 검증 (gateway-settings.mjs와 같은 순서)

def _exact(value, fields, path):
    if not isinstance(value, dict):
        raise SettingsError(path)
    if len(value) != len(fields) or any(key not in fields for key in value):
        raise SettingsError(path)
    return value


def _choice(value, allowed, path):
    if not isinstance(value, str) or value not in allowed:
        raise SettingsError(path)
    return value


def _seconds(value, path):
    if type(value) not in (int, float) or not math.isfinite(value) or not MIN_SECONDS <= value <= MAX_SECONDS:
        raise SettingsError(path)
    return float(value)


def parse_settings_fields(value, path: str = "") -> dict:
    """설정 칸 3개(timeout·uninspectable·notify_on_allow)를 검사해 같은 모양으로 돌려준다.

    칸 모양을 먼저 모두 본 뒤 값을 본다(백엔드와 같은 순서라 같은 입력이면 같은 칸 이름을 낸다).
    """
    def at(name):
        return f"{path}.{name}" if path else name

    body = _exact(value, SETTINGS_FIELDS, path or DOCUMENT_FIELD)
    timeout = _exact(body["timeout"], TIMEOUT_KINDS, at("timeout"))
    for kind in TIMEOUT_KINDS:
        _exact(timeout[kind], ("action", "seconds"), at(f"timeout.{kind}"))
    uninspectable = _exact(body["uninspectable"], UNINSPECTABLE_GROUPS, at("uninspectable"))
    rules = {}
    for kind in TIMEOUT_KINDS:
        rules[kind] = {
            "action": _choice(timeout[kind]["action"], TIMEOUT_ACTIONS, at(f"timeout.{kind}.action")),
            "seconds": _seconds(timeout[kind]["seconds"], at(f"timeout.{kind}.seconds")),
        }
    groups = {group: _choice(uninspectable[group], UNINSPECTABLE_ACTIONS, at(f"uninspectable.{group}"))
              for group in UNINSPECTABLE_GROUPS}
    if type(body["notify_on_allow"]) is not bool:
        raise SettingsError(at("notify_on_allow"))
    return {"timeout": rules, "uninspectable": groups, "notify_on_allow": body["notify_on_allow"]}


def _from_fields(fields: dict, **meta) -> GatewaySettings:
    return GatewaySettings(
        prompt=TimeoutRule(**fields["timeout"]["prompt"]),
        file=TimeoutRule(**fields["timeout"]["file"]),
        notify_on_allow=fields["notify_on_allow"],
        **fields["uninspectable"],
        **meta,
    )


def parse_settings(document, *, source: str = "DASHBOARD", applied_at: str | None = None) -> GatewaySettings:
    """대시보드 설정 문서(§1.1, 칸 7개) → GatewaySettings. 틀리면 SettingsError(칸 경로)."""
    doc = _exact(document, DOCUMENT_FIELDS, DOCUMENT_FIELD)
    version = doc["version"]
    if type(version) is not int or not 1 <= version <= MAX_SAFE_INTEGER:
        raise SettingsError("version")
    revision = doc["revision"]
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise SettingsError("revision")
    updated_at = doc["updated_at"]
    if not isinstance(updated_at, str) or len(updated_at) > 50 or not _ISO_RE.fullmatch(updated_at):
        raise SettingsError("updated_at")
    updated_by = doc["updated_by"]
    if not isinstance(updated_by, str) or not 1 <= len(updated_by) <= 200:
        raise SettingsError("updated_by")
    fields = parse_settings_fields({name: doc[name] for name in SETTINGS_FIELDS})
    return _from_fields(fields, version=version, revision=revision, updated_at=updated_at,
                        updated_by=updated_by, source=source, applied_at=applied_at or _now_iso())


def _rejected_key(document) -> tuple:
    """거부 보고의 version·revision: 그 칸 자체가 틀렸으면 None(대시보드 nullableVersion·nullableRevision)."""
    if not isinstance(document, dict):
        return (None, None)
    version = document.get("version")
    revision = document.get("revision")
    return (
        version if type(version) is int and 0 <= version <= MAX_SAFE_INTEGER else None,
        revision if isinstance(revision, str) and REVISION_RE.fullmatch(revision) else None,
    )


# ------------------------------------------------------------------ 환경변수 기본값

_ENV_NAMES = {
    "timeout.prompt.action": "DETECTION_FAILURE_POLICY",
    "timeout.prompt.seconds": "DETECTION_TIMEOUT_SECONDS",
    "timeout.file.action": "GATEWAY_FILE_TIMEOUT_ACTION",
    "timeout.file.seconds": "GATEWAY_FILE_TIMEOUT_SECONDS",
    "uninspectable.image": "GATEWAY_UNINSPECTABLE_IMAGE",
    "uninspectable.scanned_pdf": "GATEWAY_UNINSPECTABLE_SCANNED_PDF",
    "uninspectable.other": "GATEWAY_UNINSPECTABLE_OTHER",
    "notify_on_allow": "GATEWAY_NOTIFY_ON_ALLOW",
}


def _env_number(env, name, default):
    raw = env.get(name)
    raw = default if raw is None or not raw.strip() else raw.strip()
    try:
        return float(raw)
    except ValueError:
        raise ValueError(f"{name} must be numeric") from None


def env_defaults(environ=None) -> GatewaySettings:
    """환경변수 기본값(대시보드에서 받은 적 없을 때). 값이 틀리면 ValueError(시작 실패, 조용히 허용하지 않음).

    질문 규칙은 기존 DETECTION_FAILURE_POLICY·DETECTION_TIMEOUT_SECONDS(detection_client.py)를 그대로 읽는다.
    """
    env = os.environ if environ is None else environ
    policy = (env.get("DETECTION_FAILURE_POLICY") or "FAIL_OPEN").strip().upper()
    if policy not in {"FAIL_OPEN", "FAIL_CLOSED"}:
        raise ValueError("DETECTION_FAILURE_POLICY must be FAIL_OPEN or FAIL_CLOSED")
    notify = (env.get("GATEWAY_NOTIFY_ON_ALLOW") or "false").strip().lower()
    if notify not in {"true", "false"}:
        raise ValueError("GATEWAY_NOTIFY_ON_ALLOW must be true or false")
    body = {
        "timeout": {
            "prompt": {"action": "block" if policy == "FAIL_CLOSED" else "forward",
                       "seconds": _env_number(env, "DETECTION_TIMEOUT_SECONDS", "0.5")},
            "file": {"action": (env.get("GATEWAY_FILE_TIMEOUT_ACTION") or "block").strip().lower(),
                     "seconds": _env_number(env, "GATEWAY_FILE_TIMEOUT_SECONDS", "2.0")},
        },
        "uninspectable": {
            "image": (env.get("GATEWAY_UNINSPECTABLE_IMAGE") or "allow").strip().lower(),
            "scanned_pdf": (env.get("GATEWAY_UNINSPECTABLE_SCANNED_PDF") or "block").strip().lower(),
            "other": (env.get("GATEWAY_UNINSPECTABLE_OTHER") or "block").strip().lower(),
        },
        "notify_on_allow": notify == "true",
    }
    try:
        fields = parse_settings_fields(body)
    except SettingsError as exc:
        raise ValueError(f"{_ENV_NAMES.get(exc.field, exc.field)} is invalid") from None
    return _from_fields(fields, source="ENV_DEFAULT")


def file_max_bytes_from_env(environ=None) -> int:
    env = os.environ if environ is None else environ
    raw = (env.get("GATEWAY_FILE_MAX_BYTES") or "").strip()
    if not raw:
        return DEFAULT_FILE_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        raise ValueError("GATEWAY_FILE_MAX_BYTES must be an integer") from None
    if value < 1:
        raise ValueError("GATEWAY_FILE_MAX_BYTES must be positive")
    return value


def cache_path_from_env(default_dir, environ=None) -> Path:
    env = os.environ if environ is None else environ
    configured = (env.get("GATEWAY_SETTINGS_CACHE_PATH") or "").strip()
    return Path(configured) if configured else Path(default_dir) / "var" / "gateway-settings.json"


# ------------------------------------------------------------------ 보관

def _weakened_fields(before: GatewaySettings, after: GatewaySettings) -> list[str]:
    """보호가 약해지는 칸 이름만(값은 로그에 남기지 않는다)."""
    fields = []
    for kind in TIMEOUT_KINDS:
        old, new = before.timeout_for(kind), after.timeout_for(kind)
        if old.action == "block" and new.action == "forward":
            fields.append(f"timeout.{kind}.action")
        if new.action == "forward" and new.seconds < old.seconds:
            fields.append(f"timeout.{kind}.seconds")
    for group in UNINSPECTABLE_GROUPS:
        if before.uninspectable_action(group) == "block" and after.uninspectable_action(group) == "allow":
            fields.append(f"uninspectable.{group}")
    return fields


class SettingsHolder:
    """지표 응답으로 받은 설정을 들고 있다. 쓰기는 offer(지표 작업 스레드), 읽기는 current()."""

    _REJECT_LOG_KEYS = 64

    def __init__(self, defaults: GatewaySettings, *, cache_path=None, metrics_url: str | None = None,
                 logger=print):
        self._defaults = replace(defaults, source="ENV_DEFAULT", version=0, revision=None,
                                 updated_at=None, updated_by=None)
        self._cache_path = Path(cache_path) if cache_path else None
        # 사본은 같은 대시보드 주소에서 받은 것만 쓴다(가짜 대시보드로 시험한 사본이 운영 재시작에 쓰이지 않게)
        self._url_hash = hashlib.sha256(metrics_url.encode("utf-8")).hexdigest() if metrics_url else None
        self._logger = logger
        self._lock = threading.Lock()
        self._current = replace(self._defaults, applied_at=_now_iso())
        self._rejected = None
        self._rejected_logged: list[tuple] = []
        self._saw_field = False          # 2xx 응답에서 gateway_settings 칸을 본 적이 있음
        self._include_report = False     # 다음 지표에 settings_applied를 실음
        self._last_report_sent = False
        self._on_change = None
        self._load_cache()
        self._log(f"[SETTINGS] source={self._current.source} version={self._current.version}")

    # -- 읽기 (잠금 없음, 참조 하나)
    def current(self) -> GatewaySettings:
        return self._current

    def set_on_change(self, callback) -> None:
        self._on_change = callback

    def _log(self, message: str) -> None:
        try:
            self._logger(message)
        except Exception:
            pass

    # -- 디스크 사본
    def _load_cache(self) -> None:
        path = self._cache_path
        if path is None or self._url_hash is None:
            return
        try:
            if not path.exists():
                return
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("metrics_url_sha256") != self._url_hash:
                self._log("[SETTINGS] cache ignored reason=other_dashboard")
                return
            settings = parse_settings(raw.get("document"), source="CACHE")
        except SettingsError as exc:
            self._log(f"[SETTINGS] cache ignored reason=invalid field={exc.field}")
            return
        except (OSError, ValueError, TypeError) as exc:
            self._log(f"[SETTINGS] cache ignored reason={type(exc).__name__}")
            return
        self._current = settings

    def _save_cache(self, settings: GatewaySettings) -> None:
        path = self._cache_path
        if path is None or self._url_hash is None:
            return
        temporary = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
            data = json.dumps({"metrics_url_sha256": self._url_hash, "document": settings.document()},
                              ensure_ascii=False, separators=(",", ":"))
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            temporary = None
        except Exception as exc:
            self._log(f"[SETTINGS] cache write failed error_type={type(exc).__name__}")
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _remove_cache(self) -> None:
        path = self._cache_path
        if path is None:
            return
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            self._log(f"[SETTINGS] cache remove failed error_type={type(exc).__name__}")

    # -- 지표 응답 처리
    def offer(self, payload) -> None:
        """지표 전송 2xx 응답 본문. gateway_settings 칸이 없으면 아무것도 안 함(옛 대시보드·설정을 아직 못 읽음)."""
        if not isinstance(payload, dict) or "gateway_settings" not in payload:
            return
        document = payload["gateway_settings"]
        changed = False
        with self._lock:
            self._saw_field = True
            self._include_report = True
            current = self._current
            if document is None:
                # 대시보드에 저장된 설정 없음 → 환경변수 기본값, 디스크 사본 삭제
                if current.source != "ENV_DEFAULT":
                    self._current = replace(self._defaults, applied_at=_now_iso())
                    changed = True
                    self._log("[SETTINGS] applied source=ENV_DEFAULT version=0")
                self._remove_cache()
            else:
                try:
                    parsed = parse_settings(document, source="DASHBOARD")
                except SettingsError as exc:
                    version, revision = _rejected_key(document)
                    self._rejected = {"version": version, "revision": revision, "field": exc.field}
                    key = (version, revision, exc.field)
                    if key not in self._rejected_logged:   # 같은 문서가 10초마다 다시 와도 한 번만
                        self._rejected_logged = (self._rejected_logged + [key])[-self._REJECT_LOG_KEYS:]
                        self._log(f"[SETTINGS] rejected version={version} field={exc.field}")
                    return
                if parsed.key == current.key and current.source != "ENV_DEFAULT":
                    if current.source == "CACHE":   # 재시작 후 사본과 같은 판을 대시보드가 확인
                        self._current = replace(current, source="DASHBOARD")
                    return
                # "다르면 교체"(크면이 아님): DB를 되돌려 번호가 작아져도 따라간다
                weakened = _weakened_fields(current, parsed)
                self._current = parsed
                self._save_cache(parsed)
                changed = True
                self._log(f"[SETTINGS] applied version={parsed.version}")
                if weakened:
                    self._log(f"[SETTINGS] weakened fields={','.join(weakened)}")
        if changed and self._on_change is not None:
            try:
                self._on_change()   # 다음 지표를 바로 보내 반영 보고를 앞당긴다
            except Exception:
                pass

    def on_metrics_status(self, http_status) -> None:
        """settings_applied를 실은 전송이 400이면(옛 대시보드: 모르는 칸) 다음부터 뺀다. 칸이 다시 오면 다시 싣는다."""
        if http_status == 400:
            with self._lock:
                if self._last_report_sent and self._include_report:
                    self._include_report = False
                    self._log("[SETTINGS] report omitted after HTTP 400")

    def report(self) -> dict:
        """§3.3 settings_applied."""
        current = self._current
        rejected = self._rejected
        return {
            "version": current.version,
            "revision": current.revision,
            "source": current.source,
            "applied_at": current.applied_at,
            "rejected": dict(rejected) if rejected else None,
            "effective": current.effective(),
        }

    def report_field(self) -> dict:
        """지표 전송기 전용. 2xx 응답에서 gateway_settings 칸을 본 뒤에만 싣는다(옛 대시보드는 모르는 칸이면 지표 전체를 400)."""
        with self._lock:
            include = self._saw_field and self._include_report
            self._last_report_sent = include
            return {"settings_applied": self.report()} if include else {}
