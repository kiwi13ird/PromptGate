"""판정 로그(decisions.jsonl) - /detect 한 건당 한 줄. **판정 기록의 원본**이다.

2026-09-15 구조: 탐지 API는 이 파일에만 쓰고 RDS에는 쓰지 않는다. RDS `decisions`로 옮기는 것은 별도 서비스
`log_shipper`(detection-logshipper.service)가 한다. 그래서 RDS가 느리거나 끊겨도 탐지 응답은 영향이 없고,
기록은 이 파일에 남아 있다가 RDS가 돌아오면 채워진다.

- 열은 DB `decisions`와 같다. `decision_id`(판정마다 새 UUID)가 DB 기본키이고, 전송 서비스가 같은 줄을 다시 보내도
  중복 행이 생기지 않게 한다. `request_id`(Gateway 발급)는 중복될 수 있다.
- `ts`는 요청을 받은 시각(유닉스 초).
- 원문(prompt)이 들어가므로 파일 권한 0600.
- 한 줄은 잠금 안에서 한 번의 write로 쓰고 flush한다 - 전송 서비스는 줄바꿈으로 끝난 줄만 읽으므로 반쯤 쓴 줄을
  읽지 않는다. 프로세스가 죽어도 write가 끝난 줄은 OS에 넘어가 있다(인스턴스 전원 차단은 대상 밖).
- 회전: MAX_BYTES에 닿으면 decisions.jsonl.1 … .{BACKUPS} 로 이름을 밀어낸다. 이름만 바뀌고 파일 식별자(inode)는
  유지되므로 전송 서비스가 옛 파일을 끝까지 따라가 읽는다.
- 쓰기 실패는 응답을 막지 않는다(경고 로그).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("detection.decision_log")

DEFAULT_PATH = Path(os.environ.get("DETECTION_LOG_DIR", "/opt/detection/logs")) / "decisions.jsonl"
MAX_BYTES = 50 * 1024 * 1024
BACKUPS = 9

# DB decisions 표와 같은 열(prompt_kept 제외). 로그 한 줄도 이 순서로 쓴다.
COLUMNS = ("decision_id", "request_id", "ts", "service", "format", "text_chars", "blocked", "decided_by", "doc_id",
           "doc_span", "input_span", "score", "pii_hits", "reason", "hash_status", "signature_status", "total_ms",
           "prompt")


def ordered(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record.get(k) for k in COLUMNS}


def rotated_path(path: Path, i: int) -> Path:
    return path.with_name(f"{path.name}.{i}")


class DecisionLog:
    def __init__(self, path: Path | str = DEFAULT_PATH, *, max_bytes: int = MAX_BYTES, backups: int = BACKUPS):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> bool:
        line = (json.dumps(ordered(record), ensure_ascii=False) + "\n").encode("utf-8")
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed()
                new = not self.path.exists()
                with self.path.open("ab") as f:
                    f.write(line)
                    f.flush()
                if new:
                    try:
                        os.chmod(self.path, 0o600)
                    except OSError:
                        pass
            return True
        except Exception as exc:  # 로그는 응답을 막지 않는다
            log.warning("decision log write failed: %s", exc)
            return False

    def _rotate_if_needed(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        oldest = rotated_path(self.path, self.backups)
        if oldest.exists():
            oldest.unlink()
        for i in range(self.backups - 1, 0, -1):
            src = rotated_path(self.path, i)
            if src.exists():
                src.rename(rotated_path(self.path, i + 1))
        self.path.rename(rotated_path(self.path, 1))
