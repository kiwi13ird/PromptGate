"""HWP·HWPX 파싱 (보호 문서 등록 경로, 2026-10-11 명세 masking-design/SPEC.md §2.2).

글자 추출은 공통 모듈 hwpdoc(Gateway와 같은 파일)이 하고, 여기서는 본문 배치(body_layout = body_lines와 같은 순서)를
블록으로 바꾼다. 부가 글자(요약 정보·개체 설명문·필드·수식·HWPX 메타·바탕쪽)는 등록하지 않는다 - 같은 양식 문서끼리
겹치는 글자라 색인하면 본문이 무관한 문서까지 차단된다(2026-10-11 검토 지적 1: 팀 HWP 하나만 등록한 순서쌍 272개 중
거짓 차단 170). Gateway는 부가 글자까지 넣은 lines()로 검사한다(lines() = body_lines() + 부가 글자 줄).
  본문 문단 줄 → {"type": "paragraph", "text": …}
  표 행        → 한 행짜리 {"type": "table", "rows": [[칸 글자, …]]}
build_index가 표 행을 ' | '로, 블록을 '\\n'으로 이으므로 등록 글자는 '\\n'.join(body_lines())로 시작하고, 이 압축열은
Gateway가 보내는 '\\n'.join(lines()) 압축열의 앞부분이다.

레코드 순서 보충: lines()는 칸 안의 중첩 표를 그 행 뒤로 옮기므로, 한컴에서 레코드(요소) 순서로 복사한 짧은 발췌가
중첩 표 경계를 걸치면 그 창이 등록 색인에 없을 수 있다(팀 HWP 2/19). 그래서 레코드 순서 본문(paragraph_text)의 창 중
본문 배치(body_lines) 창에 없는 것만 덮는 최소 조각을 같은 문서 글자 끝에 문단 블록으로 덧붙인다. 순서가 같은 문서는
덧붙이는 것이 없어 등록 글자 = 본문 줄 그대로다. Gateway·hwpdoc 배치는 바꾸지 않는다(업로드 검사 글자의 본문 창은 모두
색인에 있음).

예외 변환(preprocessing/errors.py)
  암호·배포용·DRM(HwpUnsupported kind ∈ ENCRYPTED_KINDS) → EncryptedDocumentError
  그 밖 HwpUnsupported(kind를 사유에), olefile·lxml 없음, 본문 글자 없음 → DocumentParsingError
  HwpCorrupt·HwpTooLarge                                   → CorruptedDocumentError

이 모듈은 /detect 기동 경로에서 import하지 않는다 - router·pipeline이 함수 안에서 부른다.
"""

from __future__ import annotations

from pathlib import Path

from . import hwpdoc
from .errors import CorruptedDocumentError, DocumentParsingError, EncryptedDocumentError

# 압축을 푼 크기 상한(대시보드 등록 상한 20MiB와 같은 값, 명세 §2.2)
MAX_DECOMPRESSED = 20 * 1024 * 1024

_ENCRYPTED_MESSAGES = {
    "hwp_encrypted": "암호가 걸린 HWP 문서입니다 - 암호를 푼 사본으로 등록하세요",
    "hwp_distribution": "배포용 HWP 문서입니다(본문이 암호화됨) - 편집용 원본으로 등록하세요",
    "hwp_drm": "DRM·인증서 보안이 걸린 HWP 문서입니다 - 보안을 푼 사본으로 등록하세요",
    "hwpx_encrypted": "암호가 걸린 HWPX 문서입니다 - 암호를 푼 사본으로 등록하세요",
}
_UNSUPPORTED_MESSAGES = {
    "hwp_history": "문서 이력이 저장된 HWP입니다(이전 판 글자를 검사할 수 없음) - 이력을 지운 사본으로 등록하세요",
    "hwp_unsupported_object": "검사할 수 없는 개체(OLE·차트·글맵시·양식·컨트롤 데이터 등)가 든 HWP입니다",
    "hwpx_unknown_text": "검사 범위 밖 위치에 글자가 든 HWPX입니다",
    "hwpx_unsupported_object": "검사할 수 없는 개체(OLE·차트·글맵시·양식 등)가 든 HWPX입니다",
}


def parse_hwp(path: str | Path) -> list[dict]:
    return _parse(path, "HWP")


def parse_hwpx(path: str | Path) -> list[dict]:
    return _parse(path, "HWPX")


def _parse(path: str | Path, label: str) -> list[dict]:
    data = Path(path).read_bytes()
    try:
        doc = hwpdoc.read(data, max_decompressed=MAX_DECOMPRESSED)
    except ImportError as exc:
        raise DocumentParsingError(f"{label} 해석 패키지가 설치되지 않았습니다({exc.name or exc})") from None
    except hwpdoc.HwpUnsupported as exc:
        if exc.kind in hwpdoc.ENCRYPTED_KINDS:
            raise EncryptedDocumentError(f"{_ENCRYPTED_MESSAGES.get(exc.kind, exc.kind)} ({exc.kind})") from None
        message = _UNSUPPORTED_MESSAGES.get(exc.kind, f"지원하지 않는 {label} 구성입니다")
        raise DocumentParsingError(f"{message} ({exc})") from None
    except hwpdoc.HwpTooLarge as exc:
        raise CorruptedDocumentError(f"{label} 문서가 처리 상한(압축을 푼 크기 {MAX_DECOMPRESSED // (1024 * 1024)}MiB와 "
                                     f"그에 비례한 문단·표 칸·XML 요소 수)을 넘습니다 ({exc})") from None
    except hwpdoc.HwpCorrupt as exc:
        raise CorruptedDocumentError(f"손상된 {label} 파일입니다 ({exc})") from None

    if not any(p.text.strip() for p in doc.paragraphs):
        # 요약 정보·메타데이터 같은 부가 글자만으로는 등록하지 않는다(문서 고유 글자가 아님)
        what = "그림만 있는" if doc.media else "빈"
        raise DocumentParsingError(f"본문 글자가 없는 {label} 문서입니다({what} 문서)")
    blocks: list[dict] = []
    for item in doc.body_layout():
        if isinstance(item, list):
            blocks.append({"type": "table", "rows": [item]})
        else:
            blocks.append({"type": "paragraph", "text": item})
    for piece in record_order_supplement(doc, blocks):
        blocks.append({"type": "paragraph", "text": piece})
    return blocks


def _blocks_text(blocks: list[dict]) -> str:
    """블록을 build_index처럼 이은 글자(표 행은 ' | ', 블록은 '\\n') - 창 비교용."""
    return "\n".join(b["text"] if "text" in b else "\n".join(" | ".join(row) for row in b["rows"]) for b in blocks)


def record_order_supplement(doc, blocks: list[dict]) -> list[str]:
    """레코드 순서 본문(paragraph_text)의 창 중 blocks(등록 배치) 글자에 없는 창을 모두 덮는 최소 조각(정규화된 글자,
    문서 순서). 빠진 창이 이어진 구간 [i, j]마다 압축 위치 i ~ j+창-1의 원문 조각 하나, 조각끼리 겹치거나 맞닿으면 합친다.
    창 계산은 탐지 색인과 같은 함수(windowhash.hashing)로 한다. 순서가 같은 문서는 빈 목록.
    """
    from windowhash.hashing import WINDOW, compact, window_hashes  # noqa: PLC0415 - HWP 등록 경로에서만

    from .normalizer import normalize_text  # noqa: PLC0415

    record = normalize_text(doc.paragraph_text())
    comp = compact(record)
    hashes = window_hashes(comp.codes)
    if not hashes:
        return []
    have = set(window_hashes(compact(normalize_text(_blocks_text(blocks))).codes))
    runs: list[list[int]] = []                  # 빠진 창 시작 위치 구간 [i, j]
    for i, h in enumerate(hashes):
        if h in have:
            continue
        if runs and i <= runs[-1][1] + WINDOW:  # 앞 조각과 글자가 겹치거나 맞닿음 → 합침
            runs[-1][1] = i
        else:
            runs.append([i, i])
    return [record[comp.offsets[i]:comp.offsets[j + WINDOW - 1] + 1] for i, j in runs]
