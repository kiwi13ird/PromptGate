"""FR-PRE-001 자연어 정규화 결과를 직접 확인/저장하기 위한 CLI.

문서 파싱(cli.py)과 달리 이 스크립트는 PDF/DOCX 파서를 거치지 않는 순수 자연어 입력
경로를 다룬다. 게이트웨이에서 "자연어"로 분류된 입력(FR-GW-005)은 문서별 파서를 거칠
필요 없이 곧바로 정규화 모듈(FR-PRE-001)로만 들어가기 때문에, normalizer.normalize_text()
하나만 놓고 결과를 눈으로 확인/저장하는 용도다.

사용법:
    python -m preprocessing.normalize_cli --text "확인하고 싶은 문장"
    python -m preprocessing.normalize_cli --file 어떤_텍스트파일.txt
    python -m preprocessing.normalize_cli --demo
        (macOS/Windows/Notion 등 서로 다른 환경에서 작성된 것처럼 흉내낸 동일 문장의
         변형들을 정규화해, FR-PRE-001 검증 기준대로 결과가 모두 같은지 확인한다)

결과는 항상 파일로 저장된다 (기본: src/preprocessing/outputs/ 아래, --out으로 경로 지정 가능).
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.indexer import build_offset_map, tokenize_words
from preprocessing.normalizer import normalize_text

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "outputs"

_ZWSP = "​"
_NBSP = " "
_IDEOGRAPHIC_SPACE = "　"
_LEFT_DOUBLE_QUOTE = "“"
_RIGHT_DOUBLE_QUOTE = "”"
_EN_DASH = "–"


def demo_variants() -> list[dict]:
    """같은 문장을 서로 다른 작성 환경에서 만든 것처럼 흉내낸 변형들을 만든다.

    FR-PRE-001 검증 기준: "동일한 내용을 서로 다른 환경에서 작성한 입력에 대해
    정규화 결과가 동일해야 한다" - 아래 변형들은 전부 "같은 문장"이다. 환경마다
    인코딩/기호/공백 표기만 다르게 흉내낸 것이지 단어 자체가 달라지면 애초에
    비교 대상이 아니므로, 여기서 단어 구성은 절대 바꾸지 않는다.
    """
    base = '본 문서는 "대외비" 문서이며, 외부 유출 - 특히 이메일 첨부 - 을 금지합니다.'

    variants = [
        {"label": "기준 문장", "raw": base},
        {
            # 한글이 자모 분리형(NFD)으로 저장됨 - 화면엔 똑같이 보이지만
            # 코드포인트 수준에서는 Windows/DOCX(NFC)와 다르다.
            "label": "macOS 스타일 (NFD 자모 분리)",
            "raw": unicodedata.normalize("NFD", base),
        },
        {
            # Word/DOCX 자동고침: 곧은 따옴표 -> 스마트 따옴표, "공백-하이픈-공백"
            # -> en dash. 문단 앞 탭 들여쓰기까지 얹어 문서 서식도 흉내낸다.
            "label": "Windows/DOCX 스타일 (자동고침 스마트따옴표/en dash + 탭)",
            "raw": (
                "\t"
                + base.replace('"', _LEFT_DOUBLE_QUOTE, 1)
                .replace('"', _RIGHT_DOUBLE_QUOTE, 1)
                .replace(" - ", f" {_EN_DASH} ")
            ),
        },
        {
            # Notion도 따옴표를 스마트 기호로 자동 치환하며, 문단 앞에 NBSP가
            # 섞여 들어오는 경우가 흔하다.
            "label": "Notion 스타일 (스마트따옴표 + NBSP 혼입)",
            "raw": base.replace("본", f"본{_NBSP}", 1)
            .replace('"', _LEFT_DOUBLE_QUOTE, 1)
            .replace('"', _RIGHT_DOUBLE_QUOTE, 1),
        },
        {
            # 다른 문서/웹페이지에서 복사-붙여넣기 할 때 흔히 섞여 들어오는 비가시 문자.
            "label": "복사-붙여넣기 노이즈 (제로폭공백/NBSP/전각공백 혼입)",
            "raw": base.replace("대외비", f"대외비{_ZWSP}", 1)
            .replace(" ", _NBSP, 1)
            .replace("유출", f"유출{_IDEOGRAPHIC_SPACE}", 1),
        },
    ]

    for v in variants:
        v["normalized"] = normalize_text(v["raw"])
        v["index"] = build_index_info(v["raw"], v["normalized"])

    return variants


def build_index_info(raw: str, normalized: str) -> dict:
    """FR-PRE-005: 정규화 텍스트의 각 단어가 원문 어디서 왔는지 오프셋으로 남긴다.

    indexer.py는 원래 문서(블록 여러 개)를 위해 만들어졌지만, 자연어 입력은 애초에
    블록이 하나뿐인 문서와 같은 모양이라 build_offset_map()/tokenize_words()를 텍스트
    하나에 바로 적용하면 된다.
    """
    offset_map = build_offset_map(raw, normalized)
    words = tokenize_words(normalized)

    word_entries = []
    for w in words:
        raw_start = offset_map[w.start] if w.start < len(offset_map) else None
        raw_end = None
        if w.end > w.start and (w.end - 1) < len(offset_map):
            raw_end = offset_map[w.end - 1] + 1
        word_entries.append(
            {
                "index": w.index,
                "text": w.text,
                "normalized_start": w.start,
                "normalized_end": w.end,
                "raw_start": raw_start,
                "raw_end": raw_end,
            }
        )

    return {"offset_map": offset_map, "words": word_entries}


def _run_single(raw: str, label: str = "입력") -> list[dict]:
    normalized = normalize_text(raw)
    return [
        {
            "label": label,
            "raw": raw,
            "normalized": normalized,
            "index": build_index_info(raw, normalized),
        }
    ]


def _write_txt(results: list[dict], out_path: Path, all_equal: bool | None) -> None:
    lines = [
        "=== 자연어 정규화 결과 (FR-PRE-001) ===",
        f"생성 시각: {datetime.now().isoformat(timespec='seconds')}",
        "",
    ]
    for r in results:
        lines.append(f"--- [{r['label']}] ---")
        lines.append(f"원문 (그대로)          : {r['raw']}")
        lines.append(f"원문 (repr, 특수문자용) : {r['raw']!r}")
        lines.append(f"정규화 후 (그대로)      : {r['normalized']}")
        lines.append(f"정규화 후 (repr)        : {r['normalized']!r}")
        lines.append(f"길이 변화              : {len(r['raw'])}자 -> {len(r['normalized'])}자")
        lines.append("")

        idx = r.get("index")
        if idx:
            lines.append("단어 인덱싱 (FR-PRE-005: 정규화 텍스트 오프셋 -> 원문 오프셋):")
            for w in idx["words"]:
                lines.append(
                    f"  #{w['index']:>2} '{w['text']}'"
                    f"  정규화[{w['normalized_start']}:{w['normalized_end']}]"
                    f"  원문[{w['raw_start']}:{w['raw_end']}]"
                )
            offset_map = idx["offset_map"]
            if len(offset_map) <= 200:
                lines.append(f"전체 offset_map (정규화 문자 i -> 원문 위치): {offset_map}")
            else:
                lines.append(
                    f"전체 offset_map: {len(offset_map)}개 항목 (200자 초과라 생략, --json으로 확인)"
                )
            lines.append("")

    if all_equal is not None:
        lines.append("=== 검증 (FR-PRE-001 검증 기준: 다른 환경 입력 -> 동일 정규화 결과) ===")
        lines.append(f"모든 변형의 정규화 결과가 동일한가: {all_equal}")
        lines.append("")
        if all_equal:
            lines.append("=== 탐지 모듈로 실제 전달되는 값 (위 변형들이 전부 여기로 수렴함) ===")
            lines.append(results[0]["normalized"])
            lines.append("")
            lines.append(
                "※ 위 5개 블록은 정규화 함수 하나가 어떤 환경 입력을 받아도 같은 결과를"
                " 내는지 검증한 것이지, 5개가 각각 탐지로 넘어간다는 뜻이 아니다."
                " 실제 운영에서는 입력이 1건 들어오면 정규화 결과도 1건이고, 그 1건만"
                " FR-PRE-006을 통해 시그니처/해시/임베딩 탐지 모듈로 전달된다."
            )
            lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def _write_json(results: list[dict], out_path: Path, all_equal: bool | None) -> None:
    payload = {"results": results, "all_equal": all_equal}
    if all_equal:
        # 탐지 모듈로 실제 전달되는 단일 값 - results는 검증용 변형 목록일 뿐, 이게
        # FR-PRE-006으로 넘어가는 실제 페이로드다.
        payload["detection_payload"] = results[0]["normalized"]
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="FR-PRE-001 자연어 정규화 결과 확인/저장용 CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="정규화할 문자열을 직접 입력")
    group.add_argument("--file", help="정규화할 일반 텍스트(.txt) 파일 경로")
    group.add_argument("--demo", action="store_true", help="환경별(macOS/Windows/Notion 등) 변형 비교 데모")
    parser.add_argument("--out", help="결과 저장 경로 (기본: src/preprocessing/outputs/ 아래 자동 생성)")
    parser.add_argument("--json", action="store_true", help="txt 대신 JSON으로 저장")
    args = parser.parse_args()

    all_equal = None
    if args.demo:
        results = demo_variants()
        all_equal = len({r["normalized"] for r in results}) == 1
        default_name = "demo_normalization"
    elif args.file:
        raw = Path(args.file).read_text(encoding="utf-8")
        results = _run_single(raw, label=Path(args.file).name)
        default_name = f"normalize_{Path(args.file).stem}"
    else:
        results = _run_single(args.text, label="직접 입력")
        default_name = "normalize_text"

    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ext = "json" if args.json else "txt"
    out_path = Path(args.out) if args.out else DEFAULT_OUTPUT_DIR / f"{default_name}.{ext}"

    if args.json:
        _write_json(results, out_path, all_equal)
    else:
        _write_txt(results, out_path, all_equal)

    print(f"저장 완료: {out_path.resolve()}")
    for r in results:
        print(f"[{r['label']}] {len(r['raw'])}자 -> {len(r['normalized'])}자")
    if all_equal is not None:
        print(f"모든 변형 정규화 결과 동일: {all_equal}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
