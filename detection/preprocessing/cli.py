"""자유 입력(자연어/PDF/DOCX)의 파싱+정규화 결과를 직접 눈으로 확인하기 위한 CLI.

router.process_input()을 그대로 쓰기 때문에 인자를 파일 경로로 줘도, 그냥 문장을
줘도 알아서 감지해서 처리한다: 존재하는 파일이면 내용(매직바이트)으로 pdf/docx를
가려 해당 파서를 태우고, 아니면 자연어 입력으로 보고 정규화만 수행한다.

사용법:
    python -m preprocessing.cli "<파일경로 또는 그냥 문장>" [--raw] [--json]

옵션:
    --raw   정규화 전 원문도 함께 출력한다 (기본은 정규화 결과만 출력).
    --json  전체 결과를 JSON으로 출력한다 (파이프라인 산출물 형태를 그대로 보고 싶을 때).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.router import process_input


def _block_to_dict(b) -> dict:
    return {
        "type": b.type,
        "level": b.level,
        "page": b.page,
        "section": b.section,
        "raw_text": b.raw_text,
        "normalized_text": b.normalized_text,
        "raw_rows": b.raw_rows,
        "normalized_rows": b.normalized_rows,
    }


def _print_find(result, needle: str) -> None:
    text = result.normalized_text
    occurrences = []
    start = 0
    while True:
        pos = text.find(needle, start)
        if pos == -1:
            break
        occurrences.append(pos)
        start = pos + 1

    print(f"'{needle}' 검색 결과: {len(occurrences)}건")
    print("-" * 60)

    if not occurrences or result.index is None:
        return

    for i, pos in enumerate(occurrences):
        loc = result.index.locate(pos, pos + len(needle))
        print(f"[매치 {i}] global offset {pos}~{pos + len(needle)}")
        if loc is None:
            print("    위치를 특정할 수 없음")
            print()
            continue
        print(f"    블록: #{loc.block_index} ({loc.block_type})", end="")
        if loc.page is not None:
            print(f", page={loc.page}", end="")
        if loc.section is not None:
            print(f", section={loc.section}", end="")
        print()
        if loc.cell is not None:
            print(f"    표 위치: {loc.cell.row + 1}행 {loc.cell.col + 1}열")
        print(f"    블록 내 정규화 오프셋: {loc.local_start}~{loc.local_end}")
        print(f"    블록 내 원문(raw) 오프셋: {loc.raw_start}~{loc.raw_end}")
        print(f"    단어 인덱스: {loc.word_indices}")
        print(f"    원문 스니펫: ...{loc.raw_snippet}...")
        print(f"    한줄 요약: {loc.describe()}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="자연어/PDF/DOCX 자유 입력 파싱+정규화 결과 확인용 CLI")
    parser.add_argument("source", help="파일 경로(PDF/DOCX) 또는 그냥 문장(자연어) - 자동 감지된다")
    parser.add_argument("--raw", action="store_true", help="정규화 전 원문도 함께 출력")
    parser.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    parser.add_argument(
        "--find",
        metavar="TEXT",
        help="정규화된 전체 텍스트에서 TEXT를 찾아 위치 인덱싱 결과(FR-PRE-005)를 보여준다"
        " - 탐지 모듈이 매치를 돌려준 상황을 흉내낸다",
    )
    args = parser.parse_args()

    result = process_input(args.source)

    if args.find and result.success:
        _print_find(result, args.find)
        return 0

    if args.json:
        payload = {
            "path": result.path,
            "format": result.format,
            "success": result.success,
            "error_type": result.error_type,
            "error_message": result.error_message,
            "normalized_text": result.normalized_text,
            "blocks": [_block_to_dict(b) for b in result.blocks],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if result.success else 1

    print(f"파일: {result.path}")
    print(f"형식: {result.format}")
    print(f"성공: {result.success}")

    if not result.success:
        print(f"오류 유형: {result.error_type}")
        print(f"오류 메시지: {result.error_message}")
        return 1

    print(f"블록 수: {len(result.blocks)}")
    print("-" * 60)

    for i, b in enumerate(result.blocks):
        loc = ""
        if b.page is not None:
            loc = f" (page {b.page})"
        elif b.section is not None:
            loc = f" (section {b.section})"

        print(f"[{i}] {b.type}{loc}")

        if b.type == "table":
            for row in b.normalized_rows:
                print("    | " + " | ".join(row))
        else:
            if args.raw:
                print(f"    RAW : {b.raw_text}")
            print(f"    NORM: {b.normalized_text}")
        print()

    print("-" * 60)
    print("=== 정규화된 전체 텍스트 (탐지 모듈로 전달될 최종 입력) ===")
    print(result.normalized_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
