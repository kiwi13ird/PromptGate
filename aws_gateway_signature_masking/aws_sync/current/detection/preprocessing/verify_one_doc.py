"""기밀문서 1건을 실제 파이프라인(process_input)에 태워, 정답 카탈로그
(ground_truth_pii_credential.json)와 대조하고 인덱싱까지 눈으로 확인하는 검증 스크립트.

사용법:
    python -m preprocessing.verify_one_doc <문서경로> [--doc-key 10_인프라_구성문서]

--doc-key를 생략하면 파일명에서 확장자를 뗀 값을 그대로 ground_truth의 키로 쓴다.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.router import process_input

GROUND_TRUTH_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "testbed-dataset" / "ground_truth_pii_credential.json"
)

PATTERNS = {
    "주민등록번호": re.compile(r"\d{6}-[1-4]\d{6}"),
    "전화번호": re.compile(r"01[016789]-\d{3,4}-\d{4}"),
    "이메일": re.compile(r"[\w.\-]+@[\w\-]+\.[a-zA-Z]{2,}"),
    "계좌번호": re.compile(r"(?<!\d)\d{2,6}-\d{2,6}-\d{2,10}(?!\d)"),
    "AWS_Access_Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "DB_접속문자열": re.compile(r"(?:postgres|mysql|mongodb|redis)(?:\+\w+)?://\S+"),
    "Private_Key_PEM": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "JWT_Token": re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),
    "GitHub_Token": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    "Slack_Token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="기밀문서 1건 파이프라인 검증")
    parser.add_argument("path", help="검증할 문서 경로")
    parser.add_argument("--doc-key", help="ground_truth의 문서 키 (생략 시 파일명에서 유추)")
    parser.add_argument("--out", help="검증 보고서 저장 경로")
    args = parser.parse_args()

    doc_path = Path(args.path)
    doc_key = args.doc_key or doc_path.stem

    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    expected = ground_truth.get("per_document", {}).get(doc_key, {})

    result = process_input(str(doc_path))

    lines = []
    lines.append(f"=== 기밀문서 파이프라인 검증: {doc_path.name} ===")
    lines.append(f"라우팅 결과 형식: {result.format}")
    lines.append(f"파싱 성공: {result.success}")
    if not result.success:
        lines.append(f"오류: {result.error_type} - {result.error_message}")
        Path(args.out or "verify_result.txt").write_text("\n".join(lines), encoding="utf-8")
        print("\n".join(lines))
        return 1

    lines.append(f"블록 수: {len(result.blocks)}")
    lines.append(f"정규화 텍스트 길이: {len(result.normalized_text)}자")
    lines.append("")

    _DATE_SHAPE_RE = re.compile(r"^(19|20)\d{2}-\d{2}-\d{2}$")

    lines.append("--- 정답 카탈로그 대조 ---")
    all_ok = True
    sample_locations = []
    for label, pattern in PATTERNS.items():
        matches = list(pattern.finditer(result.normalized_text))
        if label == "계좌번호":
            # YYYY-MM-DD 형태의 날짜와 자릿수 모양이 겹치므로 명시적으로 제외한다
            # (정규식 lookahead로 막으면 엔진이 다음 위치에서 재매칭을 시도해
            # "026-08-25"처럼 한 글자 밀린 부분매치가 새로 생기므로, 매치 후
            # 후처리로 걸러내는 편이 안전하다).
            matches = [m for m in matches if not _DATE_SHAPE_RE.match(m.group(0))]
        found = len(matches)
        exp = expected.get(label)
        if exp is None:
            if found == 0:
                continue
            marker = "  (정답 카탈로그에 없는 유형 - 참고용)"
        else:
            marker = "  OK" if found == exp else "  MISMATCH"
            if found != exp:
                all_ok = False
        lines.append(f"{label}: 발견 {found}건" + (f" / 기대 {exp}건" if exp is not None else "") + marker)

        if matches:
            m = matches[0]
            sample_locations.append((label, m.start(), m.end(), m.group(0)))

    lines.append("")
    lines.append(f"전체 일치 여부: {all_ok}")
    lines.append("")

    lines.append("--- 샘플 위치 인덱싱 검증 (각 유형 첫 매치) ---")
    for label, start, end, matched_text in sample_locations:
        loc = result.index.locate(start, end) if result.index else None
        lines.append(f"[{label}] 매치: {matched_text!r} (normalized offset {start}~{end})")
        if loc is None:
            lines.append("    위치를 특정할 수 없음")
            continue
        ib = result.index.blocks[loc.block_index]
        raw_slice = ib.raw_local_text[loc.raw_start : loc.raw_end] if loc.raw_start is not None else None
        raw_match_ok = raw_slice == matched_text
        lines.append(
            f"    블록 #{loc.block_index} ({loc.block_type})"
            + (f", 표 {loc.cell.row + 1}행 {loc.cell.col + 1}열" if loc.cell else "")
        )
        lines.append(f"    원문(raw) 오프셋: {loc.raw_start}~{loc.raw_end}")
        lines.append(f"    원문에서 슬라이스한 값: {raw_slice!r}")
        lines.append(f"    매치 문자열과 raw 슬라이스 일치: {raw_match_ok}")
        lines.append("")

    report = "\n".join(lines)
    out_path = Path(args.out) if args.out else Path("verify_result.txt")
    out_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n저장 완료: {out_path.resolve()}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
