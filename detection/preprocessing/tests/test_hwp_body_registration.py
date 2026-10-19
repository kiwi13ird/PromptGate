"""등록 글자는 본문만(2026-10-11 검토 지적 1): 부가 글자(요약 정보·개체 설명문·필드·수식·HWPX 메타·바탕쪽)는 Gateway 검사
글자에만 넣고 등록 색인에는 넣지 않는다.

같은 양식에서 나온 문서는 요약 정보·그림 설명문(원본 그림 이름)·메타가 같다. 이 글자를 색인하면 본문이 전혀 겹치지 않는
문서끼리도 창이 맞아 doc_excerpt로 막힌다(BLOCK_THRESHOLD 0 - 창 하나면 차단, 한 문서에만 있는 창은 UNIQUE_DOC_CUT에 안 걸림).
글자는 모두 가짜 값.
"""

from __future__ import annotations

import fakeredis
import pytest

import hwp_synth as S
from hwp_synth import hp_p, hp_run, hp_t
from preprocessing import hwp_parser, hwpdoc
from preprocessing.normalizer import normalize_text
from preprocessing.router import process_input
from windowhash import detect, engine, index
from windowhash.hashing import compact, window_hashes

MAX = hwp_parser.MAX_DECOMPRESSED

# 한컴이 그림에 붙이는 설명문 모양(가짜 값)과 같은 양식 문서들이 공유하는 요약 정보·메타
DESC = "그림입니다.\n원본 그림의 이름: 가짜회사_로고_최종본.png\n원본 그림의 크기: 가로 1200pixel, 세로 400pixel"
SUMMARY = {2: "가짜 주식회사 분기 보고서 표준 양식", 4: "가짜 작성자 홍길동 대리", 6: "가짜 회사 내부 문서 양식 2026년판"}
META = {"title": "가짜 주식회사 분기 보고서 표준 양식", "creator": "가짜 작성자 홍길동 대리",
        "description": "가짜 회사 내부 문서 양식 2026년판"}
MASTER_TEXT = "가짜 주식회사 대외비 문서 - 무단 복제 금지 - 바탕쪽 머리 글자"

BODY_A = ["첫째 문서 본문: 신규 물류 거점은 가짜 도시 북부 산업단지에 두기로 하고 부지 매입 협상을 시작한다.",
          "예산은 가짜 숫자로 일백이십억 원이며 착공은 내년 봄으로 잡는다."]
BODY_B = ["둘째 문서 본문: 고객 상담 응대 지침을 개정하여 야간 상담 인력을 세 명 늘리고 교대 시간을 조정한다.",
          "개정 지침은 다음 달 첫 영업일부터 모든 지점에 적용한다."]


def _hwp(body: list[str]) -> bytes:
    sec = b"".join(S.p(0, t) for t in body)
    sec += S.p(0, "", S.picture(1, desc=DESC), S.equation(1, "x over y", desc="수식입니다."),
               S.field(1, "%hlk", "mailto:fake-contact@example.com;1;0;0;"))
    return S.build_hwp([sec], summary=SUMMARY)


def _hwpx(body: list[str]) -> bytes:
    sec = "".join(hp_p(hp_t(t)) for t in body)
    sec += hp_p(hp_run(f'<hp:pic id="8"><hp:shapeComment>{DESC}</hp:shapeComment><hp:img binaryItemIDRef="image1"/></hp:pic>'))
    master = (f'<?xml version="1.0" encoding="UTF-8"?><hm:masterPage {S.NSDECL} id="m0" type="BOTH">'
              f'<hp:subList>{hp_p(hp_t(MASTER_TEXT))}</hp:subList></hm:masterPage>')
    return S.build_hwpx([sec], meta=META, extra={"Contents/masterpage0.xml": master, "BinData/image1.png": b"\x89PNG0"})


MAKERS = {"hwp": _hwp, "hwpx": _hwpx}


def _register(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    parsed = process_input(str(path))
    assert parsed.success, (parsed.error_type, parsed.error_message)
    return parsed.normalized_text


def _gateway_text(data: bytes) -> str:
    """Gateway가 업로드 파일에서 보낼 글자('\\n'.join(lines()))를 Detection 탐지 입력과 같이 정규화한 것."""
    return normalize_text("\n".join(hwpdoc.read(data, max_decompressed=MAX).lines()))


@pytest.mark.parametrize("fmt", ["hwp", "hwpx"])
def test_registration_text_is_body_only_and_prefix_of_gateway_text(tmp_path, fmt):
    data = MAKERS[fmt](BODY_A)
    doc = hwpdoc.read(data, max_decompressed=MAX)
    reg = _register(tmp_path, f"a.{fmt}", data)
    assert doc.lines()[: len(doc.body_lines())] == doc.body_lines()          # lines() = 본문 줄 + 부가 글자 줄
    assert len(doc.lines()) > len(doc.body_lines())
    reg_codes = compact(reg).codes
    assert reg_codes == compact(normalize_text("\n".join(doc.body_lines()))).codes
    gw_codes = compact(_gateway_text(data)).codes
    assert gw_codes[: len(reg_codes)] == reg_codes and len(gw_codes) > len(reg_codes)   # 등록 압축열 = 검사 압축열의 앞부분
    for side in ("가짜회사_로고_최종본", "분기 보고서 표준 양식", "fake-contact@example.com", "바탕쪽 머리 글자"):
        assert side not in reg
    assert "가짜회사_로고_최종본" in _gateway_text(data)                    # 부가 글자는 여전히 Gateway 검사 범위


@pytest.mark.parametrize("fmt", ["hwp", "hwpx"])
def test_unrelated_body_with_same_side_text_is_not_blocked(tmp_path, fmt):
    make = MAKERS[fmt]
    a, b = make(BODY_A), make(BODY_B)
    r = fakeredis.FakeRedis(decode_responses=True)
    index.replace_doc_windows(r, "doc-a", engine.document_windows(_register(tmp_path, f"a.{fmt}", a)))
    # 같은 양식(부가 글자 동일)·본문 무관 → 통과
    assert not detect.decide(detect.query_text(r, _gateway_text(b))).blocked
    # 등록 문서 자체·본문 일부를 올리면 그대로 차단
    assert detect.decide(detect.query_text(r, _gateway_text(a))).blocked
    excerpt = normalize_text(BODY_A[0])
    assert window_hashes(compact(excerpt).codes)
    assert detect.decide(detect.query_text(r, excerpt)).blocked


def test_side_only_document_still_rejected(tmp_path):
    """본문이 없으면 부가 글자가 있어도 등록하지 않는다(그대로)."""
    path = tmp_path / "s.hwp"
    path.write_bytes(S.build_hwp([S.p(0, "", S.picture(1, desc=DESC))], summary=SUMMARY))
    parsed = process_input(str(path))
    assert not parsed.success and parsed.error_type == "DocumentParsingError"
