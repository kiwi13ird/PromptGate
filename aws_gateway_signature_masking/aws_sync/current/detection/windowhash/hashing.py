"""압축과 창 해시.

1. `compact()`: 정규화 텍스트에서 한글·영문·숫자만 남긴다. 공백뿐 아니라 구두점·표 구분자(|, 탭, 쉼표)·불릿도
   전부 버린다. 같은 표를 엑셀에서 복사하면 탭, 우리 추출기는 " | ", 메모장은 공백이라 구분자를 남기면 같은
   내용이 다른 해시가 된다(실측: 구분자 유지 시 표 0/30, 제거 시 30/30). 각 글자가 원문 몇 번째였는지의
   오프셋을 같이 돌려줘 일치 위치를 원문 좌표로 말할 수 있게 한다.
2. `window_hashes()`: 압축 열의 **모든** 위치에서 길이 WINDOW의 창을 Rabin-Karp 롤링 해시로 만든다.
   Winnowing처럼 창 안에서 하나를 고르지 않는다 - 고르면 편집된 자리의 지문이 사라져 강건성을 잃고,
   고르지 않아도 문서 20종은 창 20만 개(수십 MB)라 저장이 문제가 안 된다.

보장: 두 텍스트가 압축 후 WINDOW자 이상 그대로 겹치면 같은 창 해시를 반드시 하나 이상 공유한다.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# 창 길이(압축 후 글자 수). 원문으로는 약 1.3배(공백·구두점 몫).
# 실측(docs/reports/verbatim-miss-diagnosis-2026-09-10.md §11): 30이면 원문·표·문장 단위 편집 전부 30/30,
# 무관 산문 248조각 오탐 0. 50이면 "문장 절반만 남김"이 21/30로 떨어진다. 더 줄이면 짧은 상용 문구가 걸릴 위험.
WINDOW = 30

# 롤링 해시 상수. hashdb/winnowing.py의 것을 그대로 가져왔다(61비트 메르센 소수, 큰 소수 밑, 순서를 섞는 홀수 승수).
_MOD = (1 << 61) - 1
_BASE = 1_000_003
_MIX = 0x9E3779B97F4A7C15

_KEEP = re.compile(r"[가-힣A-Za-z0-9]")


class Compact(NamedTuple):
    codes: list[int]  # 남긴 글자의 코드포인트 열
    offsets: list[int]  # 각 글자의 원문(정규화 텍스트) 오프셋


def compact(text: str) -> Compact:
    """한글·영문·숫자만 남긴 코드 열과 원문 오프셋. 대소문자는 구분하지 않는다(정규화 범위 밖의 표기 차이)."""
    codes: list[int] = []
    offsets: list[int] = []
    for i, ch in enumerate(text):
        if _KEEP.match(ch):
            codes.append(ord(ch.lower()))
            offsets.append(i)
    return Compact(codes, offsets)


def window_hashes(codes: list[int], window: int = WINDOW) -> list[int]:
    """모든 위치 i에 대해 codes[i:i+window]의 해시. 길이가 window 미만이면 빈 목록(창이 없다 = 검사 불가)."""
    n = len(codes)
    if n < window:
        return []
    high = pow(_BASE, window - 1, _MOD)
    h = 0
    for c in codes[:window]:
        h = (h * _BASE + c) % _MOD
    out = [_mix(h)]
    for i in range(window, n):
        h = ((h - codes[i - window] * high) * _BASE + codes[i]) % _MOD
        out.append(_mix(h))
    return out


def _mix(rolling_hash: int) -> int:
    """값의 크기 순서를 없앤다. 정확 일치만 보는 여기서는 필수는 아니지만 키 분포를 고르게 해 둔다."""
    return (rolling_hash * _MIX) % _MOD


def window_span(comp: Compact, i: int, window: int = WINDOW) -> tuple[int, int]:
    """압축 위치 i에서 시작하는 창이 원문에서 차지하는 구간 [start, end)."""
    return comp.offsets[i], comp.offsets[i + window - 1] + 1
