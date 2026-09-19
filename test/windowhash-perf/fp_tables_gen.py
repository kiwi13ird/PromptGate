import random
rng = random.Random(11)
SUR = "김이박최정강조윤장임한오서신권황안송류전홍"; GIV = ["도현","수민","지훈","서연","민준","하은","지우","예준","시우","하윤","수아","지민","준서","유진","현우","서윤"]
DEPT = ["경영기획실","영업1팀","개발2팀","재무회계팀","인사팀","품질팀","마케팅팀"]; POS = ["사원","주임","대리","과장","차장","팀장","이사"]
BANK = ["신한은행","국민은행","하나은행","우리은행","농협"]
PAY_HDR = "귀속월 | 사번 | 성명 | 부서 | 직급 | 입사일 | 주민등록번호 | 계좌번호 | 기본급 | 식대 | 근속수당 | 연장수당 | 지급총액 | 국민연금 | 건강보험 | 고용보험 | 소득세 | 공제총액 | 실지급액"
def pay_row(i):
    base = rng.randint(280, 900) * 10000; meal = 200000; svc = rng.randint(0, 40) * 10000; ot = rng.randint(0, 30) * 10000
    tot = base + meal + svc + ot; np_ = int(tot * 0.045); hi = int(tot * 0.03545); ei = int(tot * 0.009); tax = int(tot * 0.13)
    ded = np_ + hi + ei + tax
    yy = rng.randint(70, 99); mm = rng.randint(1, 12); dd = rng.randint(1, 28)
    return (f"2026-0{rng.choice('78')} | NW{rng.randint(15,25)}-{rng.randint(1,400):04d} | {rng.choice(SUR)}{rng.choice(GIV)} | {rng.choice(DEPT)} | {rng.choice(POS)} | "
            f"20{rng.randint(15,25)}-{mm:02d}-{dd:02d} | {yy}{mm:02d}{dd:02d}-{rng.choice('12')}{rng.randint(100000,999999)} | {rng.choice(BANK)} {rng.randint(100,999)}-{rng.randint(10,99)}-{rng.randint(100000,999999)} | "
            f"{base} | {meal} | {svc} | {ot} | {tot} | {np_} | {hi} | {ei} | {tax} | {ded} | {tot-ded}")
CO = ["대한","한빛","서진","미래","청솔","그린","다온","청록","이든","아라","누리","세종","한울","금강","해든"]; SUF = ["정밀㈜","유통","테크놀로지㈜","금융시스템","전자㈜","산업","솔루션","바이오"]
IND = ["제조","유통물류","IT서비스","금융","식품","건설","에너지","제약/바이오"]
CUS_HDR = "고객사명 | 업종 | 계약등급 | 연간계약금액 | 계약시작일 | 계약갱신일 | 담당영업사원 | 담당자연락처 | 담당자이메일 | 비고"
NOTES = ["재계약 협의중", "결제 주기 분기별", "추가 라이선스 협의중", "보안 감사 대응 필요", "신규 계약", "해지 검토중", "확장 논의중"]
def cus_row(i):
    c = rng.choice(CO) + rng.choice(SUF); m = rng.randint(1, 12)
    return (f"{c} | {rng.choice(IND)} | {rng.choice(['VIP','일반','우수'])} | {rng.randint(5,200)},000,000원 | 2025-{m:02d}-{rng.randint(1,28):02d} | 2026-{m:02d}-{rng.randint(1,28):02d} | "
            f"{rng.choice(SUR)}{rng.choice(GIV)} | 010-{rng.randint(1000,9999)}-{rng.randint(1000,9999)} | {rng.choice('abcdefghijk')}{rng.choice('lmnop')}.{rng.choice('xyzqw')}{rng.choice('abc')}@{rng.choice('abcdefg')}co.kr | {rng.choice(NOTES)}")
