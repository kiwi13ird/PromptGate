import { Fragment, type ReactNode } from 'react';

/** 상태 띠 단계(설계 4.2): 정상·주의·이상 + 확인 불가(중립) + 진행(진행 중인 일만 있을 때) */
export type StripLevel = 'ok' | 'warn' | 'bad' | 'unknown' | 'progress';

export const STRIP_WORD: Readonly<Record<StripLevel, string>> = {
  ok: '정상',
  warn: '주의',
  bad: '이상',
  unknown: '확인 불가',
  progress: '진행 중',
};

/** 단계 → 배지 계열(색). 정상=정상 · 주의=주의 · 이상=차단 · 확인 불가=중립 · 진행=진행 */
export const STRIP_TONE = { ok: 'allow', warn: 'mask', bad: 'block', unknown: 'neutral', progress: 'info' } as const;

/**
 * 머리 바로 아래 한 줄: 등(●) + 상태 단어(굵게) + 근거 사실(" · "로 연결) + 오른쪽 링크·시각. 높이 40 안팎.
 * word를 주면 기본 단어 대신 그 글자(예: "이상 1 · 주의 1"). facts의 빈 값은 건너뛴다.
 */
export function PgStatusStrip({ level, word, facts = [], end, label }: {
  level: StripLevel;
  word?: ReactNode;
  /** 근거 사실. 글자 또는 강조가 든 조각(예: <>Gateway <b>정상</b></>) */
  facts?: readonly (ReactNode | null | undefined | false)[];
  /** 오른쪽 끝(링크·확인 시각) */
  end?: ReactNode;
  /** 화면 읽기 프로그램용 이름(기본 "상태") */
  label?: string;
}) {
  const shown = facts.filter((fact) => fact !== null && fact !== undefined && fact !== false && fact !== '');
  return (
    <div className={`pg-strip pg-strip--${level}`} role="status" aria-label={label ?? '상태'} data-level={level}>
      <span className="pg-strip-lamp" aria-hidden="true" />
      <span className="pg-strip-word">{word ?? STRIP_WORD[level]}</span>
      {shown.length > 0 && <span className="pg-strip-facts">{shown.map((fact, index) => <Fragment key={index}>{index > 0 && ' · '}{fact}</Fragment>)}</span>}
      {end && <span className="pg-strip-end">{end}</span>}
    </div>
  );
}
