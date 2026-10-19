import type { ReactNode } from 'react';

/**
 * 세그먼트(설계 4.11 차단 대화상자의 기간, 5.5 키워드 보기, 5.1·5.9 기간 선택): 보기에는 붙은 버튼 줄이지만 속은 라디오 묶음(fieldset + legend + radio).
 * 키보드(화살표)·화면 읽기 프로그램·getByRole('radio') 시험이 라디오 그대로 동작한다.
 * legendHidden: 묶음 이름은 화면 읽기 프로그램에만(머리 기간 선택처럼 이름표가 없어도 뜻이 분명한 곳).
 * label에 숫자를 굵게 넣을 수 있다(예: 승인 대기 <b>6</b>). 라디오 이름은 label 글자 그대로.
 */
export function PgSegment<T extends string>({ legend, legendNote, legendHidden = false, name, options, value, onChange, disabled, className = '' }: {
  legend: string;
  legendNote?: string;
  legendHidden?: boolean;
  name: string;
  options: readonly { value: T; label: ReactNode; title?: string }[];
  value: T;
  onChange: (value: T) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <fieldset className={`pg-segment-field ${className}`.trim()} disabled={disabled}>
      <legend className={legendHidden ? 'sr-only' : undefined}>{legend}{legendNote && <small> {legendNote}</small>}</legend>
      <div className="pg-segment">
        {options.map((option) => (
          <label key={option.value} className="pg-segment-option" title={option.title}>
            <input type="radio" name={name} value={option.value} checked={value === option.value} onChange={() => onChange(option.value)} />
            {option.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
