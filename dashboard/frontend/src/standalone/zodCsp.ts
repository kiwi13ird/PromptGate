import { z } from 'zod';

// 확장 프로그램 페이지(MV3 CSP: unsafe-eval 없음)용. zod 4는 z.object()를 만들 때 new Function("")으로
// eval 가능 여부를 떠 보는데, 막혀도 동작은 하지만 CSP 위반이 콘솔에 남는다.
// 스키마를 만드는 모듈보다 먼저 평가돼야 하므로 진입점의 첫 import로 둔다.
z.config({ jitless: true });
