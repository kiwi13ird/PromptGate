export const uiMode = {
  isDemo: true,
  supportedActions: ['ALLOW', 'MASK', 'BLOCK'],
  supportedDetectors: ['SHA256', 'MINHASH', 'WINDOW_HASH', 'SIGNATURE'],
  supportedMatchTypes: [
    'EXACT_DOCUMENT',
    'SIMILAR_DOCUMENT',
    'TEXT_FRAGMENT',
    'SIGNATURE_RULE',
  ],
  supportedScoreKinds: ['COVERAGE', 'SIMILARITY', 'CONFIDENCE'],
  showRecommendedAction: true,
  showFailurePolicy: true,
  canManageDocuments: true,
  canManagePolicies: true,
  authTitle: '개발·데모용 Mock Authentication',
  authDescription: '실제 운영 인증으로 사용할 수 없는 Mock 계정입니다.',
  uploadDescription:
    'Demo에서는 파일 Metadata만 생성하며 파일 원문을 저장하지 않습니다.',
  uploadHint: '최대 20MB · Demo',
} as const;
