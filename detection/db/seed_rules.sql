INSERT OR REPLACE INTO signature_rules
    (rule_id, name, category, entity_type, pattern, score, context_keywords, requires_context, enabled, description)
VALUES
    ('SIG-CRED-001', 'GitHub Access Token', 'CREDENTIAL', 'GITHUB_TOKEN',
     '(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)', 0.95, NULL, 0, 1,
     'GitHub token prefix 기반 탐지'),
    ('SIG-CRED-002', 'Generic API Key', 'CREDENTIAL', 'GENERIC_API_KEY',
     '[A-Za-z0-9_\-]{16,128}', 0.85,
     'api_key,apikey,api key,x-api-key,access_key,access key,client_secret,client secret', 1, 1,
     'API Key label에 결합된 값 탐지'),
    ('SIG-CRED-003', 'Password', 'CREDENTIAL', 'PASSWORD',
     '(?=[^\s"`,;]{6,128})(?=[^\s"`,;]*[A-Za-z])[^\s"`,;]{6,128}', 0.85,
     'password,passwd,pwd,비밀번호,db_password,database_password', 1, 1,
     'Password label에 결합된 값 탐지'),
    ('SIG-PII-001', 'Korean Bank Account Number', 'PII', 'KR_BANK_ACCOUNT',
     '[0-9]{2,6}(?:-[0-9]{2,6}){1,4}', 0.80,
     '계좌번호,계좌,입금계좌,account number,bank account', 1, 1,
     '계좌 label에 결합된 숫자열 탐지');
