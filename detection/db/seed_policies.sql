-- 최종 정책은 그대로 보존한다. 현재 BLOCK MVP는 pipeline.signature_blocks()가 임시 집행한다.
INSERT OR REPLACE INTO detection_policies
    (policy_id, target_type, target_value, action, priority, version, enabled)
VALUES
    ('POLICY-PII-MASK', 'category', 'PII', 'MASK', 100, 1, 1),
    ('POLICY-CREDENTIAL-MASK', 'category', 'CREDENTIAL', 'MASK', 100, 1, 1);
