import unittest

from signature_detector import TARGET_ENTITIES, create_analyzer


class AnalyzerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analyzer = create_analyzer()

    def detect(self, text):
        return {
            (result.entity_type, text[result.start : result.end])
            for result in self.analyzer.analyze(
                text=text,
                language="en",
                entities=TARGET_ENTITIES,
            )
        }

    def test_detects_supported_entities(self):
        text = (
            "생년월일은 1999.03.14이고 전화번호는 010-1234-5678이며 "
            "이메일은 employee1@example.com, 주민등록번호는 990314-1234567이다."
        )
        detected = self.detect(text)
        self.assertIn(("KR_DATE_OF_BIRTH", "1999.03.14"), detected)
        self.assertIn(("KR_PHONE_NUMBER", "010-1234-5678"), detected)
        self.assertIn(("EMAIL_ADDRESS", "employee1@example.com"), detected)
        self.assertIn(("KR_RRN", "990314-1234567"), detected)

    def test_keeps_known_phone_like_false_positive_documented(self):
        detected = self.detect("IP 비슷한 숫자: 010.1234.5678")
        self.assertIn(("KR_PHONE_NUMBER", "010.1234.5678"), detected)


if __name__ == "__main__":
    unittest.main()
