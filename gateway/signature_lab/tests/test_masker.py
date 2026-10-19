import unittest

from presidio_analyzer import RecognizerResult

from signature_detector.masker import mask_text


class MaskTextTest(unittest.TestCase):
    def test_masks_multiple_entities_without_offset_corruption(self):
        text = "생년월일은 1999.03.14, 이메일은 employee1@example.com이다."
        results = [
            RecognizerResult("KR_DATE_OF_BIRTH", 6, 16, 0.9),
            RecognizerResult("EMAIL_ADDRESS", 23, 44, 0.9),
        ]
        self.assertEqual(
            mask_text(text, results),
            "생년월일은 [DATE_OF_BIRTH], 이메일은 [EMAIL_ADDRESS]이다.",
        )


if __name__ == "__main__":
    unittest.main()
