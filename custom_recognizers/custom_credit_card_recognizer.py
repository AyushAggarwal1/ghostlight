from typing import List, Optional, Tuple
from base_recognizer import BaseRecognizer, Pattern


class CustomCreditCardRecognizer(BaseRecognizer):
    """
    Recognize common credit card numbers using regex + checksum.
    """

    PATTERNS = [
        Pattern(
            "All Credit Cards (weak)",
            r"\b(?!1\d{12}(?!\d))((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "credit",
        "card",
        "visa",
        "mastercard",
        "cc ",
        "amex",
        "discover",
        "jcb",
        "diners",
        "maestro",
        "instapayment",
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "CREDIT_CARD",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
    ):
        self.replacement_pairs = (
            replacement_pairs if replacement_pairs else [("-", ""), (" ", "")]
        )
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            replacement_pairs=self.replacement_pairs,
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        sanitized_value = self.sanitize_value(pattern_text)
        return self._luhn_checksum(sanitized_value)

    @staticmethod
    def _luhn_checksum(sanitized_value: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        def digits_of(n: str) -> List[int]:
            return [int(dig) for dig in str(n)]

        digits = digits_of(sanitized_value)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(str(d * 2)))
        return checksum % 10 == 0

    def get_supported_entities(self) -> List[str]:
        """Return list of supported entity types."""
        return [self.supported_entity]
