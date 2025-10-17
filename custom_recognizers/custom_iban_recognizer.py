import logging
import string
from typing import Dict, List, Optional, Tuple
import re
from base_recognizer import BaseRecognizer, Pattern

logger = logging.getLogger("custom-iban-recognizer")


class CustomIbanRecognizer(BaseRecognizer):
    """
    Recognize IBAN code using regex and checksum.
    
    """

    PATTERNS = [
        Pattern(
            "IBAN Generic",
            r"\b([A-Z]{2}[ \-]?[0-9]{2})(?=(?:[ \-]?[A-Z0-9]){9,30})((?:[ \-]?[A-Z0-9]{3,5}){2})"
            r"([ \-]?[A-Z0-9]{3,5})?([ \-]?[A-Z0-9]{3,5})?([ \-]?[A-Z0-9]{3,5})?([ \-]?[A-Z0-9]{3,5})?([ \-]?[A-Z0-9]{3,5})?"
            r"([ \-]?[A-Z0-9]{1,3})?\b",
            0.5,
        ),
    ]

    CONTEXT = ["iban", "bank", "transaction"]

    LETTERS: Dict[int, str] = {
        ord(d): str(i) for i, d in enumerate(string.digits + string.ascii_uppercase)
    }

    def __init__(
        self,
        patterns: List[str] = None,
        context: List[str] = None,
        supported_language: str = "en",
        supported_entity: str = "IBAN_CODE",
        exact_match: bool = False,
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
    ):
        self.replacement_pairs = replacement_pairs or [("-", ""), (" ", "")]
        self.exact_match = exact_match
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
        """Validate IBAN using checksum."""
        try:
            pattern_text = self.sanitize_value(pattern_text)
            is_valid_checksum = (
                self._generate_iban_check_digits(pattern_text, self.LETTERS)
                == pattern_text[2:4]
            )
            
            if is_valid_checksum:
                if self._is_valid_format(pattern_text):
                    return True
                elif self._is_valid_format(pattern_text.upper()):
                    return True
            return False
        except ValueError:
            logger.error("Failed to validate text %s", pattern_text)
            return False

    @staticmethod
    def _number_iban(iban: str, letters: Dict[int, str]) -> str:
        """Convert IBAN to numeric format."""
        return (iban[4:] + iban[:4]).translate(letters)

    @staticmethod
    def _generate_iban_check_digits(iban: str, letters: Dict[int, str]) -> str:
        """Generate IBAN check digits."""
        transformed_iban = (iban[:2] + "00" + iban[4:]).upper()
        number_iban = CustomIbanRecognizer._number_iban(transformed_iban, letters)
        return f"{98 - (int(number_iban) % 97):0>2}"

    @staticmethod
    def _is_valid_format(iban: str) -> bool:
        """Check if IBAN format is valid for the country."""
        # Basic format validation - check length and structure
        if len(iban) < 15 or len(iban) > 34:
            return False
        
        # Check country code
        country_code = iban[:2]
        if not country_code.isalpha():
            return False
        
        # Check check digits
        check_digits = iban[2:4]
        if not check_digits.isdigit():
            return False
        
        # Check remaining characters
        remaining = iban[4:]
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        if not all(c in valid_chars for c in remaining):
            return False
        
        return True

    def get_supported_entities(self) -> List[str]:
        """Return list of supported entity types."""
        return [self.supported_entity]
