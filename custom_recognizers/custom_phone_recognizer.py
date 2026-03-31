from typing import List, Optional
import re
from base_recognizer import BaseRecognizer, Pattern


class CustomPhoneRecognizer(BaseRecognizer):
    """Recognize phone numbers using regex patterns.
    
    """

    PATTERNS = [
        Pattern(
            "US Phone Number",
            r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
            0.6,
        ),
        Pattern(
            "International Phone Number",
            r"\b(?:\+?[1-9]\d{1,14})\b",
            0.5,
        ),
        Pattern(
            "Phone with extensions",
            r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\s*(?:ext|extension|x)\.?\s*([0-9]+)\b",
            0.7,
        ),
    ]

    CONTEXT = ["phone", "number", "telephone", "cell", "cellphone", "mobile", "call"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "PHONE_NUMBER",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate phone number format."""
        # Remove all non-digit characters except +
        cleaned = re.sub(r'[^\d+]', '', pattern_text)
        
        # Check if it starts with + (international)
        if cleaned.startswith('+'):
            # International format: + followed by 7-15 digits
            digits = cleaned[1:]
            return 7 <= len(digits) <= 15 and digits.isdigit()
        else:
            # Domestic format: 10-11 digits
            return 10 <= len(cleaned) <= 11 and cleaned.isdigit()

    def get_supported_entities(self) -> List[str]:
        """Return list of supported entity types."""
        return [self.supported_entity]
