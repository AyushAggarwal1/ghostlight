from typing import List, Optional
from base_recognizer import BaseRecognizer, Pattern


class CustomEmailRecognizer(BaseRecognizer):
    """
    Recognize email addresses using regex.
    
    """

    PATTERNS = [
        Pattern(
            "Email (Medium)",
            r"\b((([!#$%&'*+\-/=?^_`{|}~\w])|([!#$%&'*+\-/=?^_`{|}~\w][!#$%&'*+\-/=?^_`{|}~\.\w]{0,}[!#$%&'*+\-/=?^_`{|}~\w]))[@]\w+([-.]\w+)*\.\w+([-.]\w+)*)\b",
            0.5,
        ),
    ]

    CONTEXT = ["email"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "EMAIL_ADDRESS",
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
        """Validate email address format."""
        # Basic email validation - check for @ and domain
        if "@" not in pattern_text:
            return False
        
        parts = pattern_text.split("@")
        if len(parts) != 2:
            return False
        
        local_part, domain_part = parts
        
        # Check local part
        if not local_part or len(local_part) > 64:
            return False
        
        # Check domain part
        if not domain_part or len(domain_part) > 253:
            return False
        
        # Check for valid domain format
        if "." not in domain_part:
            return False
        
        # Check for valid characters in domain
        valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(c in valid_chars for c in domain_part):
            return False
        
        return True

    def get_supported_entities(self) -> List[str]:
        """Return list of supported entity types."""
        return [self.supported_entity]
