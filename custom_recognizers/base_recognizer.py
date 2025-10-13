from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
import re
from dataclasses import dataclass


@dataclass
class Pattern:
    """Represents a regex pattern with a name and score."""
    name: str
    regex: str
    score: float


@dataclass
class RecognizerResult:
    """Represents the result of a recognition operation."""
    entity_type: str
    start: int
    end: int
    score: float
    text: str
    pattern_name: str
    validation_result: Optional[bool] = None


class BaseRecognizer(ABC):
    """Base class for all custom recognizers."""
    
    def __init__(
        self,
        supported_entity: str,
        patterns: List[Pattern],
        context: List[str],
        supported_language: str = "en",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None
    ):
        self.supported_entity = supported_entity
        self.patterns = patterns
        self.context = context
        self.supported_language = supported_language
        self.replacement_pairs = replacement_pairs or [("-", ""), (" ", "")]
    
    def sanitize_value(self, text: str) -> str:
        """Sanitize text by applying replacement pairs."""
        sanitized = text
        for old, new in self.replacement_pairs:
            sanitized = sanitized.replace(old, new)
        return sanitized
    
    def analyze(self, text: str) -> List[RecognizerResult]:
        """Analyze text and return recognition results."""
        results = []
        
        for pattern in self.patterns:
            matches = re.finditer(pattern.regex, text, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                start, end = match.span()
                matched_text = text[start:end]
                
                # Validate the result if validation method exists
                validation_result = None
                if hasattr(self, 'validate_result'):
                    validation_result = self.validate_result(matched_text)
                
                # Calculate final score
                final_score = pattern.score
                if validation_result is not None:
                    if validation_result:
                        final_score = 1.0  # Max score for validated results
                    else:
                        final_score = 0.0  # Min score for invalid results
                
                # Only add results with score > 0
                if final_score > 0:
                    result = RecognizerResult(
                        entity_type=self.supported_entity,
                        start=start,
                        end=end,
                        score=final_score,
                        text=matched_text,
                        pattern_name=pattern.name,
                        validation_result=validation_result
                    )
                    results.append(result)
        
        return self._remove_duplicates(results)
    
    def _remove_duplicates(self, results: List[RecognizerResult]) -> List[RecognizerResult]:
        """Remove duplicate results based on start and end positions."""
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.start, result.end, result.entity_type)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results
    
    @abstractmethod
    def get_supported_entities(self) -> List[str]:
        """Return list of supported entity types."""
        pass
