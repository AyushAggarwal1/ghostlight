from typing import List, Dict, Any, Optional, Tuple
import re
from custom_recognizer_manager import CustomRecognizerManager
from base_recognizer import RecognizerResult


class DataProcessor:
    """
    Data processor for finding and filtering sensitive information.
    
    This class provides methods for processing text data to find sensitive
    information and apply filters to reduce false positives.
    """
    
    def __init__(self):
        """Initialize the data processor with recognizer manager."""
        self.recognizer_manager = CustomRecognizerManager()
        self.false_positive_patterns = self._load_false_positive_patterns()
    
    def _load_false_positive_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that commonly cause false positives."""
        return {
            'credit_card': [
                r'\b\d{4}\s+\d{4}\s+\d{4}\s+\d{4}\b',  # Common test patterns
                r'\b0000\s+0000\s+0000\s+0000\b',      # All zeros
                r'\b1111\s+1111\s+1111\s+1111\b',      # All ones
            ],
            'phone': [
                r'\b000[-.\s]?000[-.\s]?0000\b',       # All zeros
                r'\b111[-.\s]?111[-.\s]?1111\b',       # All ones
                r'\b123[-.\s]?456[-.\s]?7890\b',       # Sequential
            ],
            'email': [
                r'^test@example\.com$',
                r'^admin@localhost$',
                r'^user@domain\.com$',
            ],
            'ip': [
                r'\b0\.0\.0\.0\b',                     # All zeros
                r'\b127\.0\.0\.1\b',                   # Localhost
                r'\b255\.255\.255\.255\b',             # Broadcast
            ],
        }
    
    def find_sensitive_data(self, text: str, entities: Optional[List[str]] = None) -> List[RecognizerResult]:
        """
        Find sensitive data in text.
        
        :param text: Text to analyze
        :param entities: List of entity types to detect
        :return: List of recognition results
        """
        results = self.recognizer_manager.analyze(text, entities)
        
        # Apply false positive filtering
        filtered_results = self._filter_false_positives(results, text)
        
        return filtered_results
    
    def _filter_false_positives(self, results: List[RecognizerResult], text: str) -> List[RecognizerResult]:
        """Filter out common false positive patterns."""
        filtered_results = []
        
        for result in results:
            if not self._is_false_positive(result, text):
                filtered_results.append(result)
        
        return filtered_results
    
    def _is_false_positive(self, result: RecognizerResult, text: str) -> bool:
        """Check if a result is likely a false positive."""
        entity_type = result.entity_type.lower()
        
        if entity_type in self.false_positive_patterns:
            for pattern in self.false_positive_patterns[entity_type]:
                if re.search(pattern, result.text, re.IGNORECASE):
                    return True
        
        # Additional context-based filtering
        if self._has_suspicious_context(result, text):
            return True
        
        return False
    
    def _has_suspicious_context(self, result: RecognizerResult, text: str) -> bool:
        """Check if the result has suspicious context that might indicate a false positive."""
        # Get surrounding context
        context_start = max(0, result.start - 50)
        context_end = min(len(text), result.end + 50)
        context = text[context_start:context_end].lower()
        
        # Suspicious keywords that might indicate test data (as separate words)
        suspicious_keywords = [
            'test ', ' sample ', ' demo ', ' fake ', ' dummy ',
            ' placeholder ', ' template ', ' mock ', ' stub '
        ]
        
        for keyword in suspicious_keywords:
            if keyword in context:
                return True
        
        # Check for specific test patterns
        if 'test email:' in context or 'test phone:' in context:
            return True
        
        return False
    
    def process_batch(self, texts: List[str], entities: Optional[List[str]] = None) -> List[List[RecognizerResult]]:
        """
        Process multiple texts in batch.
        
        :param texts: List of texts to process
        :param entities: List of entity types to detect
        :return: List of recognition results for each text
        """
        results = []
        for text in texts:
            text_results = self.find_sensitive_data(text, entities)
            results.append(text_results)
        
        return results
    
    def get_statistics(self, results: List[RecognizerResult]) -> Dict[str, Any]:
        """Get statistics about the recognition results."""
        return self.recognizer_manager.get_results_summary(results)
    
    def filter_by_confidence(self, results: List[RecognizerResult], min_confidence: float = 0.7) -> List[RecognizerResult]:
        """Filter results by minimum confidence score."""
        return self.recognizer_manager.filter_results_by_confidence(results, min_confidence)
    
    def filter_by_entity(self, results: List[RecognizerResult], entity_types: List[str]) -> List[RecognizerResult]:
        """Filter results by entity types."""
        return self.recognizer_manager.filter_results_by_entity(results, entity_types)
    
    def mask_sensitive_data(self, text: str, results: List[RecognizerResult], mask_char: str = '*') -> str:
        """
        Mask sensitive data in text.
        
        :param text: Original text
        :param results: Recognition results
        :param mask_char: Character to use for masking
        :return: Text with sensitive data masked
        """
        # Sort results by start position in reverse order to avoid index issues
        sorted_results = sorted(results, key=lambda x: x.start, reverse=True)
        
        masked_text = text
        for result in sorted_results:
            # Create mask of appropriate length
            mask = mask_char * (result.end - result.start)
            masked_text = masked_text[:result.start] + mask + masked_text[result.end:]
        
        return masked_text
    
    def extract_entities(self, text: str, entity_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Extract entities of specific types from text.
        
        :param text: Text to analyze
        :param entity_types: List of entity types to extract
        :return: Dictionary mapping entity types to lists of extracted values
        """
        results = self.find_sensitive_data(text, entity_types)
        
        extracted = {}
        for result in results:
            entity_type = result.entity_type
            if entity_type not in extracted:
                extracted[entity_type] = []
            extracted[entity_type].append(result.text)
        
        return extracted
    
    def validate_entities(self, text: str, entities: Optional[List[str]] = None) -> Dict[str, List[Tuple[str, bool]]]:
        """
        Validate entities and return validation results.
        
        :param text: Text to analyze
        :param entities: List of entity types to validate
        :return: Dictionary mapping entity types to lists of (value, is_valid) tuples
        """
        results = self.find_sensitive_data(text, entities)
        
        validated = {}
        for result in results:
            entity_type = result.entity_type
            if entity_type not in validated:
                validated[entity_type] = []
            
            is_valid = result.validation_result if result.validation_result is not None else True
            validated[entity_type].append((result.text, is_valid))
        
        return validated
