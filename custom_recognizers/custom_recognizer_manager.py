from typing import List, Dict, Any, Optional
from base_recognizer import BaseRecognizer, RecognizerResult
from custom_credit_card_recognizer import CustomCreditCardRecognizer
from custom_crypto_recognizer import CustomCryptoRecognizer
from custom_date_recognizer import CustomDateRecognizer
from custom_email_recognizer import CustomEmailRecognizer
from custom_iban_recognizer import CustomIbanRecognizer
from custom_ip_recognizer import CustomIpRecognizer
from custom_phone_recognizer import CustomPhoneRecognizer
from custom_url_recognizer import CustomUrlRecognizer


class CustomRecognizerManager:
    """
    Manager class for all custom recognizers.
    
    This class manages multiple recognizers and provides a unified interface
    for analyzing text and detecting various types of entities.
    """
    
    def __init__(self):
        """Initialize the recognizer manager with all available recognizers."""
        self.recognizers = {
            'credit_card': CustomCreditCardRecognizer(),
            'crypto': CustomCryptoRecognizer(),
            'date': CustomDateRecognizer(),
            'email': CustomEmailRecognizer(),
            'iban': CustomIbanRecognizer(),
            'ip': CustomIpRecognizer(),
            'phone': CustomPhoneRecognizer(),
            'url': CustomUrlRecognizer(),
        }
        
        # Map entity types to recognizer keys
        self.entity_to_recognizer_map = {
            'CREDIT_CARD': 'credit_card',
            'CRYPTO': 'crypto',
            'DATE_TIME': 'date',
            'EMAIL_ADDRESS': 'email',
            'IBAN_CODE': 'iban',
            'IP_ADDRESS': 'ip',
            'PHONE_NUMBER': 'phone',
            'URL': 'url',
        }
    
    def analyze(self, text: str, entities: Optional[List[str]] = None) -> List[RecognizerResult]:
        """
        Analyze text using all or specified recognizers.
        
        :param text: Text to analyze
        :param entities: List of entity types to detect (if None, detect all)
        :return: List of recognition results
        """
        all_results = []
        
        # If specific entities are requested, only use those recognizers
        if entities:
            for entity in entities:
                recognizer_key = self.entity_to_recognizer_map.get(entity)
                if recognizer_key and recognizer_key in self.recognizers:
                    results = self.recognizers[recognizer_key].analyze(text)
                    all_results.extend(results)
        else:
            # Use all recognizers
            for recognizer in self.recognizers.values():
                results = recognizer.analyze(text)
                all_results.extend(results)
        
        # Remove duplicates and sort by position
        return self._remove_duplicates_and_sort(all_results)
    
    def analyze_single_entity(self, text: str, entity_type: str) -> List[RecognizerResult]:
        """
        Analyze text using a single recognizer.
        
        :param text: Text to analyze
        :param entity_type: Type of entity to detect
        :return: List of recognition results
        """
        if entity_type in self.recognizers:
            return self.recognizers[entity_type].analyze(text)
        return []
    
    def get_supported_entities(self) -> List[str]:
        """Get list of all supported entity types."""
        return list(self.recognizers.keys())
    
    def add_recognizer(self, name: str, recognizer: BaseRecognizer):
        """Add a new recognizer to the manager."""
        self.recognizers[name] = recognizer
    
    def remove_recognizer(self, name: str):
        """Remove a recognizer from the manager."""
        if name in self.recognizers:
            del self.recognizers[name]
    
    def _remove_duplicates_and_sort(self, results: List[RecognizerResult]) -> List[RecognizerResult]:
        """Remove duplicate results and sort by start position."""
        # Remove duplicates based on start, end, and entity type
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.start, result.end, result.entity_type)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        # Sort by start position
        unique_results.sort(key=lambda x: x.start)
        
        return unique_results
    
    def get_results_summary(self, results: List[RecognizerResult]) -> Dict[str, Any]:
        """Get a summary of recognition results."""
        summary = {
            'total_results': len(results),
            'entities_found': {},
            'high_confidence_results': 0,
            'medium_confidence_results': 0,
            'low_confidence_results': 0,
        }
        
        for result in results:
            entity_type = result.entity_type
            if entity_type not in summary['entities_found']:
                summary['entities_found'][entity_type] = 0
            summary['entities_found'][entity_type] += 1
            
            # Categorize by confidence level
            if result.score >= 0.8:
                summary['high_confidence_results'] += 1
            elif result.score >= 0.5:
                summary['medium_confidence_results'] += 1
            else:
                summary['low_confidence_results'] += 1
        
        return summary
    
    def filter_results_by_confidence(self, results: List[RecognizerResult], min_confidence: float = 0.5) -> List[RecognizerResult]:
        """Filter results by minimum confidence score."""
        return [result for result in results if result.score >= min_confidence]
    
    def filter_results_by_entity(self, results: List[RecognizerResult], entity_types: List[str]) -> List[RecognizerResult]:
        """Filter results by entity types."""
        return [result for result in results if result.entity_type in entity_types]
