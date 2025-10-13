"""
Integration module for custom recognizers with Ghostlight's classification system.

This module bridges the custom recognizers with the existing Ghostlight patterns
to provide enhanced validation and false positive reduction.
"""

from typing import List, Tuple, Dict, Optional, Set
import re
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'custom_recognizers'))
from data_processor import DataProcessor
from base_recognizer import RecognizerResult


class CustomRecognizerIntegration:
    """
    Integration class that bridges custom recognizers with Ghostlight's classification system.
    """
    
    def __init__(self):
        """Initialize the integration with custom recognizers."""
        self.data_processor = DataProcessor()
        
        # Map Ghostlight pattern names to custom recognizer entity types
        self.pattern_to_entity_map = {
            # GDPR patterns
            "PII.Email": "EMAIL_ADDRESS",
            "PII.Phone": "PHONE_NUMBER", 
            "PII.IBAN": "IBAN_CODE",
            "PII.IPv4": "IP_ADDRESS",
            "PII.IPv6": "IP_ADDRESS",
            "PII.DOB": "DATE_TIME",
            
            # PCI patterns
            "PCI.CreditCard": "CREDIT_CARD",
            
            # IP patterns
            "IP.API.Path": "URL",
            
            # Additional patterns we can enhance
            "PII.Coordinates": None,  # No direct mapping
            "PII.SSN": None,  # No direct mapping
            "PII.Aadhaar": None,  # No direct mapping
            "PII.PAN": None,  # No direct mapping
            "PII.Passport": None,  # No direct mapping
            "PII.DriverLicense": None,  # No direct mapping
            "PII.VIN": None,  # No direct mapping
        }
        
        # Reverse mapping for quick lookup
        self.entity_to_patterns_map = {}
        for pattern, entity in self.pattern_to_entity_map.items():
            if entity:
                if entity not in self.entity_to_patterns_map:
                    self.entity_to_patterns_map[entity] = []
                self.entity_to_patterns_map[entity].append(pattern)
    
    def validate_detections(self, detections: List[Tuple[str, str, List[str]]], text: str) -> List[Tuple[str, str, List[str]]]:
        """
        Validate detections using custom recognizers to reduce false positives.
        
        Args:
            detections: List of (bucket, pattern_name, matches) tuples
            text: Original text content
            
        Returns:
            Filtered list of validated detections
        """
        if not detections:
            return detections
        
        validated_detections = []
        
        for bucket, pattern_name, matches in detections:
            # Check if this pattern can be validated by custom recognizers
            entity_type = self.pattern_to_entity_map.get(pattern_name)
            
            if entity_type:
                # Use custom recognizer to validate matches
                validated_matches = self._validate_matches_with_custom_recognizer(
                    matches, text, entity_type, pattern_name
                )
                
                if validated_matches:
                    validated_detections.append((bucket, pattern_name, validated_matches))
            else:
                # No custom recognizer available, keep original matches
                validated_detections.append((bucket, pattern_name, matches))
        
        return validated_detections
    
    def _validate_matches_with_custom_recognizer(
        self, 
        matches: List[str], 
        text: str, 
        entity_type: str, 
        pattern_name: str
    ) -> List[str]:
        """
        Validate matches using the appropriate custom recognizer.
        
        Args:
            matches: List of matched strings
            text: Original text content
            entity_type: Type of entity to validate
            pattern_name: Original pattern name for context
            
        Returns:
            List of validated matches
        """
        validated_matches = []
        
        # Get custom recognizer results for the text
        custom_results = self.data_processor.find_sensitive_data(text, [entity_type])
        
        # Create a set of validated values from custom recognizers
        validated_values = {result.text for result in custom_results}
        
        # Check each match against validated values
        for match in matches:
            # Direct match
            if match in validated_values:
                validated_matches.append(match)
                continue
            
            # Try to find partial matches or similar values
            # This handles cases where the regex might capture slightly different text
            # than what the custom recognizer validates
            for validated_value in validated_values:
                if self._is_similar_match(match, validated_value, entity_type):
                    validated_matches.append(match)
                    break
        
        return validated_matches
    
    def _is_similar_match(self, match: str, validated_value: str, entity_type: str) -> bool:
        """
        Check if a match is similar to a validated value.
        
        This handles cases where regex patterns might capture slightly different
        text than what custom recognizers validate (e.g., different spacing, formatting).
        """
        # Normalize both strings for comparison
        match_normalized = self._normalize_text(match, entity_type)
        validated_normalized = self._normalize_text(validated_value, entity_type)
        
        # Direct match after normalization
        if match_normalized == validated_normalized:
            return True
        
        # For some entity types, check if one contains the other
        if entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"]:
            return match_normalized in validated_normalized or validated_normalized in match_normalized
        
        return False
    
    def _normalize_text(self, text: str, entity_type: str) -> str:
        """
        Normalize text for comparison based on entity type.
        """
        if entity_type == "EMAIL_ADDRESS":
            return text.lower().strip()
        elif entity_type == "PHONE_NUMBER":
            # Remove common separators
            return re.sub(r'[-.\s()]', '', text)
        elif entity_type == "CREDIT_CARD":
            # Remove common separators
            return re.sub(r'[-.\s]', '', text)
        elif entity_type == "IP_ADDRESS":
            return text.strip()
        elif entity_type == "URL":
            return text.lower().strip()
        else:
            return text.strip()
    
    def enhance_detections_with_custom_recognizers(
        self, 
        text: str, 
        existing_detections: List[Tuple[str, str, List[str]]]
    ) -> List[Tuple[str, str, List[str]]]:
        """
        Enhance existing detections with additional findings from custom recognizers.
        
        Args:
            text: Text content to analyze
            existing_detections: Existing detections from Ghostlight patterns
            
        Returns:
            Enhanced list of detections
        """
        # Get all custom recognizer results
        custom_results = self.data_processor.find_sensitive_data(text)
        
        # Convert custom recognizer results to Ghostlight format
        enhanced_detections = list(existing_detections)
        
        for result in custom_results:
            # Map entity type back to Ghostlight pattern names
            pattern_names = self.entity_to_patterns_map.get(result.entity_type, [])
            
            for pattern_name in pattern_names:
                # Check if this pattern already exists in detections
                existing_pattern = None
                for bucket, pname, matches in existing_detections:
                    if pname == pattern_name:
                        existing_pattern = (bucket, pname, matches)
                        break
                
                if existing_pattern:
                    # Add to existing pattern if not already present
                    bucket, pname, matches = existing_pattern
                    if result.text not in matches:
                        matches.append(result.text)
                else:
                    # Create new detection
                    bucket = self._get_bucket_for_pattern(pattern_name)
                    enhanced_detections.append((bucket, pattern_name, [result.text]))
        
        return enhanced_detections
    
    def _get_bucket_for_pattern(self, pattern_name: str) -> str:
        """
        Get the appropriate bucket for a pattern name.
        """
        if pattern_name.startswith("PII."):
            return "GDPR"
        elif pattern_name.startswith("PCI."):
            return "PCI"
        elif pattern_name.startswith("PHI."):
            return "HIPAA"
        elif pattern_name.startswith("IP."):
            return "IP"
        elif pattern_name.startswith("Secrets."):
            return "SECRETS"
        else:
            return "GDPR"  # Default fallback
    
    def get_validation_statistics(self, detections: List[Tuple[str, str, List[str]]]) -> Dict[str, any]:
        """
        Get statistics about validation results.
        
        Args:
            detections: List of detections
            
        Returns:
            Dictionary with validation statistics
        """
        stats = {
            "total_detections": len(detections),
            "validated_by_custom_recognizers": 0,
            "not_validated": 0,
            "validation_breakdown": {}
        }
        
        for bucket, pattern_name, matches in detections:
            entity_type = self.pattern_to_entity_map.get(pattern_name)
            
            if entity_type:
                stats["validated_by_custom_recognizers"] += 1
                if pattern_name not in stats["validation_breakdown"]:
                    stats["validation_breakdown"][pattern_name] = {
                        "entity_type": entity_type,
                        "match_count": 0
                    }
                stats["validation_breakdown"][pattern_name]["match_count"] += len(matches)
            else:
                stats["not_validated"] += 1
        
        return stats


# Global instance for easy access
custom_recognizer_integration = CustomRecognizerIntegration()
