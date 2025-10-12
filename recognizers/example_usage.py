#!/usr/bin/env python3
"""
Example usage of custom recognizers for data processing.

This script demonstrates how to use the custom recognizers to find
and filter sensitive information in text data.
"""

from data_processor import DataProcessor
from custom_recognizer_manager import CustomRecognizerManager


def main():
    """Main function demonstrating recognizer usage."""
    
    # Initialize the data processor
    processor = DataProcessor()
    
    # Sample text with various types of sensitive information
    sample_text = """
    John Doe's contact information:
    Email: john.doe@example.com
    Phone: +1-555-123-4567
    Credit Card: 4532-1234-5678-9014
    Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    IP Address: 192.168.1.1
    Website: https://www.example.com
    Date of Birth: 1990-05-15
    IBAN: GB82WEST12345698765432
    
    Test data that should be filtered:
    Test Email: test@example.com
    Test Phone: 000-000-0000
    Test Credit Card: 0000-0000-0000-0000
    """
    
    print("=== Custom Recognizer Example ===\n")
    
    # Find all sensitive data
    print("1. Finding all sensitive data:")
    results = processor.find_sensitive_data(sample_text)
    
    for result in results:
        print(f"  - {result.entity_type}: {result.text} (confidence: {result.score:.2f})")
    
    print(f"\nTotal results found: {len(results)}\n")
    
    # Get statistics
    print("2. Statistics:")
    stats = processor.get_statistics(results)
    print(f"  - Total results: {stats['total_results']}")
    print(f"  - High confidence: {stats['high_confidence_results']}")
    print(f"  - Medium confidence: {stats['medium_confidence_results']}")
    print(f"  - Low confidence: {stats['low_confidence_results']}")
    print(f"  - Entities found: {stats['entities_found']}\n")
    
    # Filter by confidence
    print("3. High confidence results only:")
    high_conf_results = processor.filter_by_confidence(results, min_confidence=0.7)
    for result in high_conf_results:
        print(f"  - {result.entity_type}: {result.text} (confidence: {result.score:.2f})")
    
    print(f"\nHigh confidence results: {len(high_conf_results)}\n")
    
    # Extract specific entities
    print("4. Extracting specific entities:")
    email_results = processor.extract_entities(sample_text, ['EMAIL_ADDRESS'])
    phone_results = processor.extract_entities(sample_text, ['PHONE_NUMBER'])
    
    print(f"  - Emails found: {email_results.get('EMAIL_ADDRESS', [])}")
    print(f"  - Phones found: {phone_results.get('PHONE_NUMBER', [])}\n")
    
    # Mask sensitive data
    print("5. Masking sensitive data:")
    masked_text = processor.mask_sensitive_data(sample_text, results)
    print(masked_text)
    
    # Validate entities
    print("\n6. Validating entities:")
    validated = processor.validate_entities(sample_text)
    for entity_type, validations in validated.items():
        print(f"  - {entity_type}:")
        for value, is_valid in validations:
            status = "✓ Valid" if is_valid else "✗ Invalid"
            print(f"    {value}: {status}")
    
    # Process batch of texts
    print("\n7. Batch processing:")
    batch_texts = [
        "Contact: john@example.com, phone: 555-123-4567",
        "Credit card: 4532-1234-5678-9014",
        "IP: 192.168.1.1, website: https://example.com"
    ]
    
    batch_results = processor.process_batch(batch_texts)
    for i, text_results in enumerate(batch_results):
        print(f"  Text {i+1}: {len(text_results)} entities found")
        for result in text_results:
            print(f"    - {result.entity_type}: {result.text}")


if __name__ == "__main__":
    main()
