# Custom Recognizers for Ghostlight

This directory contains custom implementations of data recognizers. These recognizers are designed to find and process sensitive information in text data while reducing false positives.

## Features

- **No External Dependencies**: Custom implementations that don't rely on external deps
- **False Positive Reduction**: Built-in filtering to reduce common false positives
- **Multiple Entity Types**: Support for credit cards, crypto addresses, dates, emails, IBAN, IP addresses, phone numbers, and URLs
- **Validation**: Built-in validation for detected entities
- **Batch Processing**: Support for processing multiple texts
- **Confidence Scoring**: Confidence scores for each detection
- **Masking**: Ability to mask sensitive data in text

## Supported Entity Types

1. **Credit Cards** (`CREDIT_CARD`)
   - Uses Luhn algorithm for validation
   - Supports various formats (Visa, MasterCard, Amex, etc.)

2. **Cryptocurrency Addresses** (`CRYPTO`)
   - Bitcoin address validation (P2PKH, P2SH, Bech32)
   - Checksum validation

3. **Dates** (`DATE_TIME`)
   - Multiple date formats (ISO 8601, MM/DD/YYYY, DD/MM/YYYY, etc.)
   - Context-aware detection

4. **Email Addresses** (`EMAIL_ADDRESS`)
   - RFC-compliant email validation
   - Domain validation

5. **IBAN Codes** (`IBAN_CODE`)
   - International Bank Account Number validation
   - Country-specific format validation
   - Checksum validation

6. **IP Addresses** (`IP_ADDRESS`)
   - IPv4 and IPv6 support
   - Built-in validation using Python's ipaddress module

7. **Phone Numbers** (`PHONE_NUMBER`)
   - US and international formats
   - Extension support
   - Basic validation

8. **URLs** (`URL`)
   - HTTP/HTTPS URLs
   - Domain validation
   - Quoted URL support

## Usage

### Basic Usage

```python
from data_processor import DataProcessor

# Initialize processor
processor = DataProcessor()

# Analyze text
text = "Contact: john@example.com, phone: 555-123-4567"
results = processor.find_sensitive_data(text)

# Print results
for result in results:
    print(f"{result.entity_type}: {result.text} (confidence: {result.score:.2f})")
```

### Advanced Usage

```python
from custom_recognizer_manager import CustomRecognizerManager

# Initialize manager
manager = CustomRecognizerManager()

# Analyze specific entities
results = manager.analyze(text, entities=['EMAIL_ADDRESS', 'PHONE_NUMBER'])

# Filter by confidence
high_conf_results = manager.filter_results_by_confidence(results, min_confidence=0.7)

# Get statistics
stats = manager.get_results_summary(results)
print(f"Found {stats['total_results']} entities")
```

### Batch Processing

```python
# Process multiple texts
texts = [
    "Email: user1@example.com",
    "Phone: 555-123-4567",
    "Credit card: 4532-1234-5678-9012"
]

batch_results = processor.process_batch(texts)
```

### Masking Sensitive Data

```python
# Mask sensitive data
masked_text = processor.mask_sensitive_data(text, results, mask_char='*')
print(masked_text)
```

## False Positive Reduction

The system includes built-in false positive reduction:

1. **Pattern-based filtering**: Common test patterns are filtered out
2. **Context analysis**: Suspicious context keywords are detected
3. **Validation**: Built-in validation for each entity type
4. **Confidence scoring**: Results are scored based on confidence

## File Structure

```
recognizers/
├── base_recognizer.py              # Base class for all recognizers
├── custom_credit_card_recognizer.py
├── custom_crypto_recognizer.py
├── custom_date_recognizer.py
├── custom_email_recognizer.py
├── custom_iban_recognizer.py
├── custom_ip_recognizer.py
├── custom_phone_recognizer.py
├── custom_url_recognizer.py
├── custom_recognizer_manager.py    # Manager for all recognizers
├── data_processor.py               # Main data processing class
├── example_usage.py                # Example usage script
├── requirements.txt                # Dependencies
└── README.md                       # This file
```

## Running the Example

```bash
cd recognizers
python example_usage.py
```

## Customization

### Adding New Recognizers

1. Create a new recognizer class inheriting from `BaseRecognizer`
2. Implement the required methods
3. Add it to the `CustomRecognizerManager`

### Modifying Patterns

Each recognizer has configurable patterns. You can modify the `PATTERNS` list in each recognizer class to add or modify detection patterns.

### Adjusting Confidence Scores

Confidence scores can be adjusted in the pattern definitions or in the validation logic.

## Performance Considerations

- The recognizers use regex patterns for initial detection
- Validation is performed only on detected patterns
- Batch processing is optimized for multiple texts
- Memory usage is minimal as no external libraries are loaded

## Security Notes

- All validation is performed locally
- No data is sent to external services
- Sensitive data can be masked before processing
- Results include confidence scores for manual review

## License

This code is part of the Ghostlight project and follows the same license terms.
