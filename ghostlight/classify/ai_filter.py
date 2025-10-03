"""
AI-powered context filter to reduce false positives using LLMs
"""
import os
import json
import logging
from typing import List, Tuple, Optional, Dict, Any

logger = logging.getLogger(__name__)


def is_ollama_available() -> bool:
    """Check if Ollama is available locally"""
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False


def is_openai_available() -> bool:
    """Check if OpenAI API key is configured"""
    return bool(os.getenv("OPENAI_API_KEY"))


def is_anthropic_available() -> bool:
    """Check if Anthropic API key is configured"""
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def query_ollama(prompt: str, model: str = "llama3.2") -> Optional[str]:
    """Query local Ollama instance"""
    try:
        import requests
        
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Low temperature for consistent results
                    "top_p": 0.9,
                }
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get("response", "").strip()
        else:
            logger.debug(f"Ollama request failed: {response.status_code}")
            return None
            
    except Exception as e:
        logger.debug(f"Error querying Ollama: {e}")
        return None


def query_openai(prompt: str, model: str = "gpt-4o-mini") -> Optional[str]:
    """Query OpenAI API"""
    try:
        import openai
        
        client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in data classification. Answer with ONLY 'TRUE_POSITIVE' or 'FALSE_POSITIVE' followed by a brief reason."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=100
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.debug(f"Error querying OpenAI: {e}")
        return None


def query_anthropic(prompt: str, model: str = "claude-3-haiku-20240307") -> Optional[str]:
    """Query Anthropic API"""
    try:
        import anthropic
        
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        
        response = client.messages.create(
            model=model,
            max_tokens=100,
            temperature=0.1,
            system="You are a cybersecurity expert specializing in data classification. Answer with ONLY 'TRUE_POSITIVE' or 'FALSE_POSITIVE' followed by a brief reason.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return response.content[0].text.strip()
        
    except Exception as e:
        logger.debug(f"Error querying Anthropic: {e}")
        return None


def create_analysis_prompt(
    pattern_name: str,
    matched_value: str,
    sample_text: str,
    table_name: str,
    db_engine: str,
    column_names: Optional[List[str]] = None
) -> str:
    """Create a prompt for AI analysis"""
    
    column_info = ""
    if column_names:
        column_info = f"\nColumn names in table: {', '.join(column_names[:10])}"
    
    prompt = f"""Analyze this security detection to determine if it's a TRUE_POSITIVE or FALSE_POSITIVE:

DATABASE CONTEXT:
- Database Engine: {db_engine}
- Table Name: {table_name}{column_info}

DETECTION:
- Pattern Detected: {pattern_name}
- Matched Value: {matched_value}
- Sample Context: {sample_text[:500]}

ANALYSIS CRITERIA:
1. Is this a system/metadata table? (e.g., mysql.user, pg_catalog)
2. Is the matched value actually sensitive data or just metadata?
3. Does the context suggest this is authentication data (password hashes, not plaintext)?
4. Is this a timestamp/datetime being misidentified as coordinates/phone/SSN?
5. Is this configuration data rather than user data?

System tables and metadata should be FALSE_POSITIVE.
Only real exposed sensitive user data should be TRUE_POSITIVE.

Answer with ONLY:
- "TRUE_POSITIVE: <reason>" if this is real sensitive data exposure
- "FALSE_POSITIVE: <reason>" if this is system metadata or misidentification

Answer:"""
    
    return prompt


def ai_classify_detection(
    pattern_name: str,
    matched_value: str,
    sample_text: str,
    table_name: str,
    db_engine: str,
    column_names: Optional[List[str]] = None,
    use_ai: str = "auto"  # "auto", "ollama", "openai", "anthropic", "off"
) -> Tuple[bool, str]:
    """
    Use AI to classify if a detection is a true positive or false positive
    
    Returns:
        (is_true_positive: bool, reason: str)
    """
    
    # Check if AI should be used
    if use_ai == "off":
        return True, "AI filtering disabled"
    
    # Determine which AI to use
    ai_provider = None
    if use_ai == "auto":
        if is_ollama_available():
            ai_provider = "ollama"
        elif is_openai_available():
            ai_provider = "openai"
        elif is_anthropic_available():
            ai_provider = "anthropic"
    else:
        ai_provider = use_ai
    
    if not ai_provider:
        logger.debug("No AI provider available, using rule-based filtering only")
        return True, "No AI available"
    
    # Create prompt
    prompt = create_analysis_prompt(
        pattern_name, matched_value, sample_text, 
        table_name, db_engine, column_names
    )
    
    # Query AI
    response = None
    if ai_provider == "ollama":
        logger.debug(f"Using Ollama for AI filtering on table '{table_name}'")
        response = query_ollama(prompt)
    elif ai_provider == "openai":
        logger.debug(f"Using OpenAI for AI filtering on table '{table_name}'")
        response = query_openai(prompt)
    elif ai_provider == "anthropic":
        logger.debug(f"Using Anthropic for AI filtering on table '{table_name}'")
        response = query_anthropic(prompt)
    
    if not response:
        logger.debug("AI query failed, keeping detection")
        return True, "AI query failed"
    
    # Parse response
    response_lower = response.lower()
    
    if "false_positive" in response_lower or "false positive" in response_lower:
        # Extract reason
        if ":" in response:
            reason = response.split(":", 1)[1].strip()
        else:
            reason = "AI classified as false positive"
        
        logger.info(f"🤖 AI filtered out detection in '{table_name}': {reason}")
        return False, f"AI: {reason}"
    
    elif "true_positive" in response_lower or "true positive" in response_lower:
        # Extract reason
        if ":" in response:
            reason = response.split(":", 1)[1].strip()
        else:
            reason = "AI classified as true positive"
        
        logger.info(f"🚨 AI confirmed detection in '{table_name}': {reason}")
        return True, f"AI: {reason}"
    
    else:
        # Unclear response, keep detection to be safe
        logger.debug(f"Unclear AI response: {response}")
        return True, "AI response unclear"


def get_ai_summary() -> Dict[str, Any]:
    """Get summary of available AI providers"""
    summary = {
        "ollama_available": is_ollama_available(),
        "openai_available": is_openai_available(),
        "anthropic_available": is_anthropic_available(),
        "recommended": None
    }
    
    if summary["ollama_available"]:
        summary["recommended"] = "ollama (local, free, private)"
    elif summary["openai_available"]:
        summary["recommended"] = "openai (cloud, requires API key)"
    elif summary["anthropic_available"]:
        summary["recommended"] = "anthropic (cloud, requires API key)"
    else:
        summary["recommended"] = "none (install Ollama or configure API keys)"
    
    return summary


def install_ollama_instructions() -> str:
    """Return instructions for installing Ollama"""
    return """
🤖 AI-POWERED FALSE POSITIVE REDUCTION

To enable AI filtering, install Ollama (free, local, private):

1. Install Ollama:
   curl -fsSL https://ollama.com/install.sh | sh

2. Pull a model (recommended: llama3.2, ~2GB):
   ollama pull llama3.2

3. Start Ollama (if not auto-started):
   ollama serve

4. Re-run your scan - AI filtering will be automatic!

Alternative: Use cloud AI (requires API keys):
- OpenAI: export OPENAI_API_KEY=sk-...
- Anthropic: export ANTHROPIC_API_KEY=sk-ant-...

For more info: https://ollama.com
"""

