"""
Git authentication utilities for private repositories
"""
import os
from typing import Optional, Dict
from urllib.parse import urlparse, urlunparse


def build_authenticated_url(url: str, token: Optional[str] = None, username: Optional[str] = None) -> str:
    """
    Build an authenticated git URL for cloning private repositories
    
    Supports:
    - GitHub Personal Access Token (PAT)
    - GitLab Personal Access Token
    - Bitbucket App Password
    - Generic HTTPS credentials
    
    Args:
        url: Original repository URL
        token: Personal access token or password
        username: Username (optional, defaults based on provider)
    
    Returns:
        Authenticated URL string
    
    Examples:
        GitHub: https://TOKEN@github.com/user/repo.git
        GitLab: https://oauth2:TOKEN@gitlab.com/user/repo.git
        Bitbucket: https://USERNAME:TOKEN@bitbucket.org/user/repo.git
    """
    if not url.startswith("https://"):
        return url  # SSH URLs don't need modification
    
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    # Auto-detect provider and set defaults
    if "github.com" in hostname:
        # GitHub uses token as username
        auth = token if token else ""
        netloc = f"{auth}@{hostname}" if auth else hostname
    elif "gitlab.com" in hostname or "gitlab" in hostname:
        # GitLab uses oauth2:token format
        auth = f"oauth2:{token}" if token else ""
        netloc = f"{auth}@{hostname}" if auth else hostname
    elif "bitbucket.org" in hostname:
        # Bitbucket uses username:app_password
        if username and token:
            netloc = f"{username}:{token}@{hostname}"
        else:
            netloc = hostname
    else:
        # Generic HTTPS git server
        if username and token:
            netloc = f"{username}:{token}@{hostname}"
        elif token:
            netloc = f"{token}@{hostname}"
        else:
            netloc = hostname
    
    # Preserve port if present
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    
    authenticated = parsed._replace(netloc=netloc)
    return urlunparse(authenticated)


def get_git_credentials() -> Dict[str, Optional[str]]:
    """
    Extract git credentials from environment variables
    
    Supports:
    - GIT_TOKEN / GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN
    - GIT_USERNAME / GITHUB_USERNAME
    - GIT_PASSWORD
    
    Returns:
        Dictionary with token and username
    """
    token = (
        os.environ.get("GIT_TOKEN") or
        os.environ.get("GITHUB_TOKEN") or
        os.environ.get("GITLAB_TOKEN") or
        os.environ.get("BITBUCKET_TOKEN") or
        os.environ.get("GIT_PASSWORD")
    )
    
    username = (
        os.environ.get("GIT_USERNAME") or
        os.environ.get("GITHUB_USERNAME") or
        os.environ.get("BITBUCKET_USERNAME")
    )
    
    return {
        "token": token,
        "username": username,
    }


def get_auth_help_message(url: str) -> str:
    """Generate helpful authentication message based on git provider"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    if "github.com" in hostname:
        return """
GitHub Private Repository Authentication:
1. Create Personal Access Token: https://github.com/settings/tokens
   - Scopes needed: repo (full access)
2. Set environment variable:
   export GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE
3. Or use SSH URL: git@github.com:user/repo.git
"""
    elif "gitlab" in hostname:
        return """
GitLab Private Repository Authentication:
1. Create Personal Access Token: Settings > Access Tokens
   - Scopes needed: read_repository
2. Set environment variable:
   export GITLAB_TOKEN=YOUR_TOKEN_HERE
3. Or use SSH URL: git@gitlab.com:user/repo.git
"""
    elif "bitbucket" in hostname:
        return """
Bitbucket Private Repository Authentication:
1. Create App Password: Settings > App passwords
   - Permissions needed: Repositories (Read)
2. Set environment variables:
   export BITBUCKET_USERNAME=your_username
   export BITBUCKET_TOKEN=your_app_password
3. Or use SSH URL: git@bitbucket.org:user/repo.git
"""
    else:
        return """
Private Repository Authentication:
1. Set environment variables:
   export GIT_TOKEN=your_token_or_password
   export GIT_USERNAME=your_username (if needed)
2. Or use SSH URL with configured SSH keys
3. Or configure git credential helper:
   git config --global credential.helper store
"""

