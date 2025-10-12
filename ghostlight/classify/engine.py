from __future__ import annotations

import re
from typing import Dict, List, Tuple

GDPR_RULES = {
	# Email
	"PII.Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
	# Phone (US-like). Keep strict to reduce FPs
	"PII.Phone": re.compile(r"(?<![A-Za-z0-9])(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?![A-Za-z0-9])"),
	# SSN (US)
	"PII.SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
	# Aadhaar (India)
	"PII.Aadhaar": re.compile(r"\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b"),
	# PAN (India)
	"PII.PAN": re.compile(r"(?:panNumber\s*:\s*|PAN\s*:\s*|panNo\s*=\s*|pan\s*:\s*|<)?\s*[A-Z]{5}[0-9]{4}[A-Z]\s*(?:>)?", re.IGNORECASE),
	# Passport (generic format)
	"PII.Passport": re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b"),
	# Driver License (US-like)
	"PII.DriverLicense": re.compile(r"\b[A-Z]{1,2}[-\s]?\d{5,8}\b"),
	# IBAN
	"PII.IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
	# IPv4
	"PII.IPv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
	# IPv6
	"PII.IPv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
	# Coordinates
	"PII.Coordinates": re.compile(r"[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?)\,\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)"),
	# Date of Birth (YYYY-MM-DD or DD/MM/YYYY)
	"PII.DOB": re.compile(r"\b((19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])|(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/(19|20)\d{2})\b"),
	# Vehicle VIN (17 chars, excludes I,O,Q)
	"PII.VIN": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
}

HIPAA_RULES = {
	"PHI.MRN": re.compile(r"\bMRN[:\s-]*\d{6,10}\b", re.IGNORECASE),
	"PHI.NPI": re.compile(r"\b[0-9]{10}\b"),  # National Provider Identifier
	"PHI.MedicareID": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}[A-Z]\b"),
	"PHI.MedicalRecord": re.compile(r"(?i)\b(diagnosis|prescription|medication|patient|condition)[:\s]*.{10,100}\b"),
}

PCI_RULES = {
	"PCI.CreditCard": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
}


# Intellectual property / technical artifacts
IP_RULES = {
	"IP.JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
	"IP.PEM.Key": re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----"),
	"IP.API.Path": re.compile(r"\b/api/[A-Za-z0-9/_-]{3,}\b"),
}

SECRETS_RULES = {
	# AWS credentials
	"Secrets.AWS.AccessKeyID": re.compile(r"\b(?:A3T|AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA|ANVA|AKPA)[0-9A-Z]{16}\b"),
	"Secrets.AWS.SecretAccessKey": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
	# Amazon MWS Auth Token
	"Secrets.AWS.MWSAuthToken": re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
	# SNS Topic ARN disclosure (not a secret but sensitive)
	"Secrets.AWS.SNS.TopicARN": re.compile(r"arn:aws:sns:[a-z0-9\-]+:[0-9]+:[A-Za-z0-9\-_]+"),
	# AWS Cognito identifiers (broad)
	"Secrets.AWS.Cognito.PoolId": re.compile(r"\b[a-z]{2}-[a-z]+-\d{1}_[A-Za-z0-9_-]{6,}\b"),
	"Secrets.AWS.Cognito.GUID": re.compile(r":[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}"),
	# GitHub
	"Secrets.GitHub.Token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
	# Stripe and Pictatic (two different lengths)
	"Secrets.Stripe.LiveKey": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
	"Secrets.Pictatic.APIKey": re.compile(r"\bsk_live_[0-9a-z]{32}\b"),
	# Google
	"Secrets.Google.APIKey": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
	"Secrets.GCP.ServiceAccountKey": re.compile(r"\"type\"\s*:\s*\"service_account\""),
	# Cloudinary
	"Secrets.Cloudinary.Credentials": re.compile(r"cloudinary://[0-9]{15}:[0-9A-Za-z\-_]+@[0-9A-Za-z\-_]+"),
	# FCM
	"Secrets.FCM.ServerKey": re.compile(r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}"),
	# Mailchimp
	"Secrets.Mailchimp.APIKey": re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),
	# Mailgun
	"Secrets.Mailgun.APIKey": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
	# Sendgrid
	"Secrets.Sendgrid.APIKey": re.compile(r"\bSG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}\b"),
	# Shopify
	"Secrets.Shopify.CustomAppAccess": re.compile(r"\bshpca_[a-fA-F0-9]{32}\b"),
	"Secrets.Shopify.PrivateAppAccess": re.compile(r"\bshppa_[a-fA-F0-9]{32}\b"),
	"Secrets.Shopify.SharedSecret": re.compile(r"\bshpss_[a-fA-F0-9]{32}\b"),
	# Square
	"Secrets.Square.AccessToken": re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"),
	"Secrets.Square.OAuthSecret": re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b"),
	# Slack tokens & webhook
	"Secrets.Slack.BotToken": re.compile(r"\bxoxb-[0-9A-Za-z\-]{51}\b"),
	"Secrets.Slack.UserToken": re.compile(r"\bxoxp-[0-9A-Za-z\-]{72}\b"),
	"Secrets.Slack.Webhook": re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z\-_]{10}/B[0-9A-Za-z\-_]{10}/[0-9A-Za-z\-_]{23}"),
	# SonarQube token
	"Secrets.SonarQube.Token": re.compile(r"(?i)sonar.{0,50}(?:\"|'|`)?[0-9a-f]{40}(?:\"|'|`)?"),
	# Dynatrace
	"Secrets.Dynatrace.Token": re.compile(r"dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}"),
	# Facebook
	"Secrets.Facebook.ClientID": re.compile(r"(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]"),
	"Secrets.Facebook.Secret": re.compile(r"(?i)(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}['\"]"),
	# LinkedIn
	"Secrets.LinkedIn.ClientID": re.compile(r"(?i)linkedin(.{0,20})?[0-9a-z]{12}"),
	# Paypal Braintree
	"Secrets.Braintree.AccessToken": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
	# Twilio
	"Secrets.Twilio.APIKey": re.compile(r"(?i)twilio(.{0,20})?SK[0-9a-f]{32}"),
	# Twitter
	"Secrets.Twitter.Secret": re.compile(r"(?i)twitter(.{0,20})?[0-9a-z]{35,44}"),
	# Basic auth in URL
	"Secrets.BasicAuth.URL": re.compile(r"(?i)[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\s]"),
	# Additional patterns
	"Secrets.RSA.PrivateKey": re.compile(r"-----BEGIN RSA PRIVATE KEY-----\s*\n[A-Za-z0-9+/=\s]+\n-----END RSA PRIVATE KEY-----"),
	"Secrets.OpenSSH.PrivateKey": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----\s*\n[A-Za-z0-9+/=\s]+\n-----END OPENSSH PRIVATE KEY-----"),
	"Secrets.PGP.PrivateKey": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----\s*\n[A-Za-z0-9+/=\s]+\n-----END PGP PRIVATE KEY BLOCK-----"),
	"Secrets.Generic.BearerToken": re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
	"Secrets.Database.ConnectionString": re.compile(r"(?i)(mongodb|mysql|postgresql|redis|sqlserver)://[^\s]+"),
	# Azure Storage connection string
	"Secrets.Azure.Storage": re.compile(r"(?i)DefaultEndpointsProtocol=.+;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,};EndpointSuffix=[^;\s]+"),
	# GitLab Personal Access Token
	"Secrets.GitLab.PersonalToken": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
	# Discord bot token
	"Secrets.Discord.BotToken": re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"),
	# Telegram bot token
	"Secrets.Telegram.BotToken": re.compile(r"\b\d{9,10}:AA[0-9A-Za-z_-]{33}\b"),
	# Twilio Account SID and Auth Token
	"Secrets.Twilio.AccountSID": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
	"Secrets.Twilio.AuthToken": re.compile(r"\b[0-9a-fA-F]{32}\b"),
	# Slack app/user tokens (additional prefixes)
	"Secrets.Slack.AppToken": re.compile(r"\bxox[ascr]-[0-9A-Za-z\-]{40,}\b"),
	# GitHub App and new token formats
	"Secrets.GitHub.AppToken": re.compile(r"\b(?:ghs|ghu|gho)_[A-Za-z0-9]{36}\b"),
	"Secrets.GitHub.PersonalTokenNew": re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"),
	# Stripe webhook signing secret
	"Secrets.Stripe.WebhookSecret": re.compile(r"\bwhsec_[A-Za-z0-9]{32}\b"),
	# Azure AD application/client IDs (GUID)
	"Secrets.AzureAD.ClientID": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
}


def classify_text(text: str) -> Dict[str, List[str]]:
	# Backward-compatible labels summary
	labels: Dict[str, List[str]] = {"GDPR": [], "HIPAA": [], "PCI": [], "SECRETS": [], "IP": []}
	for bucket, rules in (("GDPR", GDPR_RULES), ("HIPAA", HIPAA_RULES), ("PCI", PCI_RULES), ("SECRETS", SECRETS_RULES), ("IP", IP_RULES)):
		for name, pattern in rules.items():
			if pattern.search(text or ""):
				labels[bucket].append(name)
	return labels


def classify_text_detailed(text: str, use_custom_recognizers: bool = True) -> List[Tuple[str, str, List[str]]]:
	# Returns list of (bucket, pattern_name, matches)
	detailed: List[Tuple[str, str, List[str]]] = []
	corpus = text or ""
	for bucket, rules in (("GDPR", GDPR_RULES), ("HIPAA", HIPAA_RULES), ("PCI", PCI_RULES), ("SECRETS", SECRETS_RULES), ("IP", IP_RULES)):
		for name, pattern in rules.items():
			try:
				found = list({m.group(0) for m in pattern.finditer(corpus)})
			except Exception:
				# If pattern not suitable for finditer, fallback to boolean
				found = [name] if pattern.search(corpus) else []
			if found:
				detailed.append((bucket, name, found))
	
	# Apply custom recognizer validation if enabled
	if use_custom_recognizers:
		try:
			from .custom_recognizer_integration import custom_recognizer_integration
			detailed = custom_recognizer_integration.validate_detections(detailed, corpus)
		except ImportError:
			# Custom recognizers not available, continue with original results
			pass
	
	return detailed


def score_severity(num_detections: int, num_matches: int) -> Tuple[str, str]:
	if num_matches >= 5 or num_detections >= 3:
		return ("high", "Detected more than 5 PII or Secrets")
	if num_matches >= 2 or num_detections >= 2:
		return ("medium", "Multiple sensitive patterns detected")
	return ("low", "Single sensitive pattern detected")


