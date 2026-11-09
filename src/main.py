import re
import sys
from urllib.parse import urlsplit

email = sys.stdin.read()
def extract_urls(email):
    return re.findall(r"https?://[^\s<>\"']+", email)

def extract_hostname(url):
    return urlsplit(url).hostname

def check_suspicious_words(email):
    suspicious_words=[ "urgent",
            "password",
            "verify your account",
            "suspended",
            "click here",
            "immediately"
        ]

    detected_suspicious_words = []

    for word in suspicious_words:
        if word in email.lower():
            detected_suspicious_words.append(word)
        else:
            continue

    return detected_suspicious_words

extracted_urls = extract_urls(email)
print("Extracted URLs:", extracted_urls)

detected_words = check_suspicious_words(email)
print("Suspicious words found:", detected_words)

extracted_hostnames = [extract_hostname(url) for url in extracted_urls]
print("Extracted hostnames:", extracted_hostnames)