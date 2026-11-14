import re
from datetime import datetime, timezone
from email import message, policy
from email.parser import BytesParser
from urllib.parse import urlsplit
import tldextract
import ipaddress
import os        # Lets Python read environment variables (where your API key is stored)
import requests  # Lets Python send requests to web APIs over the internet


# This only read th eemail contents but the emails have different part to it ithas the headers, the bodyy, the attachments and such.
#email = sys.stdin.read()

with open("email.eml", "rb") as email_file:
    email = BytesParser(policy=policy.default).parse(email_file)

body = email.get_body(preferencelist=("plain",))
body_content = body.get_content() if body else ""

print("Sender:", email["From"])
print("Subject:", email["Subject"])
print("Authentication:", email["Authentication-Results"])



## This function extracts URLs from the email.

def extract_urls(email):
    cleaned_urls = [url.strip() for url in re.findall(r"https?://[^\s<>\"']+", email)]
    return cleaned_urls

#This extract the hostname of a URL;
def extract_hostname(url):
    return urlsplit(url).hostname

 # I realized that extracting the  full hostname is not reallyuseful so I decided to extract the registered domain since some hackers migh  use real company names to there left and can be passed as hostnames but because
 # of this people cannot easily tell the difference. Therefore extracting the registered domain is useful.
 ## THEN AM THINKING OF INTRODUCING APIS CALL TO CHECK THE time this domain was registered since most fake links are a few days old.

 def extract_realdomain(url):
    return tldextract.extract(url).top_domain_under_public_suffix # Extract 

def hostname_an_ipadress(url): ## I could possibly send the adress to  API IP REputation to see if others have reported this to a a servises like ABUSEIPDB
    hostname = extract_hostname(url)
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


  # This function would ideally make an API call to check the domain's registration age.
def get_domain_age(extracted_realdomain):
  
    joined_url = "https://rdap.org/domain/" + extracted_realdomain
    response = requests.get(joined_url, timeout=10) ## This puts a 10-second timeout in case the API is slow

    if response.status_code == 200:
        data = response.json()# this gets the JSON response from the API
        events = data["events"]
        for event in events:
            if event.get("eventAction") == "registration":
                registration_date = event.get("eventDate")
                if registration_date:
                    return (datetime.now(timezone.utc) - datetime.fromisoformat(registration_date)).days
    elif response.status_code == 404:
        print("Domain not found")
    else:
        print("Failed to fetch domain information")

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

def check_dmarc(email):
    headers = email.get_all("Authentication-Results")

    if not headers:
        return "none"

    first_header = headers[0].lower()

    match = re.search(r"dmarc=(\w+)", first_header)

    if match:
        return match.group(1)
    return "none"

def assess_mail(detected_words, hostname_an_ipadress_results):

    score = 0
    if len(detected_words) > 1:
        score += 1
    if any(hostname_an_ipadress_results):
        score += 4
    if dmarc_result == "fail":
        score += 1
    if score > 5:
        return "Probably Suspicious"
    
    
    else:
        return "No trace of obvious suspicious words"
  

extracted_urls = extract_urls(body_content)
print("Extracted URLs:", extracted_urls)


extracted_hostnames = [extract_hostname(url) for url in extracted_urls]
print("Extracted hostnames:", extracted_hostnames)

extracted_realdomains = [extract_realdomain(url) for url in extracted_urls]
print("Extracted real domains:", extracted_realdomains)

hostname_an_ipadress_results = [hostname_an_ipadress(url) for url in extracted_urls]
print("Hostname is IP address:", hostname_an_ipadress_results)

detected_words = check_suspicious_words(body_content)
print("Suspicious words found:", detected_words)
dmarc_result = check_dmarc(email)
print("DMARC result:", dmarc_result)

assessment = assess_mail(detected_words, hostname_an_ipadress_results)
print("Email assessment:", assessment)


