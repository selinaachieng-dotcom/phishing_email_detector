
import re
import ipaddress
import tldextract
from urllib.parse import urlsplit

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
