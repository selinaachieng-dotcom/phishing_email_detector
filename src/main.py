from url_checks import extract_urls, extract_hostname, extract_realdomain, hostname_an_ipadress
from api_getters import get_domain_age
from content_checks import check_suspicious_words
from header_checks import check_dmarc
from email_passer import  body_content, email
from assessing import assess_mail




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


