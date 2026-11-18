import re


def check_dmarc(email):
    headers = email.get_all("Authentication-Results")

    if not headers:
        return "none"

    first_header = headers[0].lower()

    match = re.search(r"dmarc=(\w+)", first_header)

    if match:
        return match.group(1)
    return "none"