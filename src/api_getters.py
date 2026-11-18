from datetime import datetime, timezone
import requests
import os        # Lets Python read environment variables (where your API key is stored)
import requests  # Lets Python send requests to web APIs over the internet


# This function would ideally make an API call to check the domain's registration age.
def get_domain_age(extracted_realdomain):

    joined_url = "https://rdap.org/domain/" + extracted_realdomain

    try:
        response = requests.get(joined_url, timeout=10) ## This puts a 10-second timeout in case the API is slow

        if response.status_code == 200:
            data = response.json()  # this gets the JSON response from the API
            events = data.get("events", [])

            for event in events:
                if event.get("eventAction") == "registration":
                    registration_date = event.get("eventDate")

                    if registration_date:
                        registration_datetime = datetime.fromisoformat(
                            registration_date.replace("Z", "+00:00")
                        )

                        domain_age = (datetime.now(timezone.utc) - datetime.fromisoformat(registration_date)).days
                        return domain_age

    except requests.exceptions.Timeout:
        print("RDAP request timed out")
        return None

    except requests.exceptions.RequestException as error:
        print("RDAP request failed:", error)
        return None

    except (ValueError, TypeError):
        print("Could not interpret the RDAP response")
        return None


## Second function CHECKS the reputation of the url by sending a request to the ABUSEIPDB API. It checks if the URL is flagged as malicious.
# My program handles :

# Handles timeouts.
# Checks the response status.
# Handles connection errors.
# Returns None if the lookup fails.


def Url_lookup(extracted_url):

    api_endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find" #Get the API

    request_body = request_body = {
    "client": {
        "clientId": "phishing_email_checker",
        "clientVersion": "1.0"
    },
    "threatInfo": {
        "threatTypes": [
            "MALWARE",
            "SOCIAL_ENGINEERING"
        ],
        "platformTypes": [
            "ANY_PLATFORM"
        ],
        "threatEntryTypes": [
            "URL"
        ],
        "threatEntries": [
            {"url": url} for url in extracted_url
        ]
    }
}

    responses = requests.post(
        api_endpoint,
        params=(
            "key": os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")  # Get the API key from environment variables
        ),
        json=request_body #
        timeout=8
    ) ## This puts a 10-second timeout in case the API is slow

    try:
        if responses.status_code == 200:
            data = responses.json()
            new_data = data.get("params", {})
            return new_data

    except requests.exceptions.Timeout:
        print("request timed out")
        return None

    except requests.exceptions.RequestException as error:
        print("request failed:", error)
        return None

    except (ValueError, TypeError):
        print("Could not interpret the ABUSEIPDB response")
        return None