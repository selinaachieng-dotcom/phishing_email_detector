


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