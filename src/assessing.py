


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