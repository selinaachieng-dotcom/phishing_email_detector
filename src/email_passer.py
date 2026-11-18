
from email import policy
from email.parser import BytesParser


# This only read th eemail contents but the emails have different part to it ithas the headers, the bodyy, the attachments and such.
#email = sys.stdin.read()

with open("email.eml", "rb") as email_file:
    email = BytesParser(policy=policy.default).parse(email_file)

body = email.get_body(preferencelist=("plain",))
body_content = body.get_content() if body else ""

print("Sender:", email["From"])
print("Subject:", email["Subject"])
print("Authentication:", email["Authentication-Results"])





  
