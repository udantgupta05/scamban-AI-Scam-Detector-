"""
samples.py  -  ready-made emails for the "Try a sample" dropdown in app.py.
Add your own: just put a new  "name": "email text"  line in the dictionary.
"""

SAMPLES = {
    "Fake bank scam (with headers)": """From: "PayPal Support" <service@paypa1-security.xyz>
Reply-To: recovery.desk@gmail.com
Subject: URGENT: Your account has been limited
Received: from mail.fake-host.example ([203.0.113.45]) by mx.example.com
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail

Dear customer, your account has been limited. Verify your password and card number immediately
at http://paypa1-security.xyz/login or your account will be closed.""",

    "Lottery scam (plain text)": """Congratulations! You are the lucky winner of a 25 lakh rupees lottery prize.
To claim your winnings, send your bank account number and a small registration fee today.
Click here: http://bit.ly/claim-prize-now""",

    "Normal college email": """From: "Dr. Dimple Chawla" <dimple@college.example.edu>
Subject: SRS submission reminder
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass

Hi all, please submit the final SRS document by Friday. Review sections three and four before sending. Thanks.""",

    "Looks normal, but fake sender": """From: "Microsoft Support" <help@micros0ft-help.top>
Subject: Meeting notes

Hi, please find the meeting notes from Tuesday here: http://bit.ly/notes-tue. Let me know your thoughts.""",
}
