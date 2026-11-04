"""
training_data.py
----------------
A SMALL list of example emails used to teach the three algorithms.

The SRS says the dataset is "not yet finalised", so this is only a starter set
to make the model work. A real project would use thousands of emails
(for example, a public spam dataset from Kaggle).

Label meaning:  1 = scam,   0 = legitimate
"""

SCAM_EMAILS = [
    "URGENT: Your bank account has been suspended. Verify your password immediately by clicking the link below or your account will be closed.",
    "Congratulations! You have won a million dollar lottery prize. Send your bank details and processing fee to claim your winnings now.",
    "Dear beneficiary, I have 25 million dollars to transfer and need your help. I will give you 30 percent. Reply with your bank account number.",
    "Your PayPal account has been limited. Confirm your identity and credit card details within 24 hours to restore access.",
    "Act now! Limited time offer. Get rich quick working from home, earn 5000 dollars per week with no experience. Click here to join.",
    "You have been selected for a free iPhone. Just pay shipping and enter your card number to receive your gift.",
    "Final warning: your Netflix payment failed. Update your billing information now or your subscription will be cancelled.",
    "Your package could not be delivered. Pay a small customs fee at the link below to reschedule delivery.",
    "Tax department notice: you owe back taxes. Pay immediately with gift cards to avoid arrest and legal action.",
    "Security alert: unusual login detected. Enter your OTP and PIN here to secure your account immediately.",
    "Congratulations winner! Claim your free vacation voucher. Offer expires today. Provide your passport number and credit card.",
    "I am a lonely widow with a large inheritance and want to donate to charity. Please send your personal details and bank account.",
    "Earn money fast investing in crypto. Guaranteed 300 percent returns in 7 days. Send bitcoin to this wallet now.",
    "Your Amazon account is locked. Verify your payment method immediately to avoid permanent suspension.",
    "Dear customer, your KYC has expired. Update your PAN and Aadhaar details immediately through this link or your account will be blocked.",
    "You have won the lottery of 25 lakh rupees. Contact our agent and deposit the registration fee to receive your prize.",
    "Miracle weight loss pill, lose 30 pounds in 10 days. Order now, 90 percent discount, limited stock, click here.",
    "Your email storage is full. Login with your password at this link right now to avoid losing all your emails.",
    "Job offer: work from home as a payment processor and earn 500 dollars daily. We need your bank account and social security number to start.",
    "Urgent business proposal. Confidential transaction of 10 million dollars. I need a trustworthy partner, reply with your full name and bank details.",
    "Your computer is infected with a virus! Call our support number now and allow remote access to fix it immediately.",
    "Claim your tax refund now. Submit your credit card number and date of birth through the secure link to receive your money.",
    "Dear user, your bank account will be blocked today. Click the link to update your net banking password and OTP.",
    "Exclusive offer, you are our lucky winner of a gift card. Complete this survey and enter your card details to claim the reward.",
    "Pay a refundable deposit to secure your dream apartment. The owner is abroad, so send the money by wire transfer today.",
    "Your invoice is attached. Payment overdue. Open the attachment and enable macros to view the invoice immediately.",
    "Last chance! Double your money in 24 hours. Guaranteed investment, no risk. Transfer funds to this account now.",
    "Your Apple ID has been disabled. Click here to verify your identity and password to restore your account.",
    "Government grant approved for you. Pay a small processing fee to release your free grant money today.",
    "Congratulations, you have been shortlisted for a scholarship. Send a registration fee and your bank details to confirm your seat.",
]

LEGIT_EMAILS = [
    "Hi team, reminder that our weekly meeting is tomorrow at 10 am in the conference room. Please bring your project updates.",
    "Thank you for your order. Your package will be delivered on Friday. You can track the shipment from your orders page.",
    "Hi Rahul, can you send me the notes from yesterday's lecture? I missed the last half hour. Thanks!",
    "Dear students, the BCA lab test will be held on Monday. Please carry your ID cards and submit your records on time.",
    "Your monthly statement is now available. You can view it whenever you like. No action is required from you.",
    "Hello Professor, I have attached my assignment for the software engineering course. Please let me know if any changes are needed.",
    "Happy birthday! Hope you have a wonderful day. Let's catch up for lunch this weekend.",
    "The project deadline has been moved to next Thursday. Please update your schedule and finish the testing report by then.",
    "Please find attached the minutes of the meeting held on Tuesday. Let me know if I missed anything.",
    "Your appointment with the doctor is confirmed for Wednesday at 4 pm. Please arrive ten minutes early.",
    "Hi Mom, I reached the hostel safely. The journey was fine. I will call you in the evening after class.",
    "Newsletter: this month we published three new articles on Python programming and data structures. Read them whenever you have time.",
    "Your library book is due on Saturday. You can renew it online or return it to the front desk.",
    "Thanks for your feedback on the draft. I have made the changes you suggested and shared the updated document.",
    "We are organising a farewell party for Meera on Friday evening. Please let me know if you can attend.",
    "Your flight is confirmed for 14 November. The e-ticket is attached. Please reach the airport two hours before departure.",
    "Hi all, the college fest committee meeting is scheduled for 3 pm. The agenda includes budget, volunteers and event schedule.",
    "Receipt for your payment of 499 rupees to the electricity board. Thank you for paying your bill on time.",
    "Could you review my pull request when you have a chance? I added the unit tests for the login module.",
    "Dear parents, the annual sports day will be held on 20 December. Children should wear their sports uniform.",
    "Following up on our conversation, I would be glad to schedule an interview next week. Please share your availability.",
    "Your subscription renewal went through successfully. Thank you for being a member. Visit your account page for details.",
    "The seminar on machine learning is open to all BCA students. Registration is free and seats are limited to the auditorium capacity.",
    "Hey, are you free for a quick call this afternoon? I wanted to discuss the group project report.",
    "Attached is the draft of our SRS document. Please review sections three and four and add your comments by Friday.",
    "Thank you for contacting support. Your ticket has been resolved. If the problem returns, simply reply to this email.",
    "The cafeteria will remain closed on Sunday for maintenance. Regular timings will resume from Monday morning.",
    "Congratulations on completing your course! Your certificate is attached. Best wishes for your future.",
    "Weekly report: we completed the database design and started coding the user interface. Testing begins next week.",
    "Dinner at our place on Saturday? We are making biryani. Bring your cousin along, everyone is welcome.",
]

# Join both lists into one, and make a matching list of labels (1 = scam, 0 = legit)
EMAILS = SCAM_EMAILS + LEGIT_EMAILS
LABELS = [1] * len(SCAM_EMAILS) + [0] * len(LEGIT_EMAILS)
