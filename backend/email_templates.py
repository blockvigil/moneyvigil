new_bill_email_body = """
Hi {name},

{created_by} added a new bill to {group_name} on MoneyVigil.

Description
-----------------
{description}

Total Amount
-----------------
{total_amount}

Your share
-----------------
{user_share}

Payers
-----------------
{payers}


Visit group here
-----------------
{group_link}

{optional_receipt}

Thanks,
MoneyVigil

--------------------
You can unsubscribe from all email notifications by visiting the following link once:
{unsubscribe_link}
"""

new_bill_receipt = """
You can download an uploaded copy of the receipt by visiting this link:
------------------------------------------------------------------------
{receipt_link}
"""

group_addition_email_body = """
Hi {name},

{inviter_name}({inviter_email}) has added you to a new group {group_name} on MoneyVigil.

Visit group here
-----------------
{group_link}

Thanks,
MoneyVigil

--------------------
You can unsubscribe from all email notifications by visiting the following link once:
{unsubscribe_link}
"""

##################################

alpha_invite_email_body = """
Hi {name},

Thank you for signing up for MoneyVigil Alpha to split and manage expenses. Visit the exclusive link below to setup your account.

{signup_link}

All expenses on MoneyVigil are managed in groups of friends. Feel free to add their email even if they aren't on MoneyVigil yet. You can create as many groups and share multiple groups with the same set of friends.

Please contact us through Intercom or reply to this email to give us feedback.

Thanks,
Your friends at MoneyVigil
"""

alpha_invite_email_subject = "You are invited to try out MoneyVigil Alpha"
