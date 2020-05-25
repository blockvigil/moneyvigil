import boto3
import random
import botocore
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from db_wrapper import DBCallsWrapper
from db_session import Session
from dynaconf import settings
from email_templates import *
import urllib

def is_subscribed_to_emails(db_sesh, user_uuid):
    """
    Returns a tuple of email subscription status and the user db object
    :param user_uuid: the UUID associated with a user
    :return: (True|False, user_db_object) or (False, None) in case user db entry does not exist
    """
    dbcall = DBCallsWrapper()
    u = dbcall.query_user_by_(session_obj=db_sesh, uuid=user_uuid)
    if u:
        return u.email_subscription, u
    else:
        return False, None


def send_activation_email(token, email_addr):
    activateEmail = urllib.parse.urlencode({'activateEmail': email_addr})
    email_subject = 'Your MoneyVigil activation code'
    email_text = f'Enter this code at the signup activation page on MoneyVigi;: {token}'
    email_text += f'\n\n{settings["MONEYVIGIL_LINK_PREFIX"]}/signup?{activateEmail}&activateCode={token}'
    return send_ses_email(email_addr=email_addr, subject=email_subject, text=email_text)


def send_invite_email(email_addr, token, name, inviter_name, inviter_email):
    signupEmail = urllib.parse.urlencode({'signupEmail': email_addr})
    signup_name = urllib.parse.urlencode({'name': name})
    email_subject = f'{inviter_name} has invited you to MoneyVigil'
    email_text = f'Hi {name},'
    email_text += f'\n\n{inviter_name} ({inviter_email}) has invited you to try out MoneyVigil to manage expenses. Enter this code at the signup page on MoneyVigil: {token}'
    email_text += f'\n\n{settings["MONEYVIGIL_LINK_PREFIX"]}/signup?{signupEmail}&inviteCode={token}&{signup_name}'
    return send_ses_email(email_addr=email_addr, subject=email_subject, text=email_text)


def send_group_addition_email(inviter_name, inviter_email, member_uuid, group_name, group_uuid):
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    # check if user being added to the group is subscribed to email notifications
    send_email_state = is_subscribed_to_emails(db_sesh, member_uuid)
    if send_email_state[0] and send_email_state[1]:
        u_db = send_email_state[1]
        unsubscribe_obj = dbcall.query_unsubscribetoken_by_(session_obj=db_sesh, user=u_db.uuid)
        unsubscribe_token = unsubscribe_obj.code
        group_link = f"{settings['MONEYVIGIL_LINK_PREFIX']}/groups/{group_uuid}"
        unsubscribe_link = f"{settings['MONEYVIGIL_LINK_PREFIX']}/unsubscribe/{unsubscribe_token}"
        formatting_args = {
            'name': u_db.name,
            'group_name': group_name,
            'group_link': group_link,
            'inviter_name': inviter_name,
            'inviter_email': inviter_email,
            'unsubscribe_link': unsubscribe_link
        }
        email_body = group_addition_email_body.format(**formatting_args)
        send_ses_email(
            email_addr=u_db.email,
            subject='You have been added to a MoneyVigil group',
            text=email_body
        )
    Session.remove()

def send_ses_email(email_addr, subject, text, from_email_addr=None):
    ses_cred = settings['SES_CREDENTIALS']
    ses_client = boto3.client(
        service_name='ses',
        region_name=ses_cred["region"],
        aws_access_key_id=ses_cred['accessKeyId'],
        aws_secret_access_key=ses_cred["secretAccessKey"]
    )
    email_subject = subject
    email_text = text
    email_recipient = email_addr
    msg_container = MIMEMultipart('mixed')
    msg_container['Subject'] = email_subject
    msg_container['From'] = ses_cred["from"] if not from_email_addr else from_email_addr
    msg_container['To'] = email_recipient
    # inner alternative container
    msg_inner = MIMEMultipart('alternative')
    textpart = MIMEText(email_text.encode('utf-8'), 'plain', 'utf-8')
    msg_inner.attach(textpart)
    msg_container.attach(msg_inner)
    response_data = None
    try:
        response = ses_client.send_raw_email(
            Destinations=[
                email_recipient
            ],
            RawMessage={
                'Data': msg_container.as_string(),
            },
            Source=ses_cred["from"]
        )
    except botocore.exceptions.ClientError as e:
        response_data = {
            "code": e.response['Error']['Code'],
            "msg": e.response['Error']['Message'],
            "requestid": e.response['ResponseMetadata']['RequestId'],
            "http_code": e.response['ResponseMetadata']['HTTPStatusCode']
        }
        print(response_data)
        return False
    else:
        response_data = response
    print(response_data)
    return True


def regen_send_activation(db_session, user_obj):
    # generate a new token
    tkn = random.choice(range(100000, 999999))
    # send out new activation token
    send_activation_email(tkn, user_obj.email)
    user_obj.activated = 0
    user_obj.activation_token = tkn
    user_obj.activation_expiry = int(time.time()) + 180 * 1000  # 180 seconds expiry
    db_session.add(user_obj)
    db_session.commit()
