from db_models import MoneyVigilUser, MoneyVigilUnsubscribeTokens, MoneyVigilInvites, Base, \
    MoneyVigilCorporateEntity, MoneyVigilUserEthereumAddresses
from eth_utils import keccak, to_normalized_address
import bcrypt
import time
from db_session import Session
from dynaconf import settings

hashed_pw = bcrypt.hashpw('password', bcrypt.gensalt(12))  # 'password' is the password for this user


def fill_entries(session):
    u1 = MoneyVigilUser(**settings['NEO'])
    session.add(u1)
    try:
        session.commit()
    except Exception as e:
        print('Exception adding user', e)
    us1 = MoneyVigilUnsubscribeTokens(
        code='b4c2084e-d889-4455-acce-1c3a39658146',
        user=u1.uuid
    )

    session.add(us1)
    try:
        session.commit()
    except Exception as e:
        print('Exception adding unsubscribe tokens ', e)

if __name__ == '__main__':
    s = Session()
    fill_entries(s)
    Session.remove()