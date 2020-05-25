from db_models import MoneyVigilUser, MoneyVigilUnsubscribeTokens, MoneyVigilInvites, Base, \
    MoneyVigilCorporateEntity, MoneyVigilUserEthereumAddresses
from eth_utils import keccak, to_normalized_address
import bcrypt
import time
from db_session import Session

hashed_pw = bcrypt.hashpw('password', bcrypt.gensalt(12))  # 'password' is the password for this user


def fill_entries(session):
    u1 = MoneyVigilUser(
        uuid='c398200b-ec08-4c32-bd09-7854838ba988',
        name="Jalal",
        email='anomit@blockvigil.com',
        password=hashed_pw,
        activated=1,
        activation_token=000000,
        activated_at=int(time.time()),
        remaining_invites=1000
    )

    u2 = MoneyVigilUser(
        uuid='f5b413ac-1d1a-46d5-868d-37a06c98eb1e',
        name="Anomit",
        email='anomit.ghosh@gmail.com',
        password=hashed_pw,
        activated=1,
        activation_token=000000,
        activated_at=int(time.time()),
        remaining_invites=1000
    )

    u3 = MoneyVigilUser(
        uuid='06647970-197f-462f-b2f8-81a705229679',
        name="Swaroop",
        email='email@swaroophegde.com',
        password=hashed_pw,
        activated=1,
        activation_token=000000,
        activated_at=int(time.time()),
        remaining_invites=1000
    )
    session.add(u1)
    session.add(u2)
    session.add(u3)
    try:
        session.commit()
    except Exception as e:
        print('Exception adding users', e)
    us1 = MoneyVigilUnsubscribeTokens(
        code='b4c2084e-d889-4455-acce-1c3a39658146',
        user='c398200b-ec08-4c32-bd09-7854838ba988'
    )

    us2 = MoneyVigilUnsubscribeTokens(
        code='8bf9538a-f45d-4fa3-8168-adb87712f5bd',
        user='f5b413ac-1d1a-46d5-868d-37a06c98eb1e'
    )

    us3 = MoneyVigilUnsubscribeTokens(
        code='3d3be058-0704-4fe2-87a2-2f0cc8fd59cb',
        user='06647970-197f-462f-b2f8-81a705229679'
    )

    session.add(us1)
    session.add(us2)
    session.add(us3)
    try:
        session.commit()
    except Exception as e:
        print('Exception adding unsubscribe tokens ', e)

if __name__ == '__main__':
    s = Session()
    fill_entries(s)
    Session.remove()