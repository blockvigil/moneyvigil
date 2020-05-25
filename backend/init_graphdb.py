from neo4j.v1 import GraphDatabase
import json
import eth_account
from eth_utils import keccak, to_normalized_address
from models import *
from neomodel import install_all_labels
from dynaconf import settings
import neomodel

driver = GraphDatabase.driver(settings['NEO4J']['URL'], auth=(settings['NEO4J']['USERNAME'], settings['NEO4J']['PASSWORD']))


def create_test_members(tx):
    group_secret = 'fe79917f-793e-403a-8c6b-55460d4fb047'
    u1_uuid = 'c398200b-ec08-4c32-bd09-7854838ba98'
    u2_uuid = 'f5b413ac-1d1a-46d5-868d-37a06c98eb1e'
    g_addr = to_normalized_address(eth_account.Account.privateKeyToAccount(keccak(text=group_secret)).address)
    u1_addr = to_normalized_address(eth_account.Account.privateKeyToAccount(keccak(text=f'{group_secret}{u1_uuid}')).address)
    u2_addr = to_normalized_address(eth_account.Account.privateKeyToAccount(keccak(text=f'{group_secret}{u2_uuid}')).address)
    return tx.run(f"""
    merge (u3:User {{uuid: '06647970-197f-462f-b2f8-81a705229679', email: 'email@swaroophegde.com', name: 'Swaroop'}})
    merge (u1:User {{uuid: 'c398200b-ec08-4c32-bd09-7854838ba988', email: 'anomit@blockvigil.com', name: 'Jalal'}})
    merge (u2:User {{uuid: 'f5b413ac-1d1a-46d5-868d-37a06c98eb1e', email: 'anomit.ghosh@gmail.com', name: 'Anomit'}})
    """)

# 0x497f6332957DbCa1A1947D26bEa710deaD838471
# 0x2334Ca63a3C79212CDe2Dc8Cdce8256D931FBde1


if __name__ == '__main__':
    with driver.session() as session:
        install_all_labels()
        session.write_transaction(create_test_members)