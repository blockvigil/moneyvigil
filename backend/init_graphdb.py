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
    u1 = settings['NEO']
    return tx.run(f"""
    merge (u1:User {{uuid: '{u1['uuid']}', email: '{u1['email']}', name: '{u1['name']}'}})
    """)

if __name__ == '__main__':
    with driver.session() as session:
        install_all_labels()
        session.write_transaction(create_test_members)