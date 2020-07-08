import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.httpclient
import tornado.escape
from tornado.options import define, options
from eth_utils import to_normalized_address
from models import *
from neo4j.v1 import GraphDatabase
import logging
import coloredlogs
import tenacity
import sys
import aiohttp
import json
import aioredis
import aioredlock
import time
from email_helper import send_ses_email
from email_templates import new_bill_email_body, new_bill_receipt
from db_wrapper import DBCallsWrapper
from db_session import mysql_engine_path
from db_models import (
    MoneyVigilUser, MoneyVigilInvites, MoneyVigilUnsubscribeTokens, MoneyVigilReward, MoneyVigilBill, MoneyVigilGroup,
    MoneyVigilEvent, MoneyVigilTransaction, MoneyVigilActivity, MoneyVigilCorporateEntity, MoneyVigilCorporateEntityRole,
    MoneyVigilCorporateEntityPermission, MoneyVigilUserEthereumAddresses
)
from tornado_sqlalchemy import as_future, make_session_factory, SessionMixin
from dynaconf import settings
from constants import *
from namehash import namehash
from redis_conn import provide_async_redis_conn
from ev_api_calls import ev_add_entity_global_owners, ev_add_entity_employees
from ethvigil.EVCore import EVCore
from ethvigil.exceptions import EVHTTPError

evc = EVCore(verbose=False)
dai_contract_instance = evc.generate_contract_sdk(
    # contract_address=to_normalized_address('0x4F96Fe3b7A6Cf9725f59d353F723c1bDb64CA6Aa'),
    contract_address=to_normalized_address(settings['DaiContract']),
    app_name='Dai'
)

ens_manager_contract = evc.generate_contract_sdk(
    contract_address=to_normalized_address(settings['ENSManagerContract']),
    app_name='ENSManagerContract'
)

cdai_contract = evc.generate_contract_sdk(
    contract_address=to_normalized_address(settings['cDaiContract']),
    app_name='cDai'
)

first_run = True
ENTITY_CONTRACTS = set()
# populate roles for this entity
with open('./entity_roles.json', 'r') as f:
    ROLES_LIST = json.load(f)

with open('./entity_permissions.json', 'r') as f:
    PERMISSIONS_LIST = json.load(f)
# app.config['WTF_CSRF_ENABLED'] = False

with open('./default_role_permissions.json', 'r') as f:
    DEFAULT_ROLE_PERMISSIONS = json.load(f)

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


define("port", default=5764, help="run on the given port", type=int)

tornado_logger = logging.getLogger('VigilMoneyWebhookListener')
tornado_logger.propagate = False
tornado_logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(u"%(levelname)-8s %(name)-4s %(asctime)s,%(msecs)d %(module)s-%(funcName)s: %(message)s")

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
# stdout_handler.setFormatter(formatter)

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
# stderr_handler.setFormatter(formatter)

tornado_logger.addHandler(stdout_handler)
tornado_logger.addHandler(stderr_handler)

hn = logging.NullHandler()
hn.setLevel(logging.DEBUG)
logging.getLogger("tornado.access").addHandler(hn)
logging.getLogger("tornado.access").propagate = False
logging.getLogger('urllib3.connectionpool').addHandler(hn)
logging.getLogger('urllib3.connectionpool').propagate = False
logging.getLogger('EVCore').addHandler(hn)
logging.getLogger('EVCore').propagate = False

neo_log = logging.getLogger('neo4j')
neo_log.addHandler(hn)
neo_log.propagate = False

coloredlogs.install(level='DEBUG', logger=tornado_logger)

def update_owes_connections(tx, member_uuid, group_uuid, mapping):
    owes_r = f'OWES_{group_uuid}'
    q = f"""
           match (u:User {{uuid: '{member_uuid}'}})-[r:`{owes_r}`]->(u2) return r.amount as owes, u2.uuid as creditor
       """
    records = tx.run(q)
    for r in records:
        c_uuid = r['creditor']
        amount = r['owes']
        mapping[member_uuid].update({c_uuid: amount})


def get_simplified_debt_graph(group_uuid):
    g = Group.nodes.first_or_none(uuid=group_uuid)
    if not g:
        return None
    # get current owed structure
    frenz_uuid_l = list(map(lambda x: x.uuid, g.members))
    owes_mapping = {u: {} for u in frenz_uuid_l}  # who owes to whom (debit map)
    simplified_mapping = {u: 0 for u in frenz_uuid_l}  # who is owed by whom (credit map)
    driver = GraphDatabase.driver(settings['NEO4J']['URL'],
                                  auth=(settings['NEO4J']['USERNAME'], settings['NEO4J']['PASSWORD']))
    with driver.session() as session:
        for u in frenz_uuid_l:
            session.read_transaction(update_owes_connections, u, group_uuid, owes_mapping)
    print('Current lending map (who owes whom) \n', owes_mapping)
    # simplify
    for debitor in owes_mapping:
        for creditor in owes_mapping[debitor]:
            simplified_mapping[creditor] += owes_mapping[debitor][creditor]
            simplified_mapping[debitor] -= owes_mapping[debitor][creditor]
    print('Simplified credit map (who is owed how much): \n', simplified_mapping)
    final_mapping = {}
    cur_debitor_l = list(filter(lambda x: simplified_mapping[x] < 0, simplified_mapping))
    cur_creditor_l = list(filter(lambda x: simplified_mapping[x] > 0, simplified_mapping))
    if all(val == 0 for val in simplified_mapping.values()):
        return final_mapping
    cur_debitor = cur_debitor_l.pop()
    cur_creditor = cur_creditor_l.pop()
    while True:
        if all(val == 0 for val in simplified_mapping.values()):
            break
        if simplified_mapping[cur_debitor] == 0:
            cur_debitor = cur_debitor_l.pop()
        if simplified_mapping[cur_creditor] == 0:
            cur_creditor = cur_creditor_l.pop()
        min_deductible = min(-1 * simplified_mapping[cur_debitor], simplified_mapping[cur_creditor])
        if cur_debitor in final_mapping:
            final_mapping[cur_debitor].update({cur_creditor: min_deductible})
        else:
            final_mapping[cur_debitor] = {cur_creditor: min_deductible}
        simplified_mapping[cur_creditor] -= min_deductible
        simplified_mapping[cur_debitor] += min_deductible
    return final_mapping

@tenacity.retry(
    stop=tenacity.stop_after_delay(90),
    wait=tenacity.wait_random_exponential(multiplier=1, max=60),
    reraise=True
)
async def redisconn():
    sentinels = await aioredis.create_sentinel(REDIS_CONF['SENTINEL']['INSTANCES'], db=REDIS_DB,
                                               password=REDIS_PASSWORD)
    redis_master = await sentinels.master_for(REDIS_CONF['SENTINEL']['CLUSTER_NAME'])
    return redis_master


@tenacity.retry(
stop=tenacity.stop_after_delay(90),
    wait=tenacity.wait_random_exponential(multiplier=1, max=60),
    reraise=True,
    after=tenacity.after_log(tornado_logger, logging.DEBUG)
)
async def update_simplified_group_debts(group_uuid, r):
    splitmap_lock_resource = SIMPLIFIED_SPLITMAP_CACHE_RESOURCE.format(settings['contractAddress'], group_uuid)
    tornado_logger.debug(f'Attempting to update splitmap resource {splitmap_lock_resource}')
    final_settlement = get_simplified_debt_graph(group_uuid)
    tornado_logger.debug('Final simplified debt graph: ')
    tornado_logger.debug(final_settlement)
    await r.set(SIMPLIFIED_GROUPDEBT_CACHE_KEY.format(settings['contractAddress'], group_uuid),
                json.dumps(final_settlement))

    return True


def create_owes_relationship(tx, debitor_uuid, creditor_uuid, relationship_label, amount):
    set_debt_query = f"match (c:User {{uuid: '{creditor_uuid}'}}) with c " \
        f"match (d:User {{uuid: '{debitor_uuid}'}}) with c, d " \
        f"merge (d)-[r:`{relationship_label}`]->(c) " \
        f"on create set r.amount = {amount} " \
        f"on match set r.amount = r.amount+ {amount}"
    return tx.run(set_debt_query)


async def process_microupdate_neo4j(debitor, creditor, group, amount):
    g = Group.nodes.first_or_none(address=to_normalized_address(group))
    if not g:
        tornado_logger.debug('Group not found for address ')
        tornado_logger.debug(group)
    else:
        debitor_uuid = None
        for d_node in g.members.match(address=to_normalized_address(debitor)):
            debitor_uuid = d_node.uuid
            break
        creditor_uuid = None
        for c_node in g.members.match(address=to_normalized_address(creditor)):
            creditor_uuid = c_node.uuid
        if debitor_uuid and creditor_uuid:
            group_specific_rel = f'OWES_{g.uuid}'
            with graph.session() as session:
                session.write_transaction(create_owes_relationship, debitor_uuid, creditor_uuid, group_specific_rel,
                                          amount)
            tornado_logger.debug('Success!')


async def get_effective_splitmap(bill_uuid_hash, bill_data, contract_address, redis_conn):
    """
    wraps necessary logic for retrieving splitmap of a bill and saving of corresponding intermediate state in case of failure
    :param bill_uuid_hash:
    :param bill_data:
    :param contract_address:
    :return:
    """
    # retrieve split map from redis
    key = EFFECTIVE_SPLITMAP_KEY.format(contract_address, bill_uuid_hash)
    final_settlement = await redis_conn.get(key=key)
    if not final_settlement:
        await backup_failed_bills(bill_uuid_hash, bill_data, contract_address)
        log_failed_bill(bill_uuid_hash,
                        'Failed to update Bill state to 1. Original split map of expenses not found in cache(Redis)')
        return None
    else:
        return json.loads(final_settlement)


async def get_bill_graphdb(bill_uuid_hash, bill_data, contract_address, redis_conn):
    """
    wraps necessary logic for retrieving bill information and saving of intermediate state of bill in case of failure
    :param bill_uuid_hash:
    :param bill_data:
    :param contract_address:
    :return:
    """
    # find  bill info and subsequently, the group it is associated with
    bill = Bill.nodes.first_or_none(uuidhash=bill_uuid_hash)
    # ERROR: if bill not found in graph DB
    if not bill:
        await backup_failed_bills(bill_uuid_hash, bill_data, contract_address, redis_conn)
        log_failed_bill(bill_uuid_hash, 'Failed to update Bill state to 1 in Neo4J: Bill not found')
        return None
    else:
        return bill


def get_entity_graphdb(company_uuid_hash):
    entity = CorporateEntity.nodes.first_or_none(uuidhash=company_uuid_hash)
    return entity


async def bill_graph_update(state_update, bill_graph_obj, bill_uuid_hash, backup_bill_data, contract_address, redis_conn):
    """
    wraps necessary logic for updating bill state in graph DB and saving of intermediate state of bill in case of failure
    :param state_update: a dict that holds necessary fields to be updated
    for example {'state_code': '1' or '2' . depends on the lifecycle phase it is in., 'metadata': {additional metadata to be added on to the bill object}
    :param bill_graph_obj: the Bill object in the graph database
    :param bill_uuid_hash:
    :param backup_bill_data:
    :param contract_address:
    :return:
    """
    if 'state_code' in state_update:
        bill_graph_obj.state = state_update['state_code']
    if 'metadata' in state_update:
        bill_graph_obj.metadata.update(state_update['metadata'])
    try:
        bill_graph_obj.save()
    except Exception as e:
        await backup_failed_bills(bill_uuid_hash, backup_bill_data.update({'exception': e}), contract_address, redis_conn)
        log_failed_bill(bill_uuid_hash, f'Update operation failed to set Bill state to {state_update} in Neo4J')
        return False
    else:
        tornado_logger.debug(f'Upgraded Bill state to {state_update} in Graph DB...')
        return True


async def bill_reldb_update(session, state_update, bill_uuid_hash, request_json, contract_address, redis_conn):
    """
        wraps necessary logic for updating bill state in relational DB and saving of intermediate state of bill in case of failure
        :param state_update: a dict that holds necessary fields to be updated
        for example {'state_code': '1' or '2' . depends on the lifecycle phase it is in., 'metadata': {additional metadata to be added on to the bill object}
        :param bill_uuid_hash: the Bill object in the relational database will be fetched against this unique key
        :param bill_data:
        :param contract_address:
        :return:
        """
    bill_r = await as_future(
        session.query(MoneyVigilBill).filter(MoneyVigilBill.uuid_hash == bill_uuid_hash).first)
    if bill_r:
        if 'state_code' in state_update:
            bill_r.state = state_update['state_code']
        if 'metadata' in state_update:
            bill_r.associated_metadata = json.dumps(
                json.loads(bill_r.associated_metadata).update(state_update['metadata']))
        # log transaction hash in table
        tx_r = await as_future(
            session.query(MoneyVigilTransaction).filter(MoneyVigilTransaction.tx_hash == request_json['txHash']).first
        )
        if not tx_r:  # a transaction can carry multiple events
            tx_reldb = MoneyVigilTransaction(
                tx_hash=request_json['txHash'],
                block_num=request_json['blockNumber'],
                transaction_index=request_json['transactionIndex'],
                to_address=request_json['contract']
            )
            session.add(tx_reldb)
            session.flush()
        # log event data in table
        tx_event_r = await as_future(
            session.query(MoneyVigilEvent).filter(MoneyVigilEvent.ethvigil_event_id==request_json['ethvigil_event_id']).first
        )
        if not tx_event_r:
            tx_event_reldb = MoneyVigilEvent(
                ethvigil_event_id=request_json['ethvigil_event_id'],
                event_name=request_json['event_name'],
                tx_hash=request_json['txHash']
            )
            tx_event_reldb.users.append(bill_r.attached_user)
            session.add(tx_event_reldb)
            session.flush()
        # finally update bill relation db object
        bill_r.initial_txhash = request_json['txHash']
        try:
            session.add(bill_r)
            session.flush()
            # await as_future(session.commit())
        except Exception as e:
            await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
                'state': '0',
                'reason': 'BillOperationFailed:RelationalDB',
                'exception': e}), contract_address)
            log_failed_bill(bill_uuid_hash,
                            f'Update operation failed to set Bill state to {state_update} in Relational DB')
        else:
            tornado_logger.debug(f'Upgraded Bill state to {state_update} in Relational DB...')
    else:
        await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
            'state': '0' if state_update == '1' else '1',
            # hinging on the possibly immutable assumption that the lifecycle stages will only be 0, 1 or 2
            'reason': 'BillNotFound:RelationalDB'
        }
        ), contract_address, redis_conn)
        log_failed_bill(bill_uuid_hash,
                        'Failed to update Bill state to 1 in Relational DB: Bill not found')


async def backup_failed_bills(bill_uuid_hash, bill_data, contract_address, redis_conn):
    """
    backup during a failed update operation on a bill
    :param bill_uuid_hash:
    :param bill_data:
    :param contract_address:
    :return:
    """
    failed_bills_set = f'MoneyVigil:{contract_address}:failedbillhashes'
    await redis_conn.sadd(failed_bills_set, bill_uuid_hash)
    failed_bill_details = f'MoneyVigil:{contract_address}:failedbill:{bill_uuid_hash}'
    await redis_conn.set(failed_bill_details, bill_data)


def log_failed_bill(bill_uuid_hash, message):
    tornado_logger.error(bill_uuid_hash)
    tornado_logger.error('--------------')
    tornado_logger.error(message)


async def record_bill_activities(session, bill_obj, request_json):
    # enter in db
    # transaction data
    tx_r = await as_future(
        session.query(MoneyVigilTransaction).filter(MoneyVigilTransaction.tx_hash == request_json['txHash']).first
    )
    if not tx_r:
        t = MoneyVigilTransaction(
            tx_hash=request_json['txHash'],
            block_num=request_json['blockNumber'],
            to_address=request_json['contract'],
            transaction_index=request_json['transactionIndex']
        )
        session.add(t)
    # event data
    tx_event_r = await as_future(
        session.query(MoneyVigilEvent).filter(
            MoneyVigilEvent.ethvigil_event_id == request_json['ethvigil_event_id']).first
    )
    e = None
    if not tx_event_r:
        e = MoneyVigilEvent(
            ethvigil_event_id=request_json['ethvigil_event_id'],
            event_name=request_json['event_name'],
            tx_hash=request_json['txHash']
        )
        session.add(e)
        session.flush()
    for u_uuid in set(bill_obj.expenseMap.keys()):
        rel_db_user = await as_future(
            session.query(MoneyVigilUser).filter(MoneyVigilUser.uuid == u_uuid).first)
        if e:
            e.users.append(rel_db_user)
        # add activities for all involved users
        a_ = MoneyVigilActivity(
            associated_event_id=request_json['ethvigil_event_id'],
            associated_metadata=json.dumps(request_json['event_data']),
            for_user_uuid=u_uuid
        )
        session.add(a_)
    session.flush()


async def transform_splitmap_to_addexpense(contract_address, splitmap, bill_group_info):
    txhashes = list()
    # group specific eth address to user uuid mapping
    users_addr_to_uuid = dict()
    group_node = bill_group_info['group_node']
    group = bill_group_info['group_address']
    bill_uuid_hash = bill_group_info['bill_uuid_hash']
    for creditor in splitmap:
        for _u in group_node.members.match(address=to_normalized_address(creditor)):
            users_addr_to_uuid[creditor] = _u.uuid
        specific_debitors = list(splitmap[creditor].keys())
        amounts = []
        for d in specific_debitors:
            amounts.append(splitmap[creditor][d])
            for _u in group_node.members.match(address=to_normalized_address(d)):
                users_addr_to_uuid[d] = _u.uuid
        method_args = {
            'debitors': json.dumps(specific_debitors),
            'creditor': creditor,
            'group': group,
            'amounts': json.dumps(amounts),
            'billUUIDHash': bill_uuid_hash
        }
        api_key = settings['ETHVIGIL_API_KEY']
        headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
        method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/contract/{contract_address}/addExpense'
        async with aiohttp.ClientSession() as session:
            async with session.post(url=method_api_endpoint, json=method_args, headers=headers) as r:
                resp = await r.json()
                tornado_logger.debug(resp)
                if resp['success']:
                    txhash = resp['data'][0]['txHash']
                    txhashes.append(txhash)
                else:
                    txhashes.append(None)
    tornado_logger.debug(f"Transactions sent out for Bill UUID Hash {bill_uuid_hash}: {txhashes}")
    return txhashes


async def process_global_ACL_update(session, eth_addr, entity_uuid_hash, role_name):
    ethaddr_rel = await as_future(
        session.query(MoneyVigilUserEthereumAddresses).filter(
            MoneyVigilUserEthereumAddresses.address == eth_addr).first
    )
    user_rel_db = ethaddr_rel.connected_user
    # get the entity in the relational DB
    entity_reldb = await as_future(
        session.query(MoneyVigilCorporateEntity).filter(
            MoneyVigilCorporateEntity.uuidhash == entity_uuid_hash).first
    )
    if role_name == 'GlobalOwner':
        entity_reldb.owners.append(user_rel_db)
        tornado_logger.debug('Added relational DB user object to corporate entity object')
        tornado_logger.debug(user_rel_db.uuid)
        entity_reldb.eth_addr_owners.append(ethaddr_rel)
        tornado_logger.debug('Added relational DB ethereum address object to corporate entity object')
        tornado_logger.debug(ethaddr_rel.address)
        session.add(entity_reldb)
    role_rel_db = await as_future(
        session.query(MoneyVigilCorporateEntityRole).filter(MoneyVigilCorporateEntityRole.name == role_name).filter(
            MoneyVigilCorporateEntityRole.corporate_entity_id == entity_reldb.id).first
    )
    user_rel_db.assigned_roles.append(role_rel_db)  # connect user entry to role entry. Could be redundant
    ethaddr_rel.assigned_roles.append(
        role_rel_db)  # connect specific ethereum address of the above user to the role entry
    tornado_logger.debug('Added relational DB user to role with UUID')
    tornado_logger.debug('Added relational DB ethereum address to role with UUID')
    tornado_logger.debug(role_rel_db.uuid)
    # also add as employee
    session.add(user_rel_db)
    session.add(ethaddr_rel)


async def process_group_ACL_update(session, eth_address, entity_uuid_hash, group_address, role_name):
    ethaddr_rel = await as_future(
        session.query(MoneyVigilUserEthereumAddresses).filter(
            MoneyVigilUserEthereumAddresses.address == eth_address).first
    )
    user_rel_db = ethaddr_rel.connected_user
    # get the entity in the relational DB
    entity_reldb = await as_future(
        session.query(MoneyVigilCorporateEntity).filter(
            MoneyVigilCorporateEntity.uuidhash == entity_uuid_hash).first
    )
    group_reldb = await as_future(
        session.query(MoneyVigilGroup).filter(
            MoneyVigilGroup.address == group_address).first
    )
    for r in group_reldb.roles:
        if r.name == role_name:
            role_reldb = r
            break

    tornado_logger.debug(f'Found role unique ID for {role_name} against group {group_reldb}')
    tornado_logger.debug(role_reldb)
    role_reldb.assigned_users.append(user_rel_db)
    tornado_logger.debug(f'Linking User UUID {user_rel_db.uuid} with Role UUID {role_reldb.uuid}')
    role_reldb.assigned_eth_addresses.append(ethaddr_rel)
    tornado_logger.debug(f'Linking User ethereum address {eth_address} with Role UUID {role_reldb.uuid}')
    session.add(role_reldb)


async def entity_contract_deployed_processing(session, uuid_hash, contract_addr, r):
    e = await r.get(TO_BE_MINED_ENTITY_INFODUMP.format(uuid_hash))
    if e:
        entity_details = json.loads(e)
        tornado_logger.debug('Processing entity setup rules')
        tornado_logger.debug(entity_details['name'])
    else:
        tornado_logger.error('Could not find stored entity info dump in Redis')
        return None
    gen_uuid = entity_details['uuid']
    entity_rel_obj = MoneyVigilCorporateEntity(
        uuid=gen_uuid,
        uuidhash='0x' + keccak(text=gen_uuid).hex(),
        name=entity_details['name'],
        email=entity_details['email'],
        contract=contract_addr,
        chain_id=entity_details['chainID'],
        deployed=True
    )
    session.add(entity_rel_obj)
    session.flush()
    # create a user node corresponding to this entity.
    # all expenses will be recorded in the future in the graph DB against this node
    gen_entity_user_uuid = entity_details['representationalUUID']
    entity_user_reldb = MoneyVigilUser(
        uuid=gen_entity_user_uuid,
        name=entity_details['name'],
        email=entity_details['email'],
        password="dummy#",
        activated=1,
        activation_token='DUMMY',
        activated_at=int(time.time())
    )
    unsubscribe_token = str(uuid4())
    us = MoneyVigilUnsubscribeTokens(
        code=unsubscribe_token,
        user=gen_entity_user_uuid
    )
    session.add(entity_user_reldb)
    session.add(us)
    for acl_role in ROLES_LIST['global']:
        acl_role_obj = MoneyVigilCorporateEntityRole(
            name=acl_role,
            uuid=str(uuid4()),
            corporate_entity_id=entity_rel_obj.id
        )
        session.add(acl_role_obj)
    for acl_perm in PERMISSIONS_LIST:
        perm_obj = MoneyVigilCorporateEntityPermission(
            name=acl_perm,
            corporate_entity_id=entity_rel_obj.id
        )
        session.add(perm_obj)
    session.flush()
    global_role_keys = ["GlobalOwner", "GlobalApprover", "GlobalDisburser", "Employee"]
    for k in global_role_keys:
        tornado_logger.debug(f'\n--Setting default permissions for role {k}--\n')
        entity_specific_role_reldb = await as_future(
            session.query(MoneyVigilCorporateEntityRole).filter(
                MoneyVigilCorporateEntityRole.corporate_entity_id == entity_rel_obj.id,
                MoneyVigilCorporateEntityRole.name == k
            ).first
        )
        tornado_logger.debug('--DB Entry Primary ID | Role--')
        tornado_logger.debug(entity_specific_role_reldb.id)
        tornado_logger.debug(k)
        for each_perm in DEFAULT_ROLE_PERMISSIONS[k]:
            # find out permission entry
            if DEFAULT_ROLE_PERMISSIONS[k][each_perm]:  # if set as true
                perm_reldb = await as_future(
                    session.query(MoneyVigilCorporateEntityPermission).filter_by(
                        name=each_perm, corporate_entity_id=entity_rel_obj.id
                    ).first
                )
                tornado_logger.debug('Found: Permission Name | Permission ID')
                tornado_logger.debug('Set: Permission | Role')
                tornado_logger.debug(each_perm)
                tornado_logger.debug(k)
                perm_reldb.assigned_roles.append(entity_specific_role_reldb)
                session.add(perm_reldb)
            else:
                tornado_logger.debug('Not being set: Permission | Role')
                tornado_logger.debug(each_perm)
                tornado_logger.debug(k)
    session.flush()
    # register subdomain on ENS
    subdomain_str = entity_details['name'].lower()
    fully_qualified_namehash = '0x' + namehash(f'{subdomain_str}.{settings["topLevelENSDomain"]["name"]}').hex()
    args = {
        'subdomain': '0x'+keccak(text=subdomain_str).hex(),
        'node': settings['topLevelENSDomain']['nameHash'],
        'entityContract': contract_addr,
        'fullyQualifiedNode': fully_qualified_namehash
    }
    tx = ens_manager_contract.registerSubdomain(**args)
    tornado_logger.debug('Sent out tx for ENS subdomain registration')
    tornado_logger.debug(tx)
    # approve compund dai contract for allowance against the deployed contract
    acl_contract_instance = evc.generate_contract_sdk(contract_address=contract_addr, app_name='EntityACL')
    tx = acl_contract_instance.approveCompoundDaiContract(numTokens=100*10**18)  # 100 DAI approval
    tornado_logger.debug('Sent out tx for Approval of cDai contract on Dai contract against Moneyvigil entity contract')
    tornado_logger.debug(tx)

async def record_balance(r_conn, contract_addr, transfer_type):
    if transfer_type == 'dai':
        v = await record_dai_balance(r_conn, contract_addr)
        return v
    elif transfer_type == 'cdai':
        v = await record_cdai_balance(r_conn, contract_addr)
        return v

async def record_dai_balance(r_conn, contract_addr):
    # update entity DAI funds balance
    # query DAI contract for entity contract balance
    # TODO: wrap in run_in_executor to make it a non-blocking code
    bal = dai_contract_instance.balanceOf(contract_addr)
    bal = int(bal['uint256'])
    tornado_logger.debug('Contract address | Fetched Dai Balance')
    tornado_logger.debug(contract_addr)
    tornado_logger.debug(bal)
    await r_conn.set(key=CONTRACT_DAI_FUNDS.format(contract_addr), value=bal)
    return bal

async def record_cdai_balance(r_conn, contract_addr):
    # update entity cDai token balance
    # TODO: wrap in run_in_executor to make it a non-blocking code
    c_bal = cdai_contract.balanceOf(contract_addr)
    c_bal = int(c_bal['uint256'])
    c_rate = cdai_contract.exchangeRateStored()
    c_rate = int(c_rate['uint256'])
    c_bal = c_bal * c_rate // 1000000000000000000;
    tornado_logger.debug('Contract address | Fetched cDai Balance')
    tornado_logger.debug(contract_addr)
    tornado_logger.debug(c_bal)
    await r_conn.set(key=CONTRACT_CDAI_FUNDS.format(contract_addr), value=c_bal)
    return c_bal

@provide_async_redis_conn
async def process_transfer_event(session, to_contract, from_contract, transfer_type, tokens, redis_conn=None):
    global first_run
    supply_to_compund_from = None
    if first_run:
        tornado_logger.debug(
            'First in-memory run. Populating all known contracts deployed against corporate entities...')
        entities = await as_future(session.query(MoneyVigilCorporateEntity).all)
        for e in entities:
            if e.contract:
                contract_addr = to_normalized_address(e.contract)
                val = await record_balance(redis_conn, contract_addr, transfer_type)
                if tokens > 0 and transfer_type == 'dai' and contract_addr == to_contract:
                    supply_to_compund_from = contract_addr
                ENTITY_CONTRACTS.add(contract_addr)
        tornado_logger.debug('Entities contract address set')
        tornado_logger.debug(ENTITY_CONTRACTS)
        first_run = False
    else:
        if to_contract in ENTITY_CONTRACTS or from_contract in ENTITY_CONTRACTS:
            contract_addr = to_contract if to_contract in ENTITY_CONTRACTS else from_contract
            val = await record_balance(r, contract_addr, transfer_type)
            if tokens > 0 and transfer_type == 'dai' and to_contract in ENTITY_CONTRACTS:
                supply_to_compund_from = contract_addr
    if supply_to_compund_from:
        # after balance updated  in redis, ensure the transferred dais are put on compound
        # TODO: wrap in run_in_executor to make it a non-blocking code
        acl_contract_instance = evc.generate_contract_sdk(contract_address=supply_to_compund_from,
                                                          app_name='EntityACL')
        try:
            tx = acl_contract_instance.supplyToCompound(numTokens=tokens)
        except EVHTTPError as e:
            tornado_logger.error('Error calling supplyToCompound on contract')
            tornado_logger.error(supply_to_compund_from)
            tornado_logger.error(e)
        except AttributeError:
            tornado_logger.error(
                'Contract interface does not support supplyToCompound() most likely. Exception follows')
        else:
            tornado_logger.debug(f'Supplying {tokens} Dai to Compound Finance with tx...{tx} from Entity contract {supply_to_compund_from}')


class daiTransferHandler(SessionMixin, tornado.web.RequestHandler):
    async def post(self):
        request_json = tornado.escape.json_decode(self.request.body)
        self.set_status(status_code=202)
        self.write({'success': True})
        await self.flush()
        if 'event_name' in request_json:
            if request_json['event_name'] == 'Transfer':
                tornado_logger.debug('\n\n-----Dai ERC20 Transfer event------\n\n')
                tornado_logger.debug(request_json)
                event_data = request_json['event_data']
                to_contract = to_normalized_address(event_data['dst'])
                from_contract = to_normalized_address(event_data['src'])
                dais = event_data['wad']
                with self.make_session() as session:
                    await process_transfer_event(session, to_contract, from_contract, 'dai', dais)

class cDaiTransferHandler(SessionMixin, tornado.web.RequestHandler):
    async def post(self):
        request_json = tornado.escape.json_decode(self.request.body)
        self.set_status(status_code=202)
        self.write({'success': True})
        if 'event_name' in request_json:
            if request_json['event_name'] == 'Transfer':
                tornado_logger.debug('\n\n-----'
                                     'cDai ERC20 Transfer event------\n\n')
                tornado_logger.debug(request_json)
                event_data = request_json['event_data']
                to_contract = to_normalized_address(event_data['to'])
                from_contract = to_normalized_address(event_data['from'])
                with self.make_session() as session:
                    await process_transfer_event(session, to_contract, from_contract, 'cdai', 0)

class MainHandler(SessionMixin, tornado.web.RequestHandler):
    @provide_async_redis_conn
    async def post(self, redis_conn=None):
        global first_run
        # tornado_logger.debug(self.request.headers['content-type'])
        # tornado_logger.debug('---Transaction---')
        request_json = tornado.escape.json_decode(self.request.body)
        self.set_status(status_code=202)
        self.write({'success': True})
        await self.flush()
        if 'event_name' in request_json:
            if request_json['event_name'] == 'ACLDeployed':
                event_data = request_json['event_data']
                tornado_logger.debug('\n\n-----ACL Deployed event------\n\n')
                tornado_logger.debug(request_json)
                contract_addr = to_normalized_address(request_json['contract'])
                ENTITY_CONTRACTS.add(contract_addr)
                with self.make_session() as session:
                    await entity_contract_deployed_processing(
                        session=session,
                        uuid_hash=event_data['companyUUIDHash'],
                        contract_addr=contract_addr,
                        r = redis_conn
                    )
                await record_dai_balance(redis_conn, contract_addr)
                await record_cdai_balance(redis_conn, contract_addr)
                # find out deploying user for this entity, add that as top level globalowner
                eth_addr = await redis_conn.get(TO_BE_MINED_ACL_CONTRACTS.format(event_data['companyUUIDHash']))
                # convert from bytes to native string
                eth_addr = eth_addr.decode('utf-8')
                tornado_logger.debug('Adding user that deployed the ACL contract as GlobalOwner')
                tornado_logger.debug(eth_addr)
                ev_add_entity_global_owners(
                    contract_address=request_json['contract'],
                    owners_list=[eth_addr]
                )
                ev_add_entity_employees(
                    contract_address=request_json['contract'],
                    employees_list=[eth_addr]
                )
            elif request_json['event_name'] == 'EmployeeAdded':
                event_data = request_json['event_data']
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Employee Added event------')
                entity_uuid_hash = event_data['companyUUIDHash']
                new_employee_ethaddr = to_normalized_address(event_data['employee'])
                # --- relational DB ops ----
                with self.make_session() as session:
                    await process_global_ACL_update(
                        session=session,
                        eth_addr=new_employee_ethaddr,
                        entity_uuid_hash=entity_uuid_hash,
                        role_name='Employee'
                    )
                    session.flush()
            elif request_json['event_name'] == 'BillCreated':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Bill Created event------')
                bill_uuid_hash = request_json['event_data']['billUUIDHash']
                contract_address = request_json['contract']
                bill = await get_bill_graphdb(bill_uuid_hash, request_json['event_data'].update({
                    'state': '0',
                    'reason': 'BillNotFound:Neo4J'
                }
                ), contract_address, redis_conn)
                if not bill:
                    return
                group = None
                group_node = None
                for g_ in bill.group:
                    group = g_.address
                    group_node = g_
                    tornado_logger.debug(f'Got group against bill UUID Hash {bill_uuid_hash}: {group}')
                # check if approval required from the group type
                tornado_logger.debug('Group approval status in graph db:')
                tornado_logger.debug(group_node.approval_required)
                # upgrade to state 0 from -1 before anything else
                if group_node.approval_required:
                    if bill.metadata['isReimbursement']:
                        state_update_mapping = dict(state_code='8')  # for requiresDisbursal state
                    else:
                        state_update_mapping = dict(state_code='7')  # for requiresApproval state
                else:
                    state_update_mapping = dict(state_code='0')
                # inject backup redundancy data
                request_json['event_data'].update({
                    'state': state_update_mapping['state_code'],
                    'reason': 'BillOperationFailed:Neo4J'
                }
                )
                s_bill_graph_update = await bill_graph_update(state_update=state_update_mapping,
                                                              bill_graph_obj=bill,
                                                              bill_uuid_hash=bill_uuid_hash,
                                                              backup_bill_data=request_json,
                                                              contract_address=contract_address,
                                                              redis_conn=redis_conn)
                # upgrade bill state in relational db too
                with self.make_session() as session:
                    await bill_reldb_update(session=session,
                                            state_update=state_update_mapping,
                                            bill_uuid_hash=bill_uuid_hash,
                                            request_json=request_json,
                                            contract_address=contract_address,
                                            redis_conn=redis_conn
                                            )
                if group_node.approval_required:
                    # do not proceed with firing addExpense() calls
                    # set bill state to pending approval
                    return
                # else proceed with firing add expense calls
                request_json['event_data'].update({
                    'state': state_update_mapping['state_code'],
                    'reason': 'SplitmapNotCached'
                }
                )
                final_settlement = await get_effective_splitmap(bill_uuid_hash, request_json, contract_address, redis_conn)
                if not final_settlement:
                    return
                sentout_txs = await transform_splitmap_to_addexpense(contract_address=contract_address,
                                                                     splitmap=final_settlement,
                                                                     bill_group_info={
                                                                         'group_node': group_node,
                                                                         'group_address': group,
                                                                         'bill_uuid_hash': bill_uuid_hash
                                                                     })
                with self.make_session() as session:
                    await record_bill_activities(session, bill, request_json)
                # upgrade to state 1, 'pendingSumbission' on chain
                state_update_mapping = dict(state_code='1')
                # inject backup redundancy
                request_json['event_data'].update({
                    'state': state_update_mapping['state_code'],
                    'reason': 'BillOperationFailed:Neo4J'
                }
                )
                s_bill_graph_update = await bill_graph_update(state_update=state_update_mapping,
                                                              bill_graph_obj=bill,
                                                              bill_uuid_hash=bill_uuid_hash,
                                                              backup_bill_data=request_json,
                                                              contract_address=contract_address,
                                                              redis_conn=redis_conn)
                # upgrade bill state in relational db too
                with self.make_session() as session:
                    await bill_reldb_update(session=session,
                                            state_update=state_update_mapping,
                                            bill_uuid_hash=bill_uuid_hash,
                                            request_json=request_json,
                                            contract_address=contract_address,
                                            redis_conn=redis_conn
                                            )
            elif request_json['event_name'] == 'BillApproved':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Bill Approved event------')
                bill_uuid_hash = request_json['event_data']['billUUIDHash']
                approver = request_json['event_data']['approver']
                is_trusted = request_json['event_data']['trusted']
                acl_contract_address = request_json['contract']  # event BillApproved is fired from ACL contract
                logic_contract_address = settings['contractAddress']
                upgraded_bill_state = '3'
                # inject backup redundancy that will be picked up by the helper functions
                request_json['event_data'].update({
                    'state': upgraded_bill_state,
                    'reason': 'SplitmapNotCached'
                }
                )
                bill = await get_bill_graphdb(bill_uuid_hash, request_json, logic_contract_address, redis_conn)
                if not bill:
                    return
                group = None
                group_node = None
                for g_ in bill.group:
                    group = g_.address
                    group_node = g_
                    tornado_logger.debug(f'Got group against bill UUID Hash {bill_uuid_hash}: {group}')

                final_settlement = await get_effective_splitmap(bill_uuid_hash, request_json, logic_contract_address, redis_conn)  # splitmap is cached against the address of the logic contract
                if not final_settlement:
                    return
                sentout_txs = await transform_splitmap_to_addexpense(contract_address=logic_contract_address,
                                                                     splitmap=final_settlement,
                                                                     bill_group_info={
                                                                         'group_node': group_node,
                                                                         'group_address': group,
                                                                         'bill_uuid_hash': bill_uuid_hash
                                                                     })
                with self.make_session() as session:
                    await record_bill_activities(session, bill, request_json)
                # inject backup redundancy data in request_json
                state_update_mapping = dict(state_code=upgraded_bill_state)
                s_bill_graph_update = await bill_graph_update(state_update=state_update_mapping,
                                                              bill_graph_obj=bill,
                                                              bill_uuid_hash=bill_uuid_hash,
                                                              backup_bill_data=request_json,
                                                              contract_address=logic_contract_address,
                                                              redis_conn=redis_conn
                                                              )
                # upgrade bill state in relational db too
                with self.make_session() as session:
                    await bill_reldb_update(session=session,
                                            state_update=state_update_mapping,
                                            bill_uuid_hash=bill_uuid_hash,
                                            request_json=request_json,
                                            contract_address=logic_contract_address,
                                            redis_conn=redis_conn
                                            )
            elif request_json['event_name'] == 'BillSubmitted':
                tornado_logger.debug('\n\n-----Bill Submitted event------\n\n')
                tornado_logger.debug(request_json)
                api_key = settings['ETHVIGIL_API_KEY']
                contract_address = request_json['contract']
                bill_uuid_hash = request_json['event_data']['billUUIDHash']
                # begin fetching expenses added against this bill UUID hash
                headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
                method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/cachedeventdata'
                method_args = {
                    'contract': contract_address,
                    'event_name': 'ExpenseAdded',
                    'indexed_param_name': 'billUUIDHash',
                    'indexed_param_value': bill_uuid_hash
                }
                group_address = None
                async with aiohttp.ClientSession() as session:
                    async with session.post(url=method_api_endpoint, json=method_args, headers=headers) as r:
                        resp = await r.json()
                        tornado_logger.debug(
                            f'Call to cached event data endpoint {method_api_endpoint} with args: {method_args}\n')
                        tornado_logger.debug(resp)
                        if resp['success']:
                            data = resp['data']
                            for cache_entry_with_ts in data:
                                t = json.loads(cache_entry_with_ts[0])
                                tornado_logger.debug(f'Processing microupdate: {t}')
                                # TODO : batch this operation if possible
                                await process_microupdate_neo4j(
                                    debitor=t['debitor'],
                                    creditor=t['creditor'],
                                    group=t['group'],
                                    amount=t['amount']
                                )
                                group_address = t['group']
                bill = Bill.nodes.first_or_none(uuidhash=bill_uuid_hash)
                if bill.group[0].approval_required:
                    if bill.metadata['isReimbursement']:
                        upgraded_bill_state = '6'  # set state to disbursed for a bill marked as reimbursement
                        # remove lock from group against disbursal
                        with self.make_session() as session:
                            entity_reldb = await as_future(
                                session.query(MoneyVigilCorporateEntity).filter(
                                    MoneyVigilCorporateEntity.uuid == bill.group[0].corporate_entity[0].uuid).first
                            )
                            await redis_conn.delete(PENDING_DISBURSAL_BILL.format(entity_reldb.contract, bill.group[0].uuid))
                    else:
                        upgraded_bill_state = '4'
                else:
                    upgraded_bill_state = '2'
                if not bill:
                    await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
                        'state': upgraded_bill_state,
                        'reason': 'BillNotFound:Neo4J'
                    }), contract_address, redis_conn)
                    log_failed_bill(bill_uuid_hash, 'Failed to update Bill state to 2 in Neo4J: Bill not found')
                    return
                # expenseMap is stored as UUID pairings to {paid:, owes:} json structure
                bill_members = set(bill.expenseMap.keys())
                bill.state = upgraded_bill_state
                try:
                    bill.save()
                except Exception as e:
                    await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
                        'state': upgraded_bill_state,
                        'reason': 'BillOperationFailed:Neo4J',
                        'exception': e
                    }
                    ), contract_address, redis_conn)
                    log_failed_bill(bill_uuid_hash, 'Update operation failed to set Bill state to 2 in Neo4J')
                else:
                    tornado_logger.debug('Upgraded Bill state in graph DB to: ')
                    tornado_logger.debug(upgraded_bill_state)
                # update in relational DB
                with self.make_session() as session:
                    bill_r = await as_future(
                        session.query(MoneyVigilBill).filter(MoneyVigilBill.uuid_hash == bill_uuid_hash).first)
                    if bill_r:
                        # transaction data
                        t = MoneyVigilTransaction(
                            tx_hash=request_json['txHash'],
                            block_num=request_json['blockNumber'],
                            to_address=request_json['contract'],
                            transaction_index=request_json['transactionIndex']
                        )
                        session.add(t)
                        # event data
                        e = MoneyVigilEvent(
                            ethvigil_event_id=request_json['ethvigil_event_id'],
                            event_name=request_json['event_name'],
                            tx_hash=request_json['txHash']
                        )
                        session.add(e)
                        for addr_uuid in bill_members:
                            rel_db_user = await as_future(session.query(MoneyVigilUser).filter(
                                MoneyVigilUser.uuid == addr_uuid).first)
                            e.users.append(rel_db_user)
                            # add activities for all involved users other than the bill submitter
                            if addr_uuid == bill.createdBy:
                                continue
                            a_ = MoneyVigilActivity(
                                associated_event_id=request_json['ethvigil_event_id'],
                                associated_metadata=json.dumps(request_json['event_data']),
                                for_user_uuid=addr_uuid
                            )
                            session.add(a_)
                        # commit transaction -> event -> activity
                        session.flush()
                        bill_r.state = bill.state  # we have already set bill state in graph DB according to group type
                        bill_r.final_txhash = request_json['txHash']
                        try:
                            session.add(bill_r)
                            session.flush()
                        except Exception as e:
                            await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
                                'state': upgraded_bill_state,
                                'reason': 'BillOperationFailed:RelationalDB',
                                'exception': e
                            }
                            ), contract_address, redis_conn)
                            log_failed_bill(bill_uuid_hash,
                                            'Update operation failed to set Bill state to 2 in Relational DB')
                        else:
                            tornado_logger.debug('Upgraded Bill state to 2 in Relational DB...')
                    else:
                        await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
                            'state': upgraded_bill_state,
                            'reason': 'BillNotFound:RelationalDB'
                        }
                        ), contract_address, redis_conn)
                        log_failed_bill(bill_uuid_hash,
                                        'Failed to update Bill state to 1 in Relational DB: Bill not found')
                # --- calculate and store the current simplified debt map for a group ---
                # get the group uuid
                g = Group.nodes.first_or_none(address=group_address)
                if g:
                    tornado_logger.debug(f'Updating simplified debt map for Group {g.uuid}...')
                    try:
                        await update_simplified_group_debts(g.uuid, redis_conn)
                    except Exception as e:
                        tornado_logger.error(f'Caught exception in updating simplified map for Group {g.uuid}')
                        tornado_logger.error(e, exc_info=True)
                else:
                    # check cached splitMap whether it is a self submitted bill.
                    # 1. such a bill does not have any ExpenseAdded events generated. Hence group address wont be found from event data cache
                    # 2. There is no splitMap to update
                    # example:{
                    # 	"0x62a1ee3b439b64870dd903e90d983c05700c03dd": {}
                    # }
                    self_submitted_bill = False
                    key = EFFECTIVE_SPLITMAP_KEY.format(contract_address, bill_uuid_hash)
                    final_settlement = await redis_conn.get(key=key)
                    final_settlement = json.loads(final_settlement)
                    if len(final_settlement.keys()) == 1:  # only one creditor
                        u = list(final_settlement.keys())[0]
                        if len(final_settlement[u].keys()) == 0:  # no debitor
                            self_submitted_bill = True
                    if not self_submitted_bill:
                        tornado_logger.error('Could not find group information from Neo4j. Group Address: ')
                        tornado_logger.error(group_address)
                        await backup_failed_bills(bill_uuid_hash, request_json['event_data'].update({
                            'state': upgraded_bill_state,
                            'reason': 'BillOperationFailed:Neo4J:GroupNotFound'
                        }
                        ), contract_address, redis_conn)
                        return
                    else:
                        # fetch group information from bill hash
                        bill_r = await as_future(
                            session.query(MoneyVigilBill).filter(MoneyVigilBill.uuid_hash == bill_uuid_hash).first)
                        if bill_r:
                            g = Group.nodes.first_or_none(uuid=bill_r.attached_group.uuid)
                        else:
                            tornado_logger.error('Could not find bill entry in relational database')
                            return
                # -- send out emails to group participants about the new bill --
                group_specific_member_mapping = dict()  # map UUID to User node objects
                for each in bill_members:
                    group_specific_member_mapping[each] = User.nodes.first_or_none(uuid=each)
                email_subject = f"New Bill added on MoneyVigil group {g.name}"
                for member in bill_members:
                    group_specific_member = group_specific_member_mapping[member]
                    with self.make_session() as session:
                        db_user = await as_future(session.query(MoneyVigilUser).filter(
                            MoneyVigilUser.uuid == group_specific_member.uuid).first)
                        if not db_user:
                            continue  # do not send email since user does not exist
                        elif db_user and db_user.activated != 1:
                            continue
                        unsubscribe_token = db_user.unsubscribe_token[0].code
                        member_email = group_specific_member.email
                        bill_created_by = User.nodes.first_or_none(uuid=bill.createdBy)
                        unsubscribe_link = f"{settings['MONEYVIGIL_LINK_PREFIX']}/unsubscribe/{unsubscribe_token}"
                        payers_tabular_text = "\n"
                        for each in bill_members:
                            each_user_node = group_specific_member_mapping[each]
                            if bill.expenseMap[each_user_node.uuid]['paid'] > 0:
                                payers_tabular_text += f"{each_user_node.name}\t\t{format(bill.expenseMap[each_user_node.uuid]['paid'] / 100, '.2f')}\n"
                            # print('Payers text: ', payers_tabular_text)
                        # find if bill has an uploaded receipt
                        bill_metadata = bill.metadata
                        if not bill_metadata['fileHash']:
                            optional_receipt = ""
                        else:
                            optional_receipt = new_bill_receipt.format(
                                **{'receipt_link': f'{settings["RECEIPT_LINK_PREFIX"]}/{bill_metadata["fileHash"]}'})
                        email_formatted_fieds = {
                            'name': group_specific_member.name,
                            'created_by': f"{bill_created_by.name} ({bill_created_by.email})",
                            'group_name': g.name,
                            'description': bill.metadata['description'],
                            'total_amount': format(float(bill.metadata['totalAmount']) / 100, '.2f'),
                            'user_share': format(bill.expenseMap[group_specific_member.uuid]['owes'] / 100, '.2f'),
                            'group_link': settings['MONEYVIGIL_LINK_PREFIX']+ '/groups/' + g.uuid,
                            'payers': payers_tabular_text,
                            'unsubscribe_link': unsubscribe_link,
                            'optional_receipt': optional_receipt
                        }
                        if group_specific_member.uuid == bill_created_by.uuid:
                            email_formatted_fieds['created_by'] = 'You'
                        email_text = new_bill_email_body.format(**email_formatted_fieds)
                        if db_user.email_subscription:
                            tornado_logger.debug('Sending email to...{}'.format(member_email))
                            tornado_logger.debug(
                                send_ses_email(email_addr=member_email, subject=email_subject, text=email_text))


            elif request_json['event_name'] == 'BillDisbursed':
                tornado_logger.debug('\n\n-----Bill Disbursed event------\n\n')
                tornado_logger.debug(request_json)
                api_key = settings['ETHVIGIL_API_KEY']
                contract_address = request_json['contract']
                bill_uuid_hash = request_json['event_data']['billUUIDHash']
                disburser = request_json['event_data']['disburser']
                is_trusted = request_json['event_data']['trusted']
                acl_contract_address = request_json['contract']  # event BillApproved is fired from ACL contract
                logic_contract_address = settings['contractAddress']
                upgraded_bill_state = '5'  # pending disbursal
                # inject backup redundancy that will be picked up by the helper functions
                request_json['event_data'].update({
                    'state': upgraded_bill_state,
                    'reason': 'SplitmapNotCached'
                }
                )
                bill = await get_bill_graphdb(bill_uuid_hash, request_json, logic_contract_address, redis_conn)
                if not bill:
                    return
                group = None
                group_node = None
                for g_ in bill.group:
                    group = g_.address
                    group_node = g_
                    tornado_logger.debug(f'Got group against bill UUID Hash {bill_uuid_hash}: {group}')

                final_settlement = await get_effective_splitmap(bill_uuid_hash, request_json,
                                                                logic_contract_address, redis_conn)  # splitmap is cached against the address of the logic contract
                if not final_settlement:
                    return
                sentout_txs = await transform_splitmap_to_addexpense(contract_address=logic_contract_address,
                                                                     splitmap=final_settlement,
                                                                     bill_group_info={
                                                                         'group_node': group_node,
                                                                         'group_address': group,
                                                                         'bill_uuid_hash': bill_uuid_hash
                                                                     })
                with self.make_session() as session:
                    await record_bill_activities(session, bill, request_json)
                # inject backup redundancy data in request_json
                state_update_mapping = dict(state_code=upgraded_bill_state)
                s_bill_graph_update = await bill_graph_update(state_update=state_update_mapping,
                                                              bill_graph_obj=bill,
                                                              bill_uuid_hash=bill_uuid_hash,
                                                              backup_bill_data=request_json,
                                                              contract_address=logic_contract_address,
                                                              redis_conn=redis_conn
                                                              )
                # upgrade bill state in relational db too
                with self.make_session() as session:
                    await bill_reldb_update(session=session,
                                            state_update=state_update_mapping,
                                            bill_uuid_hash=bill_uuid_hash,
                                            request_json=request_json,
                                            contract_address=logic_contract_address,
                                            redis_conn=redis_conn
                                            )
            elif request_json['event_name'] == 'NewGroupMember':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----New Group member event------')
                group_address = request_json['event_data']['group']
                user_address = request_json['event_data']['member']
                # we will fetch group specific user address from graph DB
                g_node = Group.nodes.first_or_none(address=to_normalized_address(group_address))
                u_node = None
                for u in g_node.members.match(address=to_normalized_address(user_address)):
                    u_node = u
                with self.make_session() as session:
                    u_db = await as_future(
                        session.query(MoneyVigilUser).filter(MoneyVigilUser.uuid == u_node.uuid).first)
                    # transaction data
                    t = MoneyVigilTransaction(
                        tx_hash=request_json['txHash'],
                        block_num=request_json['blockNumber'],
                        to_address=request_json['contract'],
                        transaction_index=request_json['transactionIndex']
                    )
                    session.add(t)
                    # event data
                    e = MoneyVigilEvent(
                        ethvigil_event_id=request_json['ethvigil_event_id'],
                        event_name=request_json['event_name'],
                        tx_hash=request_json['txHash']
                    )

                    e.users.append(u_db)
                    # add activities for all involved users
                    a_ = MoneyVigilActivity(
                        associated_event_id=request_json['ethvigil_event_id'],
                        associated_metadata=json.dumps(request_json['event_data']),
                        for_user_uuid=u_db.uuid
                    )
                    session.add(a_)
                    session.add(e)
                    session.flush()
            elif request_json['event_name'] == 'GlobalOwnerAdded':
                # the owners are already connected in the graph DB
                # on the event being fired from the contract, the same is persisted in the relational DB
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Global Owner added event------')
                event_data = request_json['event_data']
                entity_uuid_hash = event_data['companyUUIDHash']
                new_employee_ethaddr = to_normalized_address(
                    event_data['owner'])  # calls to addGlobalOwner carry ethereum addresses, not UUIDs
                # --- relational DB ops ----
                with self.make_session() as session:
                    await process_global_ACL_update(
                        session=session,
                        eth_addr=new_employee_ethaddr,
                        entity_uuid_hash=entity_uuid_hash,
                        role_name='GlobalOwner'
                    )
                    session.flush()
            elif request_json['event_name'] == 'GroupOwnerAdded':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Group Owner added event------')
                event_data = request_json['event_data']
                entity_uuid_hash = event_data['companyUUIDHash']
                group_address = event_data['group']
                new_employee_ethaddr = to_normalized_address(
                    event_data['owner'])  # calls to addGroupOwner carry ethereum addresses, not UUIDs
                # --- relational DB ops ----
                with self.make_session() as session:
                   await process_group_ACL_update(
                       session=session,
                       eth_address=new_employee_ethaddr,
                       entity_uuid_hash=entity_uuid_hash,
                       group_address=group_address,
                       role_name='GroupOwner'
                   )
                   session.flush()
            elif request_json['event_name'] == 'GlobalApproverAdded':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Global Approver added event------')
                event_data = request_json['event_data']
                entity_uuid_hash = event_data['companyUUIDHash']
                new_approver_ethaddr = to_normalized_address(
                    event_data['approver'])  # calls to addGlobalApprover carry ethereum addresses, not UUIDs
                # --- relational DB ops ----
                with self.make_session() as session:
                    await process_global_ACL_update(
                        session=session,
                        eth_addr=new_approver_ethaddr,
                        entity_uuid_hash=entity_uuid_hash,
                        role_name='GlobalApprover'
                    )
                    session.flush()
            elif request_json['event_name'] == 'GroupApproverAdded':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Group Approver added event------')
                event_data = request_json['event_data']
                entity_uuid_hash = event_data['companyUUIDHash']
                group_address = event_data['group']
                new_approver_ethaddr = to_normalized_address(
                    event_data['approver'])  # calls to addGroupApprovers carry ethereum addresses, not UUIDs
                # --- relational DB ops ----
                with self.make_session() as session:
                    await process_group_ACL_update(
                        session=session,
                        eth_address=new_approver_ethaddr,
                        entity_uuid_hash=entity_uuid_hash,
                        group_address=group_address,
                        role_name='GroupApprover'
                    )
                    session.flush()
            elif request_json['event_name'] == 'GlobalDisburserAdded':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Global Disburser added event------')
                event_data = request_json['event_data']
                entity_uuid_hash = event_data['companyUUIDHash']
                new_disburser_ethaddr = to_normalized_address(
                    event_data['disburser'])  # calls to addGlobalDisbursers carry ethereum addresses, not UUIDs
                # --- relational DB ops ----
                with self.make_session() as session:
                    await process_global_ACL_update(
                        session=session,
                        eth_addr=new_disburser_ethaddr,
                        entity_uuid_hash=entity_uuid_hash,
                        role_name='GlobalDisburser'
                    )
                    session.flush()
            elif request_json['event_name'] == 'GroupDisburserAdded':
                tornado_logger.debug(request_json)
                tornado_logger.debug('-----Group Disburser added event------')
                event_data = request_json['event_data']
                entity_uuid_hash = event_data['companyUUIDHash']
                group_address = event_data['group']
                new_disburser_ethaddr = to_normalized_address(
                    event_data['disburser'])  # calls to addGroupApprovers carry ethereum addresses, not UUIDs
                # --- relational DB ops ----
                with self.make_session() as session:
                    await process_group_ACL_update(
                        session=session,
                        eth_address=new_disburser_ethaddr,
                        entity_uuid_hash=entity_uuid_hash,
                        group_address=group_address,
                        role_name='GroupDisburser'
                    )
                    session.flush()
            # elif request_json['event_name'] == 'SettlementDisbursed':

            else:
                tornado_logger.debug('----Some other event-------')
                tornado_logger.debug(request_json)

def main():
    tornado.options.parse_command_line()
    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/dai", daiTransferHandler),
        (r"/cdai", cDaiTransferHandler)

    ], session_factory=make_session_factory(mysql_engine_path))
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port)
    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        tornado_logger.debug('Shutting down...')
        tornado.ioloop.IOLoop.current().stop()


if __name__ == "__main__":
    graph = GraphDatabase.driver(
        settings['NEO4J']['URL'],
        auth=(settings['NEO4J']['USERNAME'], settings['NEO4J']['PASSWORD']),
        encrypted=False
    )
    REDIS_CONF = {
        "SENTINEL": settings['REDIS']['SENTINEL']
    }
    s = REDIS_CONF['SENTINEL']['INSTANCES']
    REDIS_CONF['SENTINEL']['INSTANCES'] = list(map(lambda x: tuple(x), s))
    REDIS_DB = settings['REDIS']['DB']
    REDIS_PASSWORD = settings['REDIS']['PASSWORD']
    main()
