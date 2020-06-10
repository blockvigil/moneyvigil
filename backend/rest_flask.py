from functools import wraps, partial
import hmac
import hashlib
import pymysql
from ev_api_calls import *
from flask import Flask, jsonify, request
from flask_login import LoginManager, current_user, login_required
import neomodel.exceptions
from neo4j.v1 import GraphDatabase
from models import *
import datetime as dt
import json
from redis.sentinel import Sentinel
import requests
import uuid
import eth_account
from eth_utils import keccak, to_normalized_address, to_checksum_address
import random
import bcrypt
import time
import logging
import coloredlogs
import sys
import string
from flask_restx import Api, Resource
from flask_cors import CORS
from db_models import (
    MoneyVigilUser, MoneyVigilInvites, MoneyVigilUnsubscribeTokens, MoneyVigilReward, MoneyVigilBill, MoneyVigilGroup,
    MoneyVigilEvent, MoneyVigilTransaction, MoneyVigilActivity, MoneyVigilCorporateEntity, MoneyVigilCorporateEntityRole,
    MoneyVigilCorporateEntityPermission, MoneyVigilUserEthereumAddresses
)
from db_wrapper import DBCallsWrapper
from db_session import Session
import sqlalchemy.exc
from sqlalchemy import or_
from google.cloud import vision, storage
from google.cloud.vision import types
import re
from eth_account.messages import defunct_hash_message
from eth_account.account import Account
# from google.cloud.vision import types
# from werkzeug.utils import secure_filename
from dynaconf import settings
import binascii
from constants import *
from request_parsers import (
    _post_entity_approvers_parser, _post_entity_disbursers_parser, _post_entity_owners_parser,
     _post_group_members, _post_new_bill, _put_update_bill, _delete_bill, _post_bill_action, PARSERS
)
from email_helper import send_invite_email, send_group_addition_email, regen_send_activation
from ethvigil.EVCore import EVCore

formatter = logging.Formatter(u"%(levelname)-8s %(name)-4s %(asctime)s,%(msecs)d %(module)s-%(funcName)s: %(message)s")

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
# stdout_handler.setFormatter(formatter)

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
# stderr_handler.setFormatter(formatter)

app = Flask(__name__)
# app.logger.addHandler(stdout_handler)
# app.logger.addHandler(stderr_handler)
app.config['SECRET_KEY'] = settings['FLASK_APP_SECRET_KEY']
if settings["CORS_ENABLED"]:
    CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)

api_app = Api(app=app)
logged_user_ns = api_app.namespace('user', description='Logged in user resource')
user_ns = api_app.namespace('users', description='Personal User account')
corporate_entity_ns = api_app.namespace('corporateEntity', description='Corporate Entity operations')
group_ns = api_app.namespace('group', description='Group operations')
bill_ns = api_app.namespace('bill', description='Bill operations')
all_bills_ns = api_app.namespace('bill', description='Operations on entire collection of bills')

null_handler = logging.NullHandler(level=logging.DEBUG)
boto_log = logging.getLogger('botocore')
boto_log.addHandler(null_handler)
boto_log.propagate = False

neo_log = logging.getLogger('neo4j')
neo_log.addHandler(null_handler)
neo_log.propagate = False

logging.getLogger('urllib3.connectionpool').addHandler(null_handler)
logging.getLogger('urllib3.connectionpool').propagate = False

rest_logger = logging.getLogger('flask.app')
rest_logger.propagate = False
# rest_logger.setLevel(logging.DEBUG)
# rest_logger.addHandler(stdout_handler)
# rest_logger.addHandler(stderr_handler)
coloredlogs.install(level='DEBUG', logger=rest_logger)

REDIS_CONF = {
    "SENTINEL": settings['REDIS']['SENTINEL']
}
REDIS_DB = settings['REDIS']['DB']
REDIS_PASSWORD = settings['REDIS']['PASSWORD']

sentinel = Sentinel(sentinels=REDIS_CONF['SENTINEL']['INSTANCES'], db=REDIS_DB, password=REDIS_PASSWORD,
                    socket_timeout=0.1)
redis_master = sentinel.master_for(REDIS_CONF['SENTINEL']['CLUSTER_NAME'])

driver = GraphDatabase.driver(settings['NEO4J']['URL'],
                              auth=(settings['NEO4J']['USERNAME'], settings['NEO4J']['PASSWORD']))

evc = EVCore(verbose=False)
dai_contract_instance = evc.generate_contract_sdk(
    contract_address=to_normalized_address(settings['DaiContract']),
    app_name='Dai'
)

cdai_contract = evc.generate_contract_sdk(
    contract_address=to_normalized_address(settings['cDaiContract']),
    app_name='cDai'
)

# populate roles for this entity
with open('./entity_roles.json', 'r') as f:
    ROLES_LIST = json.load(f)

with open('./entity_permissions.json', 'r') as f:
    PERMISSIONS_LIST = json.load(f)
# app.config['WTF_CSRF_ENABLED'] = False

with open('./default_role_permissions.json', 'r') as f:
    DEFAULT_ROLE_PERMISSIONS = json.load(f)

# From github issue: https://github.com/maxcountryman/flask-login/issues/328
# Exception: No user_loader has been installed for this LoginManager
# if you had a logged in user with an older code base
# 1. uncomment the following lines
# 2. send a request to /logout
# 3. shutdown the server and once more comment out the following lines
# @login_manager.user_loader
# def load_user_from_pk(user_id):
#     return MoneyVigilUser.query.get(user_id)

def add_group_role_wrapper(role_name, role_list, entity_uuid, group_uuid):
    """
    :param role_name: 'GroupOwner' / 'GroupApprover'/ 'GroupDisburser'
    :param role_list: [{'uuid': '234-32323232', 'eth_address': '0x00'}]
    :param entity_uuid: entity UUID identifier
    :param group_uuid: UUID of the group
    :return:
    """
    role_contract_method_mapping = {
        'GroupOwner': ev_add_entity_group_owners,
        'GroupApprover': ev_add_entity_group_approvers,
        'GroupDisburser': ev_add_entity_group_disbursers
    }
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    # --Boilerplate checks begin--
    if not entity_graph:
        return jsonify({'success': False, 'message': 'EntityDoesNotExist'})
    entity_contract_addr = entity_graph.contract
    entity_name = entity_graph.name
    group_graph_node = Group.nodes.first_or_none(uuid=group_uuid)
    if not group_graph_node:
        return jsonify({'success': False, 'message': 'GroupDoesNotExist'})
    # check whether group is actually connected to entity
    if group_graph_node.corporate_entity[0].uuid != entity_graph.uuid:
        return jsonify({'success': False, 'message': 'GroupNotRelatedToEntity'})
    for role_member in role_list:
        role_member_uuid = role_member['uuid']
        role_member_graph_node = User.nodes.first_or_none(uuid=role_member_uuid)
        if not role_member_graph_node:
            Session.remove()
            rest_logger.error('Could not find member in graph DB. UUID: ')
            rest_logger.error(role_member_uuid)
            return jsonify({
                'success': False,
                'entity': {
                    'contract': entity_contract_addr,
                    'uuid': entity_uuid,
                    'chain_id': entity_graph.chain_id,
                    'name': entity_name
                },
                'group': {
                    'uuid': group_graph_node.uuid,
                    'address': group_graph_node.address
                },
                'error': f'{role_name}UpdateGraphDB'
            })
        else:
            # do a check whether supplied address is indeed registered against this user UUID
            found = False
            for e in role_member_graph_node.ethereum_addresses:
                if e.address == to_normalized_address(role_member['eth_address']):
                    found = True
                    break
            # --Boilerplate checks end--
            if found:
                role_member_graph_node.connected_corporate_groups.connect(group_graph_node, {
                    'address': role_member['eth_address'],
                    'role': role_name
                })
            else:
                rest_logger.error(
                    'Could not find ethereum address associated with owner in graph DB | UUID | Eth address ')
                rest_logger.error(role_member_uuid)
                rest_logger.error(role_member['eth_address'])
                return jsonify({
                    'success': False,
                    'entity': {
                        'contract': entity_contract_addr,
                        'uuid': entity_uuid,
                        'chain_id': entity_graph.chain_id,
                        'name': entity_name
                    },
                    'group': {
                        'uuid': group_graph_node.uuid,
                        'address': group_graph_node.address
                    },
                    'error': f'{role_name}UpdateGraphDB'
                })
    roles_eth_addr_l = list(map(lambda x: to_normalized_address(x['eth_address']), role_list))
    fn = role_contract_method_mapping[role_name]
    tx = fn(contract_address=entity_contract_addr, users_list=roles_eth_addr_l, group_address=group_graph_node.address)
    if tx:
        return jsonify({
            'success': True,
            'entity': {
                'contract': entity_contract_addr,
                'uuid': entity_uuid,
                'chain_id': entity_graph.chain_id,
                'name': entity_name
            },
            'group': {
                'uuid': group_graph_node.uuid,
                'address': group_graph_node.address
            },
            'connectedUsers': roles_eth_addr_l,
            'txHash': tx
        })
    else:
        return jsonify({'success': False})

# # # --- user account operations begin


def get_user_info():
    """

    :return: information about user identified by Auth-Token in headers
    """
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    user_node = get_auth_creds()
    user_db = dbcall.query_user_by_(session_obj=db_sesh, uuid=user_node.uuid)
    wallet_addresses = list()
    for each in user_db.eth_addresses:
        wallet_addresses.append({'name': each.name, 'address': each.address})
    connected_entities = dict()
    for each in user_db.assigned_roles:
        # connected_eth_address =
        user_eth_addresses = set(map(lambda x: x['address'], wallet_addresses))
        role_eth_addresses = set(map(lambda x: x.address, each.assigned_eth_addresses))
        connected_eth_address = list(user_eth_addresses.intersection(role_eth_addresses))
        # rest_logger.debug(f'Common intersection between * eth addresses assigned to role {each.name} and * user specific eth addresses')
        # rest_logger.debug(connected_eth_address)
        role = {
            'name': each.name,
            'uuid': each.uuid,
            'connectedAddresses': connected_eth_address  # there should ever be only one intersection
        }
        if each.connected_group:
            role.update({'group': each.connected_group.uuid})
        if each.connected_entity.uuid in connected_entities:
            if 'roles' not in connected_entities[each.connected_entity.uuid]:
                connected_entities[each.connected_entity.uuid]['roles'] = [role]
            else:
                connected_entities[each.connected_entity.uuid]['roles'].append(role)
        else:
            connected_entities[each.connected_entity.uuid] = {
                'entity': {
                    'name': each.connected_entity.name,
                    'email': each.connected_entity.email
                },
                'roles': [role]
            }
    # transform connected entities information into a list
    connected_entities_transformed = list(map(lambda x: dict(connected_entities[x], **{'entity': {
        'uuid': x,
        'name': connected_entities[x]['entity']['name'],
        'email': connected_entities[x]['entity']['email']
    }}), connected_entities))
    sent_out_invites = dbcall.query_invites_by_all(session_obj=db_sesh, invited_by=user_node.uuid)
    current_location = request.headers.get('CF-IPCountry')
    intercom_hash = hmac.new(
        settings['INTERCOM_HASH_SECRET'].encode('utf-8'),
        user_node.uuid.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    return_json = {
        'success': True,
        'user': {
            'name': user_db.name,
            'uuid': user_db.uuid,
            'email': user_db.email,
            'emailSubscription': current_user.email_subscription,
            'remainingInvites': user_db.remaining_invites,
            'sentInvites': len(sent_out_invites) if sent_out_invites else 0,
            'HTTP_CF_IPCOUNTRY': current_location,
            'intercomHash': intercom_hash,
            'wallets': wallet_addresses,
            'connectedEntities': connected_entities_transformed
        }
    }

    Session.remove()
    return jsonify(return_json)

@login_manager.request_loader
def load_user_from_auth_token(request):
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    token = request.headers.get('Auth-Token')
    ret = None
    if token:
        # check against the key
        user_uuid = redis_master.get(f'usertoken:{token}:toUUID')
        if user_uuid:
            user_uuid = user_uuid.decode('utf-8')  # convert from bytes object
            u = dbcall.query_user_by_(session_obj=db_sesh, uuid=user_uuid)
            # increase expiry of token
            redis_master.set(name=f'usertoken:{token}:toUUID', ex=3600 * 24 * 7, value=user_uuid)
            ret = u
        else:
            ret = None
    else:
        ret = None
    Session.remove()
    return ret


@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'success': False}), 401


@app.route('/login', methods=['POST'])
def login():
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    request_json = request.json
    email = request_json['email'].lower()
    password = request_json['password']
    u = dbcall.query_user_by_(session_obj=db_sesh, email=email)
    return_json = dict()
    if u:
        if u.activated != 1:
            return jsonify({'success': False, 'message': 'NotActivated'})
        # check password
        if bcrypt.checkpw(password, u.password):
            # generate token for session
            token = keccak(text=str(uuid.uuid4())).hex()
            redis_master.set(name=f'usertoken:{token}:toUUID', value=u.uuid, ex=3600 * 24 * 7)
            redis_master.sadd(f'uuid:{u.uuid}:authtokens', token)
            return_json = {'success': True, 'uuid': u.uuid, 'auth-token': token,
                           'remainingInvites': u.remaining_invites}
        else:
            return_json = {'success': False}
    else:
        return_json = {'success': False}
    Session.remove()
    if return_json['success']:
        return jsonify(return_json)
    else:
        return jsonify(return_json), 401


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    # logout_user()  # this doesnt do anything currently with the token based auth
    token = request.headers.get('Auth-Token')
    if token:
        # invalidate the token
        redis_master.delete(f'usertoken:{token}:toUUID')
    return jsonify({'success': True})


def get_groups_user():
    try:
        user_uuid = get_auth_creds().uuid
    except AttributeError:  # user has no entry in the graph db. can happen during testing
        return {'success': False}, 403
    s = Session()
    dbw = DBCallsWrapper()
    user_reldb = dbw.query_user_by_(session_obj=s, uuid=user_uuid)
    groups = dict()
    global_roles = dict()
    for g in user_reldb.groups:
        if g.approval_required and g.corporate_entity is not None:
            corporate_entity_uuid = g.corporate_entity.uuid
            entity_specific_groups_info = get_entity_groups(
                corporate_entity_uuid,
                global_roles.get(corporate_entity_uuid),
                s
            )
            if corporate_entity_uuid in groups.keys():
                groups[corporate_entity_uuid].extend(entity_specific_groups_info['groups'])
            else:
                groups[corporate_entity_uuid] = entity_specific_groups_info['groups']
            global_roles[corporate_entity_uuid] = entity_specific_groups_info['globalRoles']
    ret_msg = {'success': True, 'data': []}
    for each_entity_uuid in groups:
        entity_info = {
            'entityUUID': each_entity_uuid,
            'groups': groups[each_entity_uuid],
            'globalRoles': global_roles[each_entity_uuid]
        }
        ret_msg['data'].append(entity_info)
    Session.remove()
    return ret_msg, 200

    # for g in user.groups:
    #     with driver.session() as session:
    #         total_owes = session.read_transaction(return_user1_owes_total, user_uuid, g.uuid)
    #         total_owed = session.read_transaction(return_user1_is_owed_total, user_uuid, g.uuid)
    #     pending_bill_nodes = g.bills.filter(state__ne='2')
    #     group_info = {
    #         'uuid': g.uuid,
    #         'address': g.address,
    #         'name': g.name,
    #         'approval_required': g.approval_required,
    #         'totalOwes': total_owes,
    #         'totalOwed': total_owed,
    #         'pendingBills': len(pending_bill_nodes),
    #         'currency': g.currency
    #     }
    #     if g.approval_required and g.corporate_entity:
    #         # get further information on roles and allowed actions on roles
    #         group_info.update({
    #             'entity': {
    #                 'name': g.corporate_entity[0].name,
    #                 'uuid': g.corporate_entity[0].uuid,
    #                 'email': g.corporate_entity[0].email
    #             }
    #         })
    #     groups.append(group_info)
    # return jsonify({'success': True, 'groups': groups, 'member': {'uuid': user_uuid, 'email': user_email}})


@app.route('/simplifyuserdebts', methods=['POST'])
@login_required
def simplify_user_debts():
    """
    Returns the simplified debt structure for a group, specific to the logged in user
    :return: a json structure {"owed": [list of members who owe the logged in user], "owes": [list of those who are owed]}
    """
    posted_json = request.json
    group_uuid = posted_json['group']
    user_node = get_auth_creds()
    user_uuid = user_node.uuid
    final_mapping = get_simplified_debt_graph(group_uuid)
    if not final_mapping:
        return jsonify({'success': False, 'data': dict()})
    final_mapping = json.loads(final_mapping)
    # pivot around authenticated user
    pivoted_final_mapping = {'owes': [], 'owed': []}
    # look through owes list
    if user_uuid in final_mapping:
        for creditor_uuid in final_mapping[user_uuid]:
            debit_object = {'member': {}, 'amount': final_mapping[user_uuid][creditor_uuid]}
            c_user = User.nodes.first_or_none(uuid=creditor_uuid)
            debit_object['member']['uuid'] = creditor_uuid
            debit_object['member']['name'] = c_user.name
            debit_object['member']['email'] = c_user.email
            pivoted_final_mapping['owes'].append(debit_object)
    # look through values
    other_debitors = list(final_mapping.keys())
    try:
        other_debitors.remove(user_uuid)
    except ValueError:
        pass
    for each in other_debitors:
        if user_uuid in final_mapping[each]:
            # pivoted_final_mapping[each] = {user_uuid: final_mapping[each][user_uuid]}
            credit_object = {'member': {}, 'amount': final_mapping[each][user_uuid]}
            d_user = User.nodes.first_or_none(uuid=each)
            credit_object['member']['uuid'] = each
            credit_object['member']['name'] = d_user.name
            credit_object['member']['email'] = d_user.email
            pivoted_final_mapping['owed'].append(credit_object)
    return jsonify({'success': True, 'data': pivoted_final_mapping})

@app.route('/getconnectedusers', methods=['POST'])
@login_required
def get_connected_users():
    user_node = get_auth_creds()
    connections = get_connected_groups_and_users(user_node, False)
    return jsonify({'success': True, 'connections': connections})


@app.route('/getallconnections', methods=['POST'])
@login_required
def get_only_connected_users():
    user_node = get_auth_creds()
    connections = get_connected_groups_and_users(user_node, True)
    return jsonify({'success': True, 'connections': connections})

# # # --- user account operations end


def random_string(string_length=10):
    """Generate a random string of fixed length """
    letters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(letters) for i in range(string_length))

# TODO: Accept and verify ethereum address connected to the account making entity modifying calls
def entity_employee_ops_credential_check(fn):
    """
    Checks if the calling account on the Flask endpoint is a Global[Owner|Approver|Disburser]
    Employees are alllowed to update their own eth address linkage to a corporate entity.
    WARNING: Do not attempt to update multiple user eth address linkage to an entity with regular employee credentials
    :param fn: Flask view function
    :return: Authenticated function that allows Employee modifications on a corporate entity
    """
    @wraps(fn)
    def authenticated_view(*args, **kwargs):
        s = Session()
        dbw = DBCallsWrapper()
        _u = dbw.query_user_by_(session_obj=s, uuid=get_auth_creds().uuid)
        if not _u:
            return {'success': False}, 401
        # Intervention for PUT calls
        _permitted = False
        if request.method == 'PUT':
            rest_logger.debug('In PUT check')
            # go through the submitted employees
            req_json = request.json
            rest_logger.debug(req_json)
            for e in req_json['employees']:
                if e['uuid'] != _u.uuid:
                    _permitted = False
                    break
                else:
                    _permitted = True
        if _permitted:
            return fn(*args, **kwargs)
        # check roles and permissions now
        entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=request.view_args['entityUUID'])

        employee_add_perm_reldb_ID = dbw.query_permission_by_(session_obj=s, name='CAN_ADD_EMPLOYEE', corporate_entity_id=entity_reldb.id).id
        if employee_add_perm_reldb_ID:
            rest_logger.debug(f'Got permission CAN_ADD_EMPLOYEE id in DB: {employee_add_perm_reldb_ID}')
        else:
            rest_logger.error('Could not find permission CAN_ADD_EMPLOYEE id in DB')
        # all the permissions assigned to user
        _u_perms_DB_obj = map(lambda role: role.assigned_permissions, filter(lambda x: 'Global' in x.name, _u.assigned_roles))
        _u_perms_ids = []
        for permission_collection in _u_perms_DB_obj:
            for _ in permission_collection:
                _u_perms_ids.append(_.id)
        if employee_add_perm_reldb_ID not in _u_perms_ids:
            return {'success': False}, 403
        return fn(*args, **kwargs)
    return authenticated_view

def entity_caller_permission_check_template(fn, **outer_kwargs):
    """
        Checks if the calling account on the Flask endpoint has the permission as requested
        :param fn: Flask view function
        :param outer_kwargs: Example. outer_kwargs['permission']='CAN_ADD_APPROVER'
        :return: Authenticated function that allows Employee modifications on a corporate entity
        """

    @wraps(fn)
    def authenticated_view(*args, **kwargs):
        s = Session()
        dbw = DBCallsWrapper()
        _u = dbw.query_user_by_(session_obj=s, uuid=get_auth_creds().uuid)
        if not _u:
            return {'success': False}, 401
        # check roles and permissions now
        entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=request.view_args['entityUUID'])
        nullgroup_specific_roles = dbw.query_roles_by_(session_obj=s, corporate_entity_id=entity_reldb.id, group_uuid=None)
        nullgroup_specific_role_perms = list(map(lambda x: x.assigned_permissions, nullgroup_specific_roles))
        nullgroup_specific_role_perms_ids = set()
        for p in nullgroup_specific_role_perms:
            for _ in p:
                if _.name == outer_kwargs['permission']:
                    nullgroup_specific_role_perms_ids.add(_.id)
        # all the permissions assigned to user
        _u_perms_DB_obj = map(lambda role: role.assigned_permissions, _u.assigned_roles)
        _u_perms_ids = set()
        for permission_collection in _u_perms_DB_obj:
            for _ in permission_collection:
                _u_perms_ids.add(_.id)
        if len(set.intersection(nullgroup_specific_role_perms_ids, _u_perms_ids)) <= 0:
            rest_logger.error('ACL Auth failed for global entity level operation')
            return {'success': False}, 403
        return fn(*args, **kwargs)

    return authenticated_view


# specific decorators. Use the template above
can_add_global_approver = partial(entity_caller_permission_check_template, permission='CAN_ADD_APPROVER')
can_add_global_disburser = partial(entity_caller_permission_check_template, permission='CAN_ADD_DISBURSER')
can_add_global_owner = partial(entity_caller_permission_check_template, permission='CAN_ADD_OWNER')


def entity_group_permissions_check_template(fn, **outer_kwargs):
    @wraps(fn)
    def authenticated_view(*args, **kwargs):
        s = Session()
        dbw = DBCallsWrapper()
        _u = dbw.query_user_by_(session_obj=s, uuid=get_auth_creds().uuid)
        if not _u:
            return {'success': False}, 401
        # ----- STAGE 1 -----
        # check roles and permissions at a group level
        rest_logger.debug('In entity group permissions check. Got view args')
        rest_logger.debug(kwargs)
        entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=kwargs['entityUUID'])
        perm_string = outer_kwargs['permission']
        group_uuid = request.view_args['groupUUID']
        # find out permissions against roles that are group specific
        # 1. find out group specific role UUIDs
        # 2. Find out permission IDs against the roles from step 1
        group_specific_roles = dbw.query_roles_by_(session_obj=s, corporate_entity_id=entity_reldb.id, group_uuid=group_uuid)
        group_specific_role_perms = list(map(lambda x: x.assigned_permissions, group_specific_roles))
        group_specific_role_perms_ids = set()
        for p in group_specific_role_perms:
            for _ in p:
                if _.name == perm_string:
                    group_specific_role_perms_ids.add(_.id)
        # group_specific_role_perms_ids = set(map(lambda x: x.id, filter(lambda x: x.name == perm_string, group_specific_role_perms)))
        # all the group roles assigned to user
        _u_group_roles = filter(lambda x: x.group_uuid == group_uuid, _u.assigned_roles)
        # all the group permissions assigned to user
        _u_group_perms_DB_obj = map(lambda role: role.assigned_permissions, _u_group_roles)
        _u_perms_ids = set()
        for permission_collection in _u_group_perms_DB_obj:
            for _ in permission_collection:
                _u_perms_ids.add(_.id)
        if len(set.intersection(group_specific_role_perms_ids, _u_perms_ids)) <= 0:
            rest_logger.info('ACL auth not allowed at group level')
            # return {'success': False}, 401
        else:
            return fn(*args, **kwargs)
        # ----- STAGE 2 -----
        # check if the same permission might be available on a global level
        nullgroup_specific_roles = dbw.query_roles_by_(session_obj=s, corporate_entity_id=entity_reldb.id,
                                                       group_uuid=None)
        rest_logger.debug(f'Got global roles for entity {entity_reldb.name}: \n{nullgroup_specific_roles}')
        nullgroup_specific_role_perms = list(map(lambda x: x.assigned_permissions, nullgroup_specific_roles))
        nullgroup_specific_role_perms_ids = set()
        # rest_logger.debug(f'Looking for global permission {perm_string}')
        for p in nullgroup_specific_role_perms:
            for _ in p:
                rest_logger.debug(f'Scanning {_.name}')
                if _.name == perm_string:
                    # rest_logger.debug(f'Found id {_.id} in permissions table')
                    nullgroup_specific_role_perms_ids.add(_.id)
        # all the permissions assigned to user
        _u_perms_DB_obj = map(lambda role: role.assigned_permissions, _u.assigned_roles)
        _u_all_perms_ids = set()
        # rest_logger.debug('Investigating all perms for user: ')
        # rest_logger.debug(_u.name)
        for permission_collection in _u_perms_DB_obj:
            for _ in permission_collection:
                rest_logger.debug(_.name)
                _u_all_perms_ids.add(_.id)
        # rest_logger.debug(f'Global permissions list for perm {perm_string}: \n{nullgroup_specific_role_perms_ids}')
        # rest_logger.debug(f'Swaroops permissions for {perm_string}: \n{_u_all_perms_ids}')
        if len(set.intersection(nullgroup_specific_role_perms_ids, _u_all_perms_ids)) <= 0:
            return {'success': False}, 403  # return not authorized from here
        return fn(*args, **kwargs)
    return authenticated_view


can_add_group_owner = partial(entity_group_permissions_check_template, permission='CAN_ADD_OWNER')
can_add_group_approver = partial(entity_group_permissions_check_template, permission='CAN_ADD_APPROVER')
can_add_group_disburser = partial(entity_group_permissions_check_template, permission='CAN_ADD_DISBURSER')

# # # --- personal group operations

def addmember(request_json, group_secret=None):
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    try:
        approval_required = request_json['approval_required']
    except KeyError:
        approval_required = False
    user_node = get_auth_creds()
    user_uuid = user_node.uuid
    user1_groupspecific_addr = None
    group_name = None
    group_currency = None
    group_relational_obj = None
    ev_users_add = list()
    member_uuid = request_json['member']
    member_user_obj = dbcall.query_user_by_(session_obj=db_sesh, uuid=member_uuid)
    if not member_user_obj:
        return jsonify({'success': False, 'message': 'MemberDoesNotExist'})
    if not group_secret:
        group_secret = str(uuid.uuid4())
        try:
            group_name = request_json['name']  # if name key is not supplied it will raise a KeyError
            if group_name == "":  # treat a blank string as no group supplied
                raise KeyError
        except KeyError:
            group_name = f'NewGroup{random.choice(range(1, 100000000))}'
        user1_groupspecific_addr = eth_account.Account.privateKeyToAccount(
            keccak(text=f'{group_secret}{user_uuid}')).address
        user1_groupspecific_addr = to_normalized_address(user1_groupspecific_addr)
        ev_users_add.append(user1_groupspecific_addr)
        try:
            group_currency = request_json['currency']
        except KeyError:
            return jsonify({'success': False, 'message': 'GroupCurrencyNotSupplied'})
    else:
        g = Group.nodes.first_or_none(uuid=group_secret)
        if g:
            rel = g.members.relationship(user_node)
            user1_groupspecific_addr = to_normalized_address(rel.address)
            group_name = g.name
            group_currency = g.currency
        else:
            return jsonify({'success': False, 'message': 'GroupDoesNotExistGraphDB'})
        group_relational_obj = dbcall.query_group_by_(session_obj=db_sesh, uuid=group_secret)
        if not group_relational_obj:
            return jsonify({'success': False, 'message': 'GroupDoesNotExistRelationalDB'})
    # passing bytes instead of account object, this is intentional
    group_eth_address = eth_account.Account.privateKeyToAccount(keccak(text=group_secret)).address
    group_eth_address = to_normalized_address((group_eth_address))
    user2_addr = eth_account.Account.privateKeyToAccount(keccak(text=f'{group_secret}{member_uuid}')).address
    user2_addr = to_normalized_address(user2_addr)
    ev_users_add.append(user2_addr)
    rest_logger.info('Selected group name, currency: ')
    rest_logger.info(group_name)
    rest_logger.info(group_currency)
    cypher_query = f"""
        merge (g:Group {{uuid: '{group_secret}', 
        address: '{group_eth_address}', 
        name: '{group_name}', 
        currency: '{group_currency}',
        approval_required: {approval_required}
        }}) with g
    """
    # attempt new group creation
    if not group_relational_obj:
        group_relational_obj = MoneyVigilGroup(
            uuid=group_secret,
            address=group_eth_address,
            name=group_name,
            approval_required=approval_required,
            currency=group_currency
        )
        db_sesh.add(group_relational_obj)
        db_sesh.commit()
    if current_user not in group_relational_obj.users:
        try:
            group_relational_obj.users.append(current_user)
        except Exception as e:
            logging.error(f'Error adding user {current_user.name} to group in relational DB')
            logging.error(e)
        else:
            db_sesh.add(group_relational_obj)
            db_sesh.commit()
            rest_logger.info(f'Current User added: {current_user.name} to relational DB against group {group_secret}')
    if member_user_obj not in group_relational_obj.users:
        try:
            group_relational_obj.users.append(member_user_obj)
        except Exception as e:
            logging.error(f'Error adding user {member_user_obj.name} to group in relational DB')
            logging.error(e)
        else:
            db_sesh.add(group_relational_obj)
            db_sesh.commit()
            rest_logger.info(f'User added: {member_user_obj.name} to relational DB against group {group_secret}')
    Session.remove()
    cypher_query += f"""
        merge (u2:User {{uuid: '{member_uuid}'}})
        merge (u2)-[:MEMBER_OF {{address: '{user2_addr}'}}]->(g)
    """
    if user1_groupspecific_addr:
        cq2 = f"""
            merge (u1:User {{uuid: '{user_uuid}'}})
            merge (u1)-[:MEMBER_OF {{address: '{user1_groupspecific_addr}'}}]->(g)
        """
        cypher_query += cq2
    with driver.session() as session:
        session.run(cypher_query)
    send_group_addition_email(inviter_name=user_node.name, inviter_email=user_node.email, member_uuid=member_uuid,
                              group_name=group_name, group_uuid=group_secret)
    # send EthVigil call to add member on contract
    for u_ in ev_users_add:
        ev_add_group_member(group_address=group_eth_address, user_address=u_)
    return jsonify({
        'success': True,
        'group': {'uuid': group_secret, 'address': group_eth_address, 'name': group_name, 'currency': group_currency},
        'member': {'uuid': member_uuid, 'address': user2_addr},
        'user': {'uuid': user_uuid, 'address': user1_groupspecific_addr}
    })


def get_group_members(group_uuid):
    g = Group.nodes.first_or_none(uuid=group_uuid)
    members = []
    for m in g.members:
        rel = g.members.relationship(m)
        members.append({'uuid': m.uuid, 'email': m.email, 'address': rel.address, 'name': m.name})
    return jsonify({'success': True, 'members': members, 'group': {'uuid': group_uuid, 'address': g.address}})


def get_groupdebts(group_uuid):
    user_node = get_auth_creds()
    groupdebt_info = {'owed': [], 'owes': []}
    set_credit_addrs = dict()  # stores the index in the owed list against a member uuid
    with driver.session() as session:
        records = session.read_transaction(return_user1_is_owed, user_node.uuid, group_uuid)
        for idx, each in enumerate(records):
            rest_logger.info(each)
            set_credit_addrs[each['u2']['uuid']] = idx
            credit_object = {'member': {}, 'amount': each['r']['amount']}
            for user_field in ['uuid', 'name', 'email']:
                credit_object['member'][user_field] = each['u2'][user_field]
            groupdebt_info['owed'].append(credit_object)
        owes_records = session.read_transaction(return_user1_owes, user_node.uuid, group_uuid)
        for each in owes_records:
            rest_logger.info(each)
            debit_object = {'member': {}, 'amount': each['r']['amount']}
            if each['u2']['uuid'] in set_credit_addrs:
                idx = set_credit_addrs[each['u2']['uuid']]
                if debit_object['amount'] > groupdebt_info['owed'][idx]['amount']:
                    debit_object['amount'] -= groupdebt_info['owed'][idx]['amount']
                    del groupdebt_info['owed'][idx]  # remove from owed category
                    for user_field in ['uuid', 'name', 'email']:  # create new object for owes category
                        debit_object['member'][user_field] = each['u2'][user_field]
                    groupdebt_info['owes'].append(debit_object)
                elif debit_object['amount'] < groupdebt_info['owed'][idx]['amount']:
                    groupdebt_info['owed'][idx]['amount'] -= debit_object['amount']
                elif debit_object['amount'] == groupdebt_info['owed'][idx]['amount']:
                    del groupdebt_info['owed'][idx]  # remove from owed category , dont add anything
        # total_owed = reduce(lambda x, y: x['amount']+y['amount'], groupdebt_info['owed'])
        # total_owes = reduce(lambda x, y: x['amount']+y['amount'], groupdebt_info['owes'])
        total_owed = 0
        total_owes = 0
        for each in groupdebt_info['owed']:
            total_owed += each['amount']
        for each in groupdebt_info['owes']:
            total_owes += each['amount']
        groupdebt_info.update({'totalOwed': total_owed, 'totalOwes': total_owes})
    return jsonify({'success': True, 'data': groupdebt_info})


def simplify_group_debts(group_uuid):
    result = get_simplified_debt_graph(group_uuid)
    if result:
        return jsonify({'success': True, 'data': json.loads(result)})
    else:
        return jsonify({'success': False, 'data': dict()})  # return an empty dict


def get_group_expenses(groupUUID):
    g = Group.nodes.first_or_none(uuid=groupUUID)
    if not g:
        return jsonify({'success': False, 'message': 'Invalid groupUUID'})
    g_addr = to_normalized_address(g.address)
    # find all expense added events for given groupUUID from ethvigil cache
    api_key = settings['ETHVIGIL_API_KEY']
    contract_address = settings['contractAddress']
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/cachedeventdata'
    method_args = {
        'contract': contract_address,
        'event_name': 'ExpenseAdded',
        'indexed_param_name': 'groupUUID',
        'indexed_param_value': g_addr
    }
    r = requests.post(url=method_api_endpoint, json=method_args, headers=headers)
    rest_logger.info(r.text)
    r = r.json()
    data = r['data']
    expenses = []
    for cache_entry_with_ts in data:
        t = json.loads(cache_entry_with_ts[0])
        debitor_node = None
        for d in g.members.match(address=to_normalized_address(t['debitor'])):
            debitor_node = d
            break
        creditor_node = None
        for c in g.members.match(address=to_normalized_address(t['creditor'])):
            creditor_node = c
            break
        t['debitor'] = {'uuid': debitor_node.uuid, 'email': debitor_node.email, 'name': debitor_node.name}
        t['creditor'] = {'uuid': creditor_node.uuid, 'email': creditor_node.email, 'name': creditor_node.name}
        del t['groupUUID']
        expenses.append(t)
    return jsonify(
        {'success': True, 'expenses': expenses, 'groupUUID': {'uuid': g.uuid, 'address': g.address, 'name': g.name}})


def get_bill_splits(group_uuid):
    """

    :return: Returns stream of splits of expenses grouped together under the original bills
    """
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    # g = Group.nodes.first_or_none(uuid=group)
    g = dbcall.query_group_by_(session_obj=db_sesh, uuid=group_uuid)
    g_graph = Group.nodes.first_or_none(uuid=group_uuid)
    if not g:
        return jsonify({'success': False, 'message': 'Invalid group UUID'})
    bill_splits = list()
    for b in g.bills:
        prev_bill = b.prev_bill
        child_bill = None
        if len(b.child_bills) > 0:
            try:
                linkage = json.loads(b.child_bills[0].associated_metadata)['linkage']
            except:
                linkage = None
            child_bill = {
                'uuid': b.child_bills[0].uuid,
                'uuid_hash': b.child_bills[0].uuid_hash,
                'linkage': linkage
            }
        if prev_bill:
            prev_bill = {'uuid': prev_bill.uuid, 'uuid_hash': prev_bill.uuid_hash}
        bill_obj = {
            'uuid': b.uuid,
            'uuidHash': b.uuid_hash,
            'metadata': json.loads(b.associated_metadata),
            'expenseMap': json.loads(b.expense_map),
            'state': b.STATES[b.state],
            'initialTxHash': b.initial_txhash,
            'finalTxHash': b.final_txhash,
            'prevBill': prev_bill,
            'childBill': child_bill
        }
        splits_obj = []
        if not g_graph:
            rest_logger.error(
                'Group information not found in graph DB. Returning bill information without splits.\n====')
            rest_logger.error(group_uuid)
            bill_splits.append({'bill': bill_obj, 'splits': []})
            continue
        # get split map
        key = ORIGINAL_SPLITMAP_KEY.format(settings["contractAddress"], b.uuid_hash)
        split_map = redis_master.get(key)
        if not split_map:
            bill_splits.append({'bill': bill_obj, 'splits': []})
            continue
        try:
            split_map = json.loads(split_map)
        except json.JSONDecodeError:
            bill_splits.append({'bill': bill_obj, 'splits': []})
            continue
        rest_logger.debug(f'Got split map for bill {b.uuid_hash}')
        rest_logger.debug(split_map)
        for creditor in split_map:
            # find UUID from group specific ethereum address
            creditor_obj = {'email': '', 'name': '', 'uuid': ''}
            for c in g_graph.members.match(address=to_normalized_address(creditor)):
                creditor_obj['email'] = c.email
                creditor_obj['name'] = c.name
                creditor_obj['uuid'] = c.uuid
                break
            specific_debitors = list(split_map[creditor].keys())
            for debitor in specific_debitors:
                debitor_obj = {'email': '', 'name': '', 'uuid': ''}
                for d in g_graph.members.match(address=to_normalized_address(debitor)):
                    debitor_obj['email'] = d.email
                    debitor_obj['name'] = d.name
                    debitor_obj['uuid'] = d.uuid
                    break
                splits_obj.append({
                    'amount': split_map[creditor][debitor],
                    'creditor': creditor_obj,
                    'debitor': debitor_obj
                })
        bill_splits.append({'bill': bill_obj, 'splits': splits_obj})
    Session.remove()
    return jsonify({'success': True, 'bills': bill_splits})
# # # --- personal group ops end


# # # ---- bill operations begin

def bill_ops_credential_check(fn):
    """
    Checks if the calling account on the Flask endpoint is a Global[Owner|Approver|Disburser]
    Employees are alllowed to update their own eth address linkage to a corporate entity.
    WARNING: Do not attempt to update multiple user eth address linkage to an entity with regular employee credentials
    :param fn: Flask view function
    :return: Authenticated function that allows Employee modifications on a corporate entity
    """
    @wraps(fn)
    def authenticated_view(*args, **kwargs):
        s = Session()
        dbw = DBCallsWrapper()
        _u = dbw.query_user_by_(session_obj=s, uuid=get_auth_creds().uuid)
        if not _u:
            return {'success': False}, 401
        # Intervention for PUT calls
        _permitted = False
        if request.method == 'POST':
            rest_logger.debug('In new bill creations permission check')
            # go through the submitted employees
            req_json = request.json
            rest_logger.debug(req_json)
            group_uuid = req_json['group']
            g_reldb = dbw.query_group_by_(session_obj=s, uuid=group_uuid)
            group_role_found = False
            employee_role_found = False
            global_role_found = False
            # check through permissions assigned to user
            for r in _u.assigned_roles:
                # check if `CAN_ADD_BILL` is in list of permissions assigned to this role
                for p in r.assigned_permissions:
                    if p.name == 'CAN_ADD_BILL':
                        if r.connected_group and r.connected_group.uuid == group_uuid:
                            group_role_found = True
                            break
                        if 'Global' in r.name and g_reldb.corporate_entity_id == r.corporate_entity_id:
                            global_role_found = True
                            break
                        if 'Employee' in r.name and g_reldb.corporate_entity_id == r.corporate_entity_id:
                            employee_role_found = True
                            break
                if group_role_found or employee_role_found or global_role_found:
                    _permitted = True
                    break
        if _permitted:
            return fn(*args, **kwargs)
        else:
            return {'success': False, 'message': 'NotPermitted'}, 403
    return authenticated_view

def individual_bill_ops_credential_check(fn):
    """
    Checks if the calling account on the Flask endpoint is a Global[Owner|Approver|Disburser]
    Employees are alllowed to update their own eth address linkage to a corporate entity.
    WARNING: Do not attempt to update multiple user eth address linkage to an entity with regular employee credentials
    :param fn: Flask view function
    :return: Authenticated function that allows Employee modifications on a corporate entity
    """
    @wraps(fn)
    def authenticated_view(*args, **kwargs):
        s = Session()
        dbw = DBCallsWrapper()
        _u = dbw.query_user_by_(session_obj=s, uuid=get_auth_creds().uuid)

        if not _u:
            return {'success': False}, 401
        _permitted = False
        if request.method == 'POST':
            rest_logger.debug('In bill action permission check')
            # go through the submitted employees
            req_json = request.json
            rest_logger.debug(req_json)
            action_type = req_json['message']['message']['actionType']
            group_eth_addr = to_normalized_address(req_json['message']['message']['group'])
            g_reldb = dbw.query_group_by_(session_obj=s, address=group_eth_addr)
            group_role_found = False
            global_role_found = False
            if action_type == 'Approval':
                permission_to_be_checked = 'CAN_APPROVE_BILL'
            elif action_type == 'Disbursal':
                permission_to_be_checked = 'CAN_DISBURSE'
            else:
                permission_to_be_checked = ''
            # check through permissions assigned to user
            for r in _u.assigned_roles:
                rest_logger.debug('\n--Got role--')
                rest_logger.debug(r.name)
                # check if `CAN_ADD_BILL` is in list of permissions assigned to this role
                for p in r.assigned_permissions:
                    rest_logger.debug('Scanning permission')
                    rest_logger.debug(p.name)
                    if p.name == permission_to_be_checked:
                        if r.connected_group and r.connected_group == g_reldb:
                            rest_logger.debug('Found group role for permission')
                            group_role_found = True
                            break
                        if 'Global' in r.name and g_reldb.corporate_entity_id == r.corporate_entity_id:
                            rest_logger.debug('Found global role for permission')
                            global_role_found = True
                            break
                if group_role_found or global_role_found:
                    _permitted = True
                    break
        if _permitted:
            return fn(*args, **kwargs)
        else:
            return {'success': False, 'message': 'NotPermitted'}, 403
    return authenticated_view


def addbill(posted_json):
    s = Session()
    dbw = DBCallsWrapper()
    logged_in_uuid = get_auth_creds().uuid
    ts = dt.datetime.utcnow()
    rest_logger.info(posted_json)
    expense_map = posted_json['expenseMap']
    form_date = posted_json['date']
    form_totalamount = posted_json['totalAmount']
    form_description = posted_json['description']
    try:
        file_hash = posted_json['fileHash']
    except KeyError:
        file_hash = None
    try:
        is_reimbursement = posted_json['reimbursement']
    except KeyError:
        is_reimbursement = False
    bill_uuid = str(uuid.uuid4())
    simplified_balance_mapping = dict()
    filtered_payers = list(filter(lambda x: expense_map[x]["paid"] == form_totalamount, expense_map))
    rest_logger.debug(filtered_payers)
    api_key = settings['ETHVIGIL_API_KEY']
    # find out group address
    g = Group.nodes.first_or_none(uuid=posted_json['group'])
    if not g:
        return {'success': False, 'message': 'Invalid Group UUID'}, 404
    entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=g.corporate_entity[0].uuid)
    is_group_pending_disbursal = redis_master.exists(PENDING_DISBURSAL_BILL.format(entity_reldb.contract, g.uuid))
    if is_reimbursement:
        if is_group_pending_disbursal:
            return {'success': False, 'message': 'Group is already pending a reimbursement amount'}, 403
        else:
            # check if this amount is less or equal to the owed amount
            if len(filtered_payers) == 1:  # check that reimbursement bill is always generated for one recipent
                # get the simplifed debt map for the group
                try:
                    group_debtmap = json.loads(get_simplified_debt_graph(g.uuid))
                except:
                    rest_logger.error('Could not access JSON serialized simplified debt map for the group from Redis')
                    return {'success': False, 'message': 'Could not access cached expenses for group'}, 404
                rest_logger.debug('Got simplified debt graph ')
                rest_logger.debug(group_debtmap)
                if len(group_debtmap.keys()) == 0:
                    return {'success': False, 'message': 'All amounts reimbursed'}, 403
                entity_representational_user_db = dbw.query_user_by_(session_obj=s, email=entity_reldb.email)
                # check if entity representational user is a debitor in the group debt graph
                if entity_representational_user_db.uuid in group_debtmap.keys():
                    owed_mapping = group_debtmap[entity_representational_user_db.uuid]
                    # NOTE: assuming only one employee per group. the owed amount for the representational user is assumed as the total owed
                    #  has to be extended later for multi party corp groups
                    owed_mapping_values = sum(owed_mapping.values())
                    if form_totalamount > owed_mapping_values:
                        return {'success': False, 'message': 'Reimbursement amount exceeds owed amount'}, 403
    mapped_uuids = dict()  # map user uuids to group specific ethereum addresses
    final_settlement = dict()
    for user_uuid in expense_map:
        user_node = User.nodes.first_or_none(uuid=user_uuid)
        if not user_node:
            return {'success': False, 'message': f'Invalid member UUID {user_uuid}'}, 404
        # find group specific address
        rel = g.members.relationship(user_node)
        user_grp_addr = rel.address
        # print(f'Group specific address for {user_uuid} : {user_grp_addr}')
        mapped_uuids[user_uuid] = rel.address
        # simplified_balance_mapping[user_grp_addr] = expense_map[user_uuid]['paid'] - expense_map[user_uuid]['owes']
        simplified_balance_mapping[user_grp_addr] = expense_map[user_uuid]['owes'] - expense_map[user_uuid]['paid']
    # print("Simplified balance mapping (lending model, not owed model): ", simplified_balance_mapping)
    rest_logger.info("Simplified balance mapping (owed model, not lending model): ")
    rest_logger.info(simplified_balance_mapping)
    rest_logger.info("Mapped UUIDs: ")
    rest_logger.info(mapped_uuids)
    # find out if one person has paid the entire bill. In that case, do not simplify further

    if len(filtered_payers) == 1:
        rest_logger.info("-----Only one payer for the entire bill!-----")
        # found one person who paid it all
        # create a final settlement where everyone else pays their owed amount to filtered_payer
        filtered_payers = filtered_payers[0]
        filtered_payers = mapped_uuids[filtered_payers]  # convert to group specific ethereum address for this user
        final_settlement[filtered_payers] = dict()
        for each in simplified_balance_mapping:
            if each != filtered_payers:
                final_settlement[filtered_payers].update({each: simplified_balance_mapping[each]})
    # for expenses that might have more than one participant in the group
    else:
        while True:
            if all(val == 0 for val in simplified_balance_mapping.values()):
                break
            negative_key = random.choice(
                list(
                    filter(lambda x: simplified_balance_mapping[x] < 0, simplified_balance_mapping)))  # pick a creditor
            positive_key = random.choice(
                list(filter(lambda x: simplified_balance_mapping[x] > 0, simplified_balance_mapping)))  # pick a debitor
            # min of(some owed value for a fat cat, some owes value for a poor boy)
            diff_val = min(-1 * simplified_balance_mapping[negative_key], simplified_balance_mapping[positive_key])
            if negative_key in final_settlement:
                final_settlement[negative_key].update({positive_key: diff_val})
            else:
                final_settlement[negative_key] = {positive_key: diff_val}
            simplified_balance_mapping[negative_key] += diff_val
            simplified_balance_mapping[positive_key] -= diff_val
            # print('Overall balance mapping: ', simplified_balance_mapping)
    rest_logger.info('Final settlement mapping: ')
    rest_logger.info(final_settlement)
    metadata = {
        'description': form_description,
        'date': form_date,
        'totalAmount': form_totalamount,
        'fileHash': file_hash,
        'isReimbursement': is_reimbursement
    }
    rest_logger.info(metadata)
    md_hash = keccak(text=json.dumps(metadata)).hex()
    md_hash = '0x' + md_hash
    # create bill on contract
    prev_bill_uuid = '0'
    prev_bill_uuidhash = '0x' + keccak(text="0").hex()
    contract_address = settings['contractAddress']
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/contract/{contract_address}/createBill'
    method_args = {
        'billUUIDHash': '0x' + keccak(text=bill_uuid).hex(),
        'prevBillUUIDHash': prev_bill_uuidhash,
        'metadataHash': md_hash,
        'splitMapCount': len(final_settlement.keys()),
        'createdBy': g.members.relationship(get_auth_creds()).address
    }
    rest_logger.info('Sending method args to createBill')
    rest_logger.info(method_args)
    r = requests.post(url=method_api_endpoint, json=method_args, headers=headers)
    rest_logger.info(r.text)
    rj = r.json()
    if rj['success']:
        # set prev uuid hash as null in relational DB if the "0" UUID bill is parent
        # else create relation between current bill node and supplied previous bill node
        txhash = rj['data'][0]['txHash']
        bill = Bill(
            uuid=bill_uuid,
            uuidhash=method_args["billUUIDHash"],
            metadata=metadata,
            expenseMap=expense_map,
            state='-1',
            createdBy=logged_in_uuid
        ).save()
        bill.group.connect(g, {"timestamp": ts, "billUUIDHash": method_args["billUUIDHash"]})
        if prev_bill_uuid != '0':
            prev_bill_node = Bill.nodes.first_or_none(uuid=prev_bill_uuid)
            if prev_bill_node:
                bill.parentBill.connect(prev_bill_node)
            else:
                rest_logger.error('Error updating connection to previous bill node in Graph DB')
                rest_logger.error(prev_bill_uuid)
        # create relational entry
        # check if previous bill UUID is '0'. If yes, sent prev uuidhash as null
        prev_uuid_hash_relational = None if prev_bill_uuid == '0' else prev_bill_uuidhash
        bill_r = MoneyVigilBill(
            uuid=bill_uuid,
            uuid_hash=method_args["billUUIDHash"],
            associated_metadata=json.dumps(metadata),
            expense_map=json.dumps(expense_map),
            state='-1',
            created_by=logged_in_uuid,
            bill_of=g.uuid,
            prev_uuid_hash=prev_uuid_hash_relational
        )
        db_sesh = Session()
        db_sesh.add(bill_r)
        db_sesh.commit()
        return_bill_obj = {
            'uuid': bill_r.uuid,
            'uuidHash': bill_r.uuid_hash,
            'prevBill': None if prev_bill_uuid == '0' else {'uuid': prev_bill_uuid, 'uuidHash': prev_bill_uuidhash},
            'metadata': json.loads(bill_r.associated_metadata),
            'expenseMap': json.loads(bill_r.expense_map),
            'state': bill_r.state
        }
        # cache final splits against billUUIDHash to be retrieved on webhook listener
        original_splitmap_key = ORIGINAL_SPLITMAP_KEY.format(contract_address, method_args["billUUIDHash"])
        effective_splitmap_key = EFFECTIVE_SPLITMAP_KEY.format(contract_address, method_args["billUUIDHash"])
        redis_master.set(original_splitmap_key, json.dumps(final_settlement))
        redis_master.set(effective_splitmap_key, json.dumps(final_settlement))
        if is_reimbursement:
            redis_master.set(PENDING_DISBURSAL_BILL.format(entity_reldb.contract, g.uuid), bill_uuid)
        Session.remove()
        return {
            'success': True,
            'txHash': txhash,
            'bill': return_bill_obj
        }, 201
    else:
        return jsonify({'success': False})


def update_bill(prev_bill_uuid, request_json):
    s = Session()
    dbwrapper = DBCallsWrapper()
    prev_bill_obj = dbwrapper.query_bill_by_(session_obj=s, uuid=prev_bill_uuid)
    if not prev_bill_obj:
        rest_logger.error('Referenced previous Bill does not exist')
        rest_logger.error(prev_bill_uuid)
        return jsonify({'success': False})
    if len(prev_bill_obj.child_bills) > 0:
        rest_logger.error('Referenced previous bill already has children')
        rest_logger.error(prev_bill_uuid)
        return jsonify({'success': False})
    prev_bill_uuid_hash = '0x' + keccak(text=prev_bill_uuid).hex()
    new_bill_uuid = str(uuid.uuid4())
    new_bill_date = request_json['date']
    group = request_json['group']
    g = Group.nodes.first_or_none(uuid=group)
    description = request_json['description']
    total_amount = request_json['totalAmount']
    expense_map = request_json['expenseMap']
    file_hash = request_json.get('fileHash', None)
    rest_logger.debug('Expense map')
    rest_logger.debug(expense_map)
    addl_splitmap = expensemap_to_splitmap(expense_map=expense_map, group_uuid=group, total_amount=total_amount)
    rest_logger.debug('Splitmap of the new expense map: ')
    rest_logger.debug(addl_splitmap)
    new_bill_original_splitmap = addl_splitmap  # we will set this on successful submission of the updated bill to createBill()
    # reverse splitmap of previously referenced bill
    reversed_splitmap = dict()
    # prev_effective_splitmap_key = EFFECTIVE_SPLITMAP_KEY.format(settings["contractAddress"], prev_bill_uuid_hash)
    prev_effective_splitmap_key = ORIGINAL_SPLITMAP_KEY.format(settings["contractAddress"], prev_bill_uuid_hash)
    try:
        prev_splitmap = json.loads(redis_master.get(prev_effective_splitmap_key))
    except:
        rest_logger.error('Could not find splitMap for previous Bill UUID Hash: ')
        rest_logger.error(prev_bill_uuid_hash)
    else:
        # reverse the splitmap
        reversed_splitmap = reverse_splitmap(prev_splitmap)
    rest_logger.debug('Reversed splitmap of the previous bill: ')
    rest_logger.debug(reversed_splitmap)
    # merge the splitmaps
    addl_splitmap = merge_splitmaps(addl_splitmap, reversed_splitmap)
    rest_logger.debug('Merged splitmap of reversed previous bill and current bill: ')
    rest_logger.debug(addl_splitmap)
    # metadata
    metadata = {
        'description': description,
        'date': new_bill_date,
        'totalAmount': total_amount,
        'fileHash': file_hash,
        'linkage': 'update',
        'isReimbursement': False
    }
    md_hash = keccak(text=json.dumps(metadata)).hex()
    md_hash = '0x' + md_hash
    rest_logger.debug('In /updatebill. Making EV call to createBill')
    contract_address = settings['contractAddress']
    api_key = settings['ETHVIGIL_API_KEY']
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/contract/{contract_address}/createBill'
    method_args = {
        'billUUIDHash': '0x' + keccak(text=new_bill_uuid).hex(),
        'prevBillUUIDHash': prev_bill_uuid_hash,
        'metadataHash': md_hash,
        'splitMapCount': len(addl_splitmap.keys()),
        'createdBy': g.members.relationship(get_auth_creds()).address
    }
    rest_logger.info('Sending method args to createBill')
    rest_logger.info(method_args)
    r = requests.post(url=method_api_endpoint, json=method_args, headers=headers)
    rest_logger.info(r.text)
    rj = r.json()
    if rj['success']:
        # set prev uuid hash as null in relational DB if the "0" UUID bill is parent
        # else create relation between current bill node and supplied previous bill node
        txhash = rj['data'][0]['txHash']
        bill = Bill(
            uuid=new_bill_uuid,
            uuidhash=method_args["billUUIDHash"],
            metadata=metadata,
            expenseMap=expense_map,
            state='0',
            createdBy=current_user.uuid
        ).save()
        bill.group.connect(g, {"timestamp": dt.datetime.utcnow(), "billUUIDHash": method_args["billUUIDHash"]})
        prev_bill_node = Bill.nodes.first_or_none(uuid=prev_bill_uuid)
        bill.parentBill.connect(prev_bill_node)
        # create relational entry
        bill_r = MoneyVigilBill(
            uuid=new_bill_uuid,
            uuid_hash=method_args["billUUIDHash"],
            associated_metadata=json.dumps(metadata),
            expense_map=json.dumps(expense_map),
            state='0',
            created_by=current_user.uuid,
            bill_of=g.uuid,
            prev_uuid_hash=prev_bill_uuid_hash
        )
        db_sesh = Session()
        db_sesh.add(bill_r)
        db_sesh.commit()
        return_bill_obj = {
            'uuid': bill_r.uuid,
            'uuidHash': bill_r.uuid_hash,
            'prevBill': {'uuid': prev_bill_uuid, 'uuidHash': prev_bill_uuid_hash},
            'metadata': metadata,
            'expenseMap': expense_map,
            'state': bill_r.STATES[bill_r.state]
        }
        Session.remove()
        # cache final splits against billUUIDHash to be retrieved on webhook listener
        effective_splitmap_key = EFFECTIVE_SPLITMAP_KEY.format(contract_address, method_args["billUUIDHash"])
        original_splitmap_key = ORIGINAL_SPLITMAP_KEY.format(contract_address, method_args["billUUIDHash"])
        redis_master.set(effective_splitmap_key, json.dumps(addl_splitmap))
        redis_master.set(original_splitmap_key, json.dumps(new_bill_original_splitmap))
        return jsonify({
            'success': True,
            'txHash': txhash,
            'bill': return_bill_obj
        })
    else:
        return jsonify({
            'success': False,
            'modifiedSplitMap': addl_splitmap
        })


def get_pending_bills():
    db_sesh = Session()
    db_u = current_user
    pending_bills = list()
    state_cond = or_(
        MoneyVigilBill.state == '-1',
        MoneyVigilBill.state == '0'
    )
    a = db_sesh.query(MoneyVigilBill).filter(state_cond, MoneyVigilBill.created_by == db_u.uuid).all()
    for b in a:
        prev_bill = b.prev_bill
        child_bill = None
        if len(b.child_bills) > 0:
            try:
                linkage = json.loads(b.child_bills[0].associated_metadata)['linkage']
            except:
                linkage = None
            child_bill = {
                'uuid': b.child_bills[0].uuid,
                'uuid_hash': b.child_bills[0].uuid_hash,
                'linkage': linkage
            }
        if prev_bill:
            prev_bill_obj = {'uuid': prev_bill.uuid, 'uuidHash': prev_bill.uuid_hash}
        else:
            prev_bill_obj = None
        pending_bills.append({
            'uuid': b.uuid,
            'uuidHash': b.uuid_hash,
            'prevBill': prev_bill_obj,
            'childBill': child_bill,
            'metadata': json.loads(b.associated_metadata),
            'expenseMap': json.loads(b.expense_map),
            'state': b.STATES[b.state]
        })
    Session.remove()
    return jsonify({
        'success': True,
        'bills': pending_bills
    })


def submit_bill_processing(request_json):
    """
    :param request.json['message'] -- the whole goddamn message
    :param request.json['signature'] -- the whole goddamn signature blob
    :param request.json['signer'] -- the signer damned to eternal hell
    :return: utter hopelessness
    """
    rest_logger.debug(request_json)
    msg_obj = request_json['message']['message']
    s = Session()
    dw = DBCallsWrapper()

    group_eth_addr = msg_obj['group']
    g_rel_obj = dw.query_group_by_(s, address=group_eth_addr)
    if not g_rel_obj:
        Session.remove()
        rest_logger.debug('Did not find group address in relational DB')
        rest_logger.debug(group_eth_addr)
        return {'success': False}
    # check if amount for disbursal matches bill amount
    if msg_obj['actionType'] == 'Disbursal':
        bill_reldb = dw.query_bill_by_(session_obj=s, uuid_hash=msg_obj['bill'])
        expense_map = json.loads(bill_reldb.expense_map)
        # find out paid amount by filtering expense map
        total_amount = 0
        for e in expense_map:
            total_amount += expense_map[e]['paid']
        if total_amount != msg_obj['amount']:
            return {'success': False, 'message': 'Bill amount and EIP-712 message amount do not match'}, 403
    # create teh data structure to be sent out for the MessageEntity structure
    api_key = settings['ETHVIGIL_API_KEY']
    # get ACL contract address from the group
    contract_address = g_rel_obj.corporate_entity.contract
    # expand the message object into individual components
    msg_obj_request_str = expand_messageobject(msg_obj)
    hex_sig = request_json['signature'][2:]
    sig_r = '0x' + hex_sig[:64]
    sig_s = '0x' + hex_sig[64:128]
    sig_v = int('0x' + hex_sig[128:130], 16)

    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/contract/{contract_address}/'
    if request_json['message']['message']['actionType'] == 'Approval':
        method_api_endpoint += 'submitApproval'
    elif request_json['message']['message']['actionType'] == 'Disbursal':
        method_api_endpoint += 'submitDisbursal'
    method_args = {
        'messageObj': msg_obj_request_str,
        'sigR': sig_r,
        'sigS': sig_s,
        'sigV': sig_v
    }
    rest_logger.info('Sending method args to')
    rest_logger.info(method_api_endpoint)
    rest_logger.info(method_args)
    r = requests.post(url=method_api_endpoint, json=method_args, headers=headers)
    rest_logger.info(r.text)
    r_json = r.json()
    if r_json['success']:
        # find bill objects and set state to pending approval
        bill_graph = Bill.nodes.first_or_none(uuidhash=msg_obj['bill'])
        bill_graph.state = '3' if msg_obj['actionType'] == 'Approval' else '5'
        bill_graph.save()
        bill_reldb = dw.query_bill_by_(session_obj=s, uuid_hash=msg_obj['bill'])
        bill_reldb.state = '3' if msg_obj['actionType'] == 'Approval' else '5'
        s.add(bill_reldb)
        s.commit()
        return_msg = {'success': True, 'txHash': r_json['data'][0]['txHash']}
    else:
        return_msg = {'success': r_json['success']}
    Session.remove()
    return return_msg

def delete_bill(prev_bill_uuid, request_json):
    s = Session()
    dbwrapper = DBCallsWrapper()
    prev_bill_obj = dbwrapper.query_bill_by_(session_obj=s, uuid=prev_bill_uuid)
    if not prev_bill_obj:
        rest_logger.error('Referenced previous Bill does not exist')
        rest_logger.error(prev_bill_uuid)
        return jsonify({'success': False})
    if len(prev_bill_obj.child_bills) > 0:
        rest_logger.error('Referenced previous bill already has children')
        rest_logger.error(prev_bill_uuid)
        return jsonify({'success': False})
    prev_bill_uuid_hash = '0x' + keccak(text=prev_bill_uuid).hex()
    contract_address = settings['contractAddress']
    # get previous split map
    splitmap_key = ORIGINAL_SPLITMAP_KEY.format(contract_address, prev_bill_uuid_hash)
    # splitmap_key = EFFECTIVE_SPLITMAP_KEY.format(contract_address, prev_bill_uuid_hash)
    try:
        prev_splitmap = json.loads(redis_master.get(splitmap_key))
    except Exception as e:
        rest_logger.error('Could not fetch split map for Bill UUID')
        rest_logger.error(prev_bill_uuid)
        rest_logger.error(e)
        return jsonify({'success': False})
    rest_logger.debug('Got previous split map')
    rest_logger.debug(prev_splitmap)
    # reverse the splits
    reversed_splitmap = dict()
    for creditor in prev_splitmap:
        for debitor in prev_splitmap[creditor]:
            entry = {creditor: prev_splitmap[creditor][debitor]}
            if debitor in reversed_splitmap:
                reversed_splitmap[debitor].update(entry)
            else:
                reversed_splitmap[debitor] = entry
    rest_logger.debug('Reversed split map of previous bill')
    rest_logger.debug(reversed_splitmap)
    # a self bill will not hold any reversals
    if len(reversed_splitmap.keys()) == 0:
        return jsonify({'success': True, 'reversedSplitMap': reversed_splitmap})
    # create new bill UUID that will hold reversal of the split Map
    del_uuid = str(uuid.uuid4())

    prev_metadata = json.loads(prev_bill_obj.associated_metadata)
    del_bill_metadata = {
        'description': f'Reversal for Bill UUID hash {prev_bill_uuid_hash}',
        'totalAmount': prev_metadata['totalAmount'],
        'date': request_json['date'],
        'fileHash': None,
        'linkage': 'delete'
    }
    # reverse the expense map too
    prev_expensemap = json.loads(prev_bill_obj.expense_map)
    reversed_expensemap = dict()
    for each in prev_expensemap:
        reversed_expensemap[each] = {'paid': prev_expensemap[each]['owes'], 'owes': prev_expensemap[each]['paid']}
    del_bill_obj = MoneyVigilBill(
        uuid=del_uuid,
        uuid_hash='0x' + keccak(text=del_uuid).hex(),
        state=0,
        expense_map=json.dumps(reversed_expensemap),
        associated_metadata=json.dumps(del_bill_metadata),
        created_by=current_user.uuid,
        bill_of=prev_bill_obj.bill_of,
        prev_uuid_hash=prev_bill_uuid_hash
    )
    # submit to contract via EV API
    group_graphdb = Group.nodes.first_or_none(
        uuid=prev_bill_obj.bill_of)  # to find out user specific eth address for this group
    api_key = settings['ETHVIGIL_API_KEY']
    contract_address = settings['contractAddress']
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/contract/{contract_address}/createBill'
    method_args = {
        'billUUIDHash': del_bill_obj.uuid_hash,
        'prevBillUUIDHash': prev_bill_uuid_hash,
        'metadataHash': '0x' + keccak(text=del_bill_obj.associated_metadata).hex(),
        'splitMapCount': len(reversed_splitmap.keys()),
        'createdBy': group_graphdb.members.relationship(get_auth_creds()).address
    }
    rest_logger.info('Sending method args to createBill')
    rest_logger.info(method_args)
    r = requests.post(url=method_api_endpoint, json=method_args, headers=headers)
    rest_logger.info(r.text)
    rj = r.json()
    if rj['success']:
        txhash = rj['data'][0]['txHash']
        s.add(del_bill_obj)
        s.commit()
        # save to graph DB too
        bill = Bill(
            uuid=del_uuid,
            uuidhash=del_bill_obj.uuid_hash,
            metadata=del_bill_metadata,
            expenseMap={},
            state='0',
            createdBy=current_user.uuid
        ).save()
        # connect to a group
        bill.group.connect(group_graphdb, {"timestamp": dt.datetime.utcnow(), "billUUIDHash": del_bill_obj.uuid_hash})
        # connect to previous group
        prev_bill_obj_graphdb = Bill.nodes.first_or_none(uuid=prev_bill_uuid)
        if prev_bill_obj_graphdb:
            bill.parentBill.connect(prev_bill_obj_graphdb)
        rest_logger.debug('Bill to delete previous bill sent out successfully | Bill UUID |  Prev UUID | TxHash')
        rest_logger.debug(del_uuid)
        rest_logger.debug(prev_bill_uuid)
        rest_logger.debug(txhash)
        return_bill_obj = {
            'uuid': del_bill_obj.uuid,
            'uuidHash': del_bill_obj.uuid_hash,
            'prevBill': {'uuid': prev_bill_uuid, 'uuidHash': prev_bill_uuid_hash},
            'metadata': del_bill_metadata,
            'expenseMap': {},
            'state': del_bill_obj.STATES[del_bill_obj.state]
        }
        Session.remove()
        # set reversed split map in cache
        reversed_splitmap_original_key = ORIGINAL_SPLITMAP_KEY.format(contract_address, del_bill_obj.uuid_hash)
        reversed_splitmap_effective_key = EFFECTIVE_SPLITMAP_KEY.format(contract_address, del_bill_obj.uuid_hash)
        redis_master.set(reversed_splitmap_original_key, json.dumps(reversed_splitmap))
        redis_master.set(reversed_splitmap_effective_key, json.dumps(reversed_splitmap))
        return jsonify({
            'success': True,
            'txHash': txhash,
            'bill': return_bill_obj
        })
    else:
        Session.remove()
        return jsonify({'success': False})


def get_bill(bill_uuid):
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    b = dbcall.query_bill_by_(session_obj=db_sesh, uuid=bill_uuid)
    if not b:
        return jsonify({'success': False})
    else:
        prev_bill = b.prev_bill
        child_bill = None
        if prev_bill:
            prev_bill = {
                'uuid': prev_bill.uuid,
                'uuid_hash': prev_bill.uuid_hash
            }
        if len(b.child_bills) > 0:
            try:
                linkage = json.loads(b.child_bills[0].associated_metadata)['linkage']
            except:
                linkage = None
            child_bill = {
                'uuid': b.child_bills[0].uuid,
                'uuid_hash': b.child_bills[0].uuid_hash,
                'linkage': linkage
            }
        return jsonify({
            'uuid': b.uuid,
            'metadata': json.loads(b.associated_metadata),
            'expenseMap': json.loads(b.expense_map),
            'state': b.STATES[b.state],
            'initialTxHash': b.initial_txhash,
            'finalTxHash': b.final_txhash,
            'group': b.bill_of,
            'prevBill': prev_bill,
            'childBill': child_bill
        })


# # # ---- bill operations end


@user_ns.route('/')
class MoneyVigilUserResource(Resource):
    @login_required
    @api_app.expect(PARSERS['user']['get'])
    def get(self):  # replacing @app.route('/getuser', methods=['POST'])
        req_args = PARSERS['user']['get'].parse_args()
        if not req_args['email']:
            return jsonify({'success': False}), 404
        else:
            return get_user_by_email(req_args['email'])

    @login_required
    @api_app.expect(PARSERS['user']['post'])
    def post(self):
        req_args = PARSERS['user']['post'].parse_args()
        return invite_add_user(req_args)


@user_ns.route('/<string:employeeUUID>/permissions')
class MoneyVigilUserPermissionsResource(Resource):
    @login_required
    def get(self, employeeUUID):
        return get_assigned_permissions(employeeUUID)


@logged_user_ns.route('/')
class LoggedInUser(Resource):
    @login_required
    def get(self):
        return get_user_info()

    @login_required
    def put(self):
        """
        Update logged in user info
        Supported fields:
            write-over updates:  `name, password, email, email_subscription`
            append updates: `walletAddresses`
            Example: `"walletAddresses": [{ "name": "new_wallet33", "address": "0x4a20608f7821d13dCB61aE130753cD58B597b03b"}]`

            Request example: (successful wallet address append, and email update)
                {
                    "walletAddresses": [
                        {
                            "name": "new_wallet89",
                            "name": "ndef put(ew_wallet89",
                            "address": "0x5d6D3f7691f53c8562f40ecBc6b63a01f23370FE"
                        }

                        ],
                    "email": "anomitghosh@gmail.com"
                }
            Response:
                {
                    "failed_fields": [],
                    "success": true,
                    "updated_fields": [
                        "email",
                        {
                            "data": {
                                "address": "0x5d6D3f7691f53c8562f40ecBc6b63a01f23370FE",
                                "name": "new_wallet89"
                            },
                            "field": "walletAddresses"
                        }
                    ]
                }
        """
        return update_userinfo()


@logged_user_ns.route('/groups')
class LoggedInUserGroupResource(Resource):
    @login_required
    def get(self):
        return get_groups_user()

    @login_required
    @api_app.expect(_post_group_members)
    def post(self):
        """Create a new group with the current logged in user and another specified member"""
        req_args = _post_group_members.parse_args()
        return addmember(req_args)

@logged_user_ns.route('/corporateEntity/<string:entityUUID>/groups')
class LoggedInUserEntityRoles(Resource):
    """
    Roles, permissions in corporate entities for current logged in user
    """
    @login_required
    def get(self, entityUUID):
        """
        Get groups,roles of logged in user against an entity
        """
        return get_entity_groups(entityUUID), 200


@corporate_entity_ns.route('/')
class MoneyVigilCorporateEntityResource(Resource):
    # TODO: Define a system level permission check for creation of a new entity. Would follow from UX decision
    @api_app.expect(PARSERS['corporate_entity']['post'])
    @login_required
    def post(self):
        """
        Create a new corporate entity
        """
        req_args = PARSERS['corporate_entity']['post'].parse_args()
        return create_entity(req_args)

@corporate_entity_ns.route('/<string:entityUUID>')
class MoneyVigilCorporateEntityResource(Resource):
    # TODO: add permission check for global level owner/approver/disburser to view entity details
    @login_required
    def get(self, entityUUID):
        """Get information about a corporate entity. email, dai balance and contract address"""
        s = Session()
        dbw = DBCallsWrapper()
        e = dbw.query_entity_by_(session_obj=s, uuid=entityUUID)
        if not e:
            return {'success': False}, 404
        contract_addr = to_normalized_address(e.contract) if e.contract else None
        rest_logger.debug('Got contraact address')
        rest_logger.debug(e.contract)
        ret_info = {
            'email': e.email,
            'daiBalance': 0,
            'cDaiBalance': 0,
            'name': e.name,
            'contract': contract_addr
        }
        if not contract_addr:
            return ret_info, 200
        if redis_master.exists(CONTRACT_DAI_FUNDS.format(contract_addr)):
            # TODO: some cache invalidation logic might help here
            ret_info['daiBalance'] = int(redis_master.get(CONTRACT_DAI_FUNDS.format(contract_addr)))
        else:
            try:
                bal = dai_contract_instance.balanceOf(contract_addr)
            except Exception as e:
                rest_logger.error('Error fetching Dai balance of contract')
                rest_logger.error(contract_addr)
                rest_logger.error(e)
                bal = 0
            else:
                bal = bal['uint256']
                redis_master.set(CONTRACT_DAI_FUNDS.format(contract_addr), bal)
                ret_info['daiBalance'] = bal

        if redis_master.exists(CONTRACT_CDAI_FUNDS.format(contract_addr)):
            # TODO: some cache invalidation logic might help here
            ret_info['cDaiBalance'] = int(redis_master.get(CONTRACT_CDAI_FUNDS.format(contract_addr)))
        else:
            try:
                c_bal = cdai_contract.balanceOf(contract_addr)
            except Exception as e:
                rest_logger.error('Error fetching cDai balance of contract')
                rest_logger.error(contract_addr)
                rest_logger.error(e)
                c_bal = 0
            else:
                c_bal = c_bal['uint256']
                redis_master.set(CONTRACT_DAI_FUNDS.format(contract_addr), c_bal)
            ret_info['daiBalance'] = c_bal

        rest_logger.debug(ret_info)
        Session.remove()
        return ret_info, 200

@corporate_entity_ns.route('/<string:entityUUID>/users/')
class MoneyVigilCorporateUser(Resource):
    @corporate_entity_ns.expect(PARSERS['corporate_entity_user']['post'])
    @entity_employee_ops_credential_check
    @login_required
    def post(self, entityUUID):
        """
        Add new employees to an entity. Email,name necessary. Not connected ethereum addresses.
        """
        req_args = PARSERS['corporate_entity_user']['post'].parse_args()
        req_args['entityUUID'] = entityUUID
        return add_employees(req_args)

    @corporate_entity_ns.expect(PARSERS['corporate_entity_user']['put'])
    @entity_employee_ops_credential_check
    @login_required
    def put(self, entityUUID):
        """
        Update eth addresses connected to registered employees
        """
        request_json = request.json
        # req_args = PARSERS['corporate_entity_user']['put'].parse_args()
        request_json['entityUUID'] = entityUUID
        # req_args['entityUUID'] = entityUUID
        rest_logger.debug('Got request args parsed I hope')
        rest_logger.debug(request_json)
        return update_employees(request_json)

    @entity_employee_ops_credential_check
    @login_required
    def get(self, entityUUID):
        """
        Returns all employees registered against an entity UUID
        """
        return get_entity_employees(entityUUID)


@corporate_entity_ns.route('/<string:entityUUID>/approvers/')
class MoneyVigilCorporateApprovers(Resource):
    @login_required
    @can_add_global_approver
    @api_app.expect(PARSERS['corporate_entity_approver']['post'])
    def post(self, entityUUID):
        """
        Add global level approvers
        """
        req_args = PARSERS['corporate_entity_approver']['post'].parse_args()
        return add_global_approvers(entityUUID, req_args)

    @login_required
    def get(self, entityUUID):
        """
        not yet implemented
        """
        return jsonify({'success': False, 'message': 'NotImplemented'}), 404


@corporate_entity_ns.route('/<string:entityUUID>/disbursers/')
class MoneyVigilCorporateDisbursers(Resource):
    @login_required
    @can_add_global_disburser
    @api_app.expect(PARSERS['corporate_entity_disburser']['post'])
    def post(self, entityUUID):
        """
        Add global level disbursers
        """
        req_args = PARSERS['corporate_entity_disburser']['post'].parse_args()
        return add_global_disbursers(req_args, entityUUID)

    @login_required
    def get(self, entityUUID):
        """
        not yet implemented
        """
        return jsonify({'success': False, 'message': 'NotImplemented'}), 404


@corporate_entity_ns.route('/<string:entityUUID>/owners/')
class MoneyVigilCorporateOwners(Resource):
    # @can_add_global_owner
    @login_required
    @api_app.expect(PARSERS['corporate_entity_owner']['post'])
    def post(self, entityUUID):
        """
        Add global level owners
        """
        req_args = PARSERS['corporate_entity_owner']['post'].parse_args()
        return add_global_owners(req_args, entityUUID)

    @login_required
    def get(self, entityUUID):
        """
        not yet implemented
        """
        return jsonify({'success': False, 'message': 'NotImplemented'}), 404


@corporate_entity_ns.route('/<string:entityUUID>/group/')
class MoneyVigilCorporateGroups(Resource):
    @login_required
    @api_app.expect(PARSERS['corporate_entity_group']['post'])
    def post(self, entityUUID):
        """
        Create a group under this corporate entity
        """
        req_args = PARSERS['corporate_entity_group']['post'].parse_args()
        return create_corporate_group(entity_uuid=entityUUID, request_json=req_args)


@corporate_entity_ns.route('/<string:entityUUID>/group/<string:groupUUID>/owners')
class MoneyVigilCorporateGroupOwners(Resource):
    @login_required
    @can_add_group_owner
    @api_app.expect(_post_entity_owners_parser)
    def post(self, entityUUID, groupUUID):
        """
        Add owners against a group
        """
        req_args = _post_entity_owners_parser.parse_args()
        return add_group_owners(entityUUID, groupUUID, req_args)

@corporate_entity_ns.route('/<string:entityUUID>/group/<string:groupUUID>/approvers')
class MoneyVigilCorporateGroupApprovers(Resource):
    @can_add_group_approver
    @login_required
    @api_app.expect(_post_entity_approvers_parser)
    def post(self, entityUUID, groupUUID):
        """
        Add approvers against a group
        """
        req_args = _post_entity_approvers_parser.parse_args()
        return add_group_approvers(entityUUID, groupUUID, req_args)


@corporate_entity_ns.route('/<string:entityUUID>/group/<string:groupUUID>/disbursers')
class MoneyVigilCorporateGroupDisbursers(Resource):
    @login_required
    @can_add_group_disburser
    @api_app.expect(_post_entity_disbursers_parser)
    def post(self, entityUUID, groupUUID):
        """
        Add disbursers against a group
        """
        req_args = _post_entity_disbursers_parser.parse_args()
        return add_group_disbursers(entityUUID, groupUUID, req_args)


@corporate_entity_ns.route('/<string:entityUUID>/role/<string:roleUUID>/permissions')
class MoneyVigilCorporateRolePermissions(Resource):
    @login_required
    @api_app.expect(PARSERS['corporate_entity_role_permissions']['put'])
    def put(self, entityUUID, roleUUID):
        req_args = PARSERS['corporate_entity_role_permissions']['put'].parse_args()
        return update_role_permissions(entityUUID, roleUUID, req_args)


@group_ns.route('/<string:groupUUID>/members')
class MoneyVigilPersonalGroupResource(Resource):
    @login_required
    def get(self, groupUUID):
        return get_group_members(groupUUID)

    @login_required
    @api_app.expect(_post_group_members)
    def post(self, groupUUID):
        """Add a specified user as a member against this group"""
        req_args = _post_group_members.parse_args()
        return addmember(request_json=req_args, group_secret=groupUUID)


@group_ns.route('/<string:groupUUID>/expenses')
class MoneyVigilGroupExpensesResource(Resource):
    @login_required
    def get(self, groupUUID):
        return get_group_expenses(groupUUID)


@group_ns.route('/<string:groupUUID>/simplifiedDebtGraph')
class MoneyVigilGroupSimplifiedDebtsResource(Resource):
    @login_required
    def get(self, groupUUID):
        return simplify_group_debts(groupUUID)


@group_ns.route('/<string:groupUUID>/totalDebts')
class MoneyVigilGroupTotalDebtsResource(Resource):
    @login_required
    def get(self, groupUUID):
        return get_groupdebts(groupUUID)


@group_ns.route('/<string:groupUUID>/billSplits')
class MoneyVigilGroupBillSplits(Resource):
    @login_required
    def get(self, groupUUID):
        return get_bill_splits(groupUUID)


@bill_ns.route('/<string:billUUID>/')
class MoneyVigilBillResource(Resource):
    @login_required
    def get(self, billUUID):
        return get_bill(billUUID)

    @login_required
    @api_app.expect(_put_update_bill, validate=False)
    def put(self, billUUID):
        """Update a bill"""
        req_args = _put_update_bill.parse_args()
        return update_bill(billUUID, req_args)

    @login_required
    @api_app.expect(_delete_bill)
    def delete(self, billUUID):
        """Delete a bill"""
        req_args = _delete_bill.parse_args()
        return delete_bill(billUUID, req_args)

    @individual_bill_ops_credential_check
    @login_required
    @api_app.expect(_post_bill_action, validate=False)
    def post(self, billUUID):
        """
        Take actions of `approve` or `disburse` on a bill.
        Example request body:
        ```
        {'action': 'approve'}
        ```
        or
        ```
        {'action': 'disburse'}
        ```
        """
        # req_args = _post_bill_action.parse_args()
        if not (request.json['action'] == 'approve' or request.json['action'] == 'disburse'):
            return {'sucess': False}, 403
        return submit_bill_processing(request.json)


@all_bills_ns.route('/pending')
class MoneyVigilBillsPendingResource(Resource):
    @login_required
    def get(self):
        return get_pending_bills()


@all_bills_ns.route('/')
class MoneyVigilBills(Resource):
    @bill_ops_credential_check
    @login_required
    @api_app.expect(_post_new_bill)
    def post(self):
        """Create a new bill"""
        req_args = _post_new_bill.parse_args()
        return addbill(req_args)


@app.route('/unsubscribe', methods=['POST'])
def unsubscribe_token_based():
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    request_json = request.json
    token = request_json['token']
    usub = dbcall.query_unsubscribetoken_by_(session_obj=db_sesh, code=token)
    if not usub:
        return jsonify({'success': False, 'message': 'TokenDoesNotExist'})
    user = dbcall.query_user_by_(session_obj=db_sesh, uuid=usub.user)
    user.email_subscription = False
    db_sesh.add(user)
    db_sesh.commit()
    return jsonify({'success': True})


@app.route('/signup', methods=['POST'])
def signup():
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    request_json = request.json
    email = request_json['email'].lower()
    invite_code = request_json.get('inviteCode', None)
    u = dbcall.query_user_by_(session_obj=db_sesh, email=email)
    rest_logger.info('User activation value')
    rest_logger.info(u.activated)
    if u:
        if u.activated == -1:
            pass
        elif u.activated == 0:
            # check if activation token expired
            cur_ts = int(time.time())
            expiry_ts = u.activation_expiry if u.activation_expiry else 0  # expiry might hold null value
            if expiry_ts > cur_ts:
                return jsonify({'success': False, 'message': 'NotActivated'})
            else:
                regen_send_activation(db_sesh, u)
                return jsonify({'success': False, 'message': 'ActivationExpired'})
        elif u.activated == 1:
            return jsonify({'success': False, 'message': 'SignedUp'})
    else:
        return jsonify({'success': False, 'message': 'InvalidUser'})
    password = request_json['password']
    name = request_json['name']
    password = bcrypt.hashpw(password, bcrypt.gensalt(12))
    # find out invite code entry
    i = dbcall.query_invites_by_all(session_obj=db_sesh, code=invite_code)[0]
    return_json = dict()
    if not i:
        return_json = {'success': False, 'message': 'InvalidInvite'}
    if email.lower() != i.email.lower():
        return_json = {'success': False, 'message': 'InvalidEmailForInvite'}
    # check time stamp
    cur_ts = int(time.time())
    if i.expiry < cur_ts:
        return jsonify({'success': False, 'message': 'ExpiredInvite'})
    else:
        # get uuid from graph DB that was filled during activation
        graph_u = User.nodes.first_or_none(email=email)
        if graph_u:
            gen_uuid = graph_u.uuid
            graph_u.name = name  # update the name supplied during sign up
            graph_u.save()
        # update user entry to activate
        u.activated = 1
        u.remaining_invites = 5
        u.activated_at = cur_ts
        u.password = password
        u.email_subscription = 1
        u.name = name
        # update invite as used
        i.used_at = cur_ts
        db_sesh.add(u)
        db_sesh.add(i)
        db_sesh.commit()
        # create a unsubscribe token for the activated user
        unsubscribe_token = str(uuid.uuid4())
        us = MoneyVigilUnsubscribeTokens(
            code=unsubscribe_token,
            user=u.uuid
        )
        db_sesh.add(us)
        db_sesh.commit()
        return_json = {
            'success': True,
            'uuid': gen_uuid,
            'unsubscribeToken': unsubscribe_token,
            'expenseGraphActivation': True if graph_u else False,
            'activated': True
        }
    Session.remove()
    return jsonify(return_json)


@app.route('/activate', methods=['POST'])
def activate():
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    request_json = request.json
    token = request_json['token']
    email = request_json['email'].lower()
    u = dbcall.query_user_by_(session_obj=db_sesh, email=email)
    return_json = dict()
    if u:
        if u.activated == 0:
            if token == u.activation_token:
                cur_ts = int(time.time())
                expiry_ts = u.activation_expiry
                if expiry_ts >= cur_ts:
                    u.activated = 1
                    u.activated_at = cur_ts
                    db_sesh.add(u)
                    db_sesh.commit()
                    try:
                        u_ = User(name=u.name, email=u.email, uuid=u.uuid).save()
                    except neomodel.exceptions.UniqueProperty:
                        u_ = None
                    return_json = {'success': True, 'expenseGraphActivation': True if u_ else False}
                else:
                    regen_send_activation(db_sesh, u)
                    return_json = {"success": False, 'message': 'ActivationExpired'}
            else:
                return_json = {"success": False, 'message': 'IncorrectToken'}
        else:
            return_json = {"success": False, 'message': 'SignedUp'}
    else:
        return_json = {'success': False}
    Session.remove()
    return jsonify(return_json)




@app.route('/splitmap', methods=['POST'])
@login_required
def get_splitmap():
    """
    Encapsulates the algorithm that creates a map of splits from an input of original shares of expenses
    Expects `expenseMap`, `totalAmount` in the request body
    :return: map of splits from a given expense map
    """
    simplified_balance_mapping = dict()
    final_settlement = dict()
    request_json = request.json
    expense_map = request_json["expenseMap"]
    total_amount = request_json["totalAmount"]
    for user_uuid in expense_map:
        user_node = User.nodes.first_or_none(uuid=user_uuid)
        if not user_node:
            return jsonify({'success': False, 'message': f'Invalid member UUID {user_uuid}'})

        # simplified_balance_mapping[user_grp_addr] = expense_map[user_uuid]['paid'] - expense_map[user_uuid]['owes']
        simplified_balance_mapping[user_uuid] = expense_map[user_uuid]['owes'] - expense_map[user_uuid]['paid']
    # print("Simplified balance mapping (lending model, not owed model): ", simplified_balance_mapping)
    rest_logger.info("Simplified balance mapping (owed model, not lending model): ")
    rest_logger.info(simplified_balance_mapping)
    # find out if one person has paid the entire bill. In that case, do not simplify further
    filtered_payer = list(filter(lambda x: expense_map[x]["paid"] == total_amount, expense_map))
    if len(filtered_payer) == 1:
        rest_logger.info("-----Only one payer for the entire bill!-----")
        # found one person who paid it all
        # create a final settlement where everyone else pays their owed amount to filtered_payer
        filtered_payer = filtered_payer[0]
        final_settlement[filtered_payer] = dict()
        for each in simplified_balance_mapping:
            if each != filtered_payer:
                final_settlement[filtered_payer].update({each: simplified_balance_mapping[each]})
    else:
        while True:
            if all(val == 0 for val in simplified_balance_mapping.values()):
                break
            negative_key = random.choice(
                list(
                    filter(lambda x: simplified_balance_mapping[x] < 0, simplified_balance_mapping)))  # pick a creditor
            positive_key = random.choice(
                list(filter(lambda x: simplified_balance_mapping[x] > 0, simplified_balance_mapping)))  # pick a debitor
            # min of(some owed value for a fat cat, some owes value for a poor boy)
            diff_val = min(-1 * simplified_balance_mapping[negative_key], simplified_balance_mapping[positive_key])
            if negative_key in final_settlement:
                final_settlement[negative_key].update({positive_key: diff_val})
            else:
                final_settlement[negative_key] = {positive_key: diff_val}
            simplified_balance_mapping[negative_key] += diff_val
            simplified_balance_mapping[positive_key] -= diff_val
            # print('Overall balance mapping: ', simplified_balance_mapping)
    rest_logger.info('Final settlement mapping: ')
    rest_logger.info(final_settlement)
    return jsonify({'success': True, 'data': final_settlement})


def sia_upload(file_hash, file_content):
    headers = {'user-agent': 'Sia-Agent', 'content-type': 'application/octet-stream'}
    rest_logger.debug('Attempting to upload file on Sia...')
    rest_logger.debug(file_hash)
    r = requests.post(
        url=f"http://localhost:9980/renter/uploadstream/{file_hash}?datapieces=10&paritypieces=20",
        headers=headers,
        data=file_content
    )
    rest_logger.debug('Got Sia upload response')
    rest_logger.debug(r.text)

@app.route('/vision', methods=['POST'])
@login_required
def cloudvision_processor():
    rest_logger.debug(request.form)
    uploaded_receipt_obj = request.files['receipt']
    receipt_filename = uploaded_receipt_obj.filename
    file_content = uploaded_receipt_obj.read()
    image = types.Image(content=file_content)
    file_hex = binascii.hexlify(file_content).hex()
    filehash = keccak(hexstr=file_hex).hex()
    # upload on Sia
    vision_client = vision.ImageAnnotatorClient()
    try:
        response = vision_client.annotate_image({
            # 'image': {'source': {'image_uri': f'gs://{settings["GCP_BUCKET"]}/{filehash}'}},
            'image': image,
            'features': [{'type': vision.enums.Feature.Type.TEXT_DETECTION}],
        })
    except Exception as e:
        rest_logger.error('Error processing receipt by Google CV || Exception follows')
        rest_logger.error(e, exc_info=True)
        return jsonify({'success': False, 'fileHash': filehash, 'message': 'CVFailed'})
    else:
        sia_upload(filehash, file_content)
    rest_logger.debug('Text detection results follow\n======================')
    # rest_logger.debug(type(response))
    ret_cv_response = ""
    description = ""
    try:
        text_results = [text.description for text in response.text_annotations]
    except Exception as e:
        rest_logger.error(
            'Error traveersing list of AnnotatedImageResponse || Response object, Exception follow')
        rest_logger.error(response.text_annotations)
        rest_logger.error(e)
    else:
        try:
            rest_logger.debug(text_results[0])
            text_result = text_results[0]
            text_result = text_result.split('\n')
            description = text_result[0]
        except Exception as e:
            rest_logger.error('Error extracting textual information from AnnotatedImageResponse')
            rest_logger.error(e, exc_info=True)
            description = ""
        else:
            ret_cv_response = text_results[0]
    total = 0.00
    amounts = list()
    try:
        for each in text_result:
            match_obj = re.findall(r'[0-9,]+\.[0-9]+$', each)
            # match_obj = re.match(r'(.)?\d+(\.\d{1,2})+$', each)
            # rest_logger.debug(f'Matching {each}.')
            if match_obj:
                rest_logger.debug(f'Found match. Finding matched string: {match_obj}')
                try:
                    amounts.append(float(match_obj[0].replace(',', '')))
                except:
                    continue
        if len(amounts) > 0:
            rest_logger.debug(f'Scanned amounts: {amounts}')
            total = max(amounts)
    except:
        total = 0.00
    return jsonify({
        'success': True,
        'description': description,
        'amount': total,
        'fileHash': filehash,
        'CVResponse': ret_cv_response
    })


def get_entity_groups(entity_uuid, cached_global_roles=None, session_obj=None):
    """
    :param request.json['entityUUID']
    """
    dbw = DBCallsWrapper()
    if not session_obj:
        s = Session()
    else:
        s = session_obj
    entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=entity_uuid)
    if not entity_reldb:
        return jsonify({'success': False})
    groups = dict()
    global_roles = ['GlobalOwner', 'GlobalApprover', 'GlobalDisburser']
    assigned_global_roles = list()
    _u = dbw.query_user_by_(session_obj=s, uuid=current_user.uuid)
    user_eth_addresses = set(map(lambda x: x.address, _u.eth_addresses))
    if not cached_global_roles:
        for _r in entity_reldb.roles:
            if _u in _r.assigned_users and _r.name in global_roles:
                role_eth_addresses = set(map(lambda x: x.address, _r.assigned_eth_addresses))
                assigned_global_roles.append({
                    'name': _r.name,
                    'uuid': _r.uuid,
                    'permissions': list(map(lambda x: x.name, _r.assigned_permissions)),
                    'connectedAddresses': list(user_eth_addresses.intersection(role_eth_addresses))
                })
    else:
        assigned_global_roles = cached_global_roles

    if len(assigned_global_roles) > 0:  # show all groups # maybe also return group specific roles too in case applicable
        for grp in entity_reldb.groups:
            global_perms = set()
            group_info = {
                'name': grp.name,
                'uuid': grp.uuid,
                'permissions': [

                ],
                'roles': [

                ],
                'members': [

                ]
            }
            for _r in grp.roles:
                if _u in _r.assigned_users:
                    role_eth_addresses = set(map(lambda x: x.address, _r.assigned_eth_addresses))
                    connected_eth_address = list(user_eth_addresses.intersection(role_eth_addresses))
                    group_info['roles'].append({'name': _r.name, 'uuid': _r.uuid, 'connectedAddresses': connected_eth_address})
                    # add permissions associated with roles
                    for _p in _r.assigned_permissions:
                        global_perms.add(_p.name)

            # populate permissions from global roles
            for _r1 in assigned_global_roles:
                global_perms = global_perms.union(set(_r1['permissions']))
            group_info['permissions'].extend(list(global_perms))
            groups[grp.uuid] = group_info

    for _r in _u.assigned_roles:
        # rest_logger.debug(f'Got assigned role for user {_u.uuid} | Role UUID: {_r.uuid} | Role name: {_r.name} ')
        # if _r.connected_group:
        #     rest_logger.debug(f'Connected Group: {_r.connected_group.name} | Connected Entity: {_r.connected_entity.uuid}')
        if _r.connected_group and _r.connected_entity.uuid == entity_uuid:  # if you happen to be connected with a group based role
            if _r.connected_group.uuid not in groups:
                # populate for the first ime
                group_info = {
                    'name': _r.connected_group.name,
                    'uuid': _r.connected_group.uuid,
                    'permissions': [

                    ],
                    'roles': [

                    ],
                    'members': [

                    ]
                }
                groups[_r.connected_group.uuid] = group_info
            role_eth_addresses = set(map(lambda x: x.address, _r.assigned_eth_addresses))
            connected_eth_address = list(user_eth_addresses.intersection(role_eth_addresses))
            groups[_r.connected_group.uuid]['roles'].append({
                'name': _r.name,
                'uuid': _r.uuid,
                'connectedAddresses': connected_eth_address
            })
            for _p in _r.assigned_permissions:
                if _p.name not in groups[_r.connected_group.uuid]['permissions']:
                    groups[_r.connected_group.uuid]['permissions'].append(_p.name)

    # also pull from graph DB regarding plain ass group memberships for the current logged in user
    # NOTE: query is from the perspective of the logged in user
    u_g_node = User.nodes.first_or_none(uuid=current_user.uuid)
    emp_role_entity_specific_reldb = dbw.query_role_by_(session_obj=s, name='Employee',
                                                        corporate_entity_id=entity_reldb.id)
    for g in u_g_node.connected_corporate_groups:
        if g.corporate_entity[0].uuid != entity_reldb.uuid:
            continue
        g_rel = u_g_node.connected_corporate_groups.relationship(g)
        if g_rel.role == 'Employee':
            group_info = {
                'name': g.name,
                'uuid': g.uuid,
                'permissions': [

                ],
                'roles': [

                ],
                'members': [

                ]
            }
            # get Employee role permissions
            if emp_role_entity_specific_reldb:
                group_info['roles'].append({'name': emp_role_entity_specific_reldb.name, 'uuid': emp_role_entity_specific_reldb.uuid})
                # get permissions
                for _p in emp_role_entity_specific_reldb.assigned_permissions:
                    group_info['permissions'].append(_p.name)
                groups[g.uuid] = group_info
    # fill members information of allowed groups that can be accessed
    # get corporate entity user representation
    for g_uuid in groups:
        g_reldb = dbw.query_group_by_(session_obj=s, uuid=g_uuid)
        for _m in g_reldb.users:
            user_eth_addresses = set(map(lambda x: x.address, _m.eth_addresses))
            employee_role_eth_addresses = set(map(lambda x: x.address, emp_role_entity_specific_reldb.assigned_eth_addresses))
            emp_connected_eth_addresses = list(user_eth_addresses.intersection(employee_role_eth_addresses))
            member_info = {'uuid': _m.uuid, 'email': _m.email, 'name': _m.name, 'corporate_representation': False, 'walletAddresses': emp_connected_eth_addresses}
            # check if member is not the corporate entity user representation
            if _m.email != entity_reldb.email:
                with driver.session() as session:
                    total_owes = session.read_transaction(return_user1_owes_total, _m.uuid, g_uuid)
                    total_owed = session.read_transaction(return_user1_is_owed_total, _m.uuid, g_uuid)
                    groups[g_uuid]['totalOwes'] = total_owes
                    groups[g_uuid]['totalOwed'] = total_owed
            else:
                member_info['corporate_representation'] = True
            groups[g_uuid]['members'].append(member_info)
        pending_state_cond = or_(
            MoneyVigilBill.state == '-1',
            MoneyVigilBill.state == '0'
        )
        pending_bills = s.query(MoneyVigilBill).filter(pending_state_cond).all()
        if pending_bills:
            groups[g_uuid]['pendingBills'] = len(pending_bills)
        groups[g_uuid]['currency'] = g_reldb.currency
        groups[g_uuid]['ethAddress'] = g_reldb.address
    if not session_obj:
        Session.remove()
    return {
        'success': True,
        'groups': list(map(lambda x: groups[x], groups)),
        'globalRoles': assigned_global_roles
    }


def get_assigned_permissions(employee_uuid=None):
    request_json = request.json
    acl = dict()
    s = Session()
    dbw = DBCallsWrapper()
    if employee_uuid:
        emp_reldb = dbw.query_user_by_(session_obj=s, uuid=employee_uuid)
    else:
        emp_reldb = dbw.query_user_by_(session_obj=s, uuid=current_user.uuid)
    for r in emp_reldb.assigned_roles:
        user_eth_addresses = set(map(lambda x: x.address, emp_reldb.eth_addresses))
        role_eth_addresses = set(map(lambda x: x.address, r.assigned_eth_addresses))
        connected_eth_address = list(user_eth_addresses.intersection(role_eth_addresses))
        role_info = {
            'role': {
                'uuid': r.uuid,
                'name': r.name,
                'connectedAddresses': connected_eth_address
            }
        }
        if r.connected_group:
            role_info.update({'group': r.connected_group.uuid})
        permissions = list()
        for a in r.assigned_permissions:
            perm_info = a.name
            if a.specific_sublinkage:
                try:
                    perm_info.update(json.loads(a.specific_sublinkage))
                except:
                    pass
            permissions.append(perm_info)
        role_info.update({'permissions': permissions})
        if r.connected_entity.uuid not in acl:
            acl[r.connected_entity.uuid] = {
                'entity': {
                    'name': r.connected_entity.name,
                    'uuid': r.connected_entity.uuid,
                    'email': r.connected_entity.email
                },
                'allowed': [role_info]
            }
        else:
            acl[r.connected_entity.uuid]['allowed'].append(role_info)
    Session.remove()
    acl_t = list(map(lambda x: acl[x], acl))
    return jsonify({'success': True, 'ACL': acl_t})


def add_employees(request_json):
    """
    :param request.json['employees'] : Invite employees to this entity.
           Email addresses provided. [{"email": "", "name": "Anomit"},...]
           --OR--
           UUID's provided with optional ethereum addresses to connect to the Employee Role against the Corporate Entity
            [{"uuid": "34253478-45658-x56t", "eth_address": null}]
    :param request.json['entityUUID'] : UUID of the corporate entity against which these owners will be added

    :return:

    Request body example:
    {
        "entityUUID": "10d6e91c-2781-47f3-80aa-fb99b167a78d",
        "employees": [
            {"email": "anomit+299@blockvigil.com"},
            {"uuid": "f5b413ac-1d1a-46d5-868d-37a06c98eb1e", "eth_address": null},
            {"email": "anomit+300@blockvigil.com", "name": "ano 300"}
        ]
    }
    """
    # request_json = request.json
    employees_l = request_json['employees']
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    if len(employees_l) < 1:
        return jsonify({'success': False, 'message': 'One or more employees to be supplied'})

    entity_uuid = request_json['entityUUID']
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    entity_reldb = dbcall.query_entity_by_(session_obj=db_sesh, uuid=entity_uuid)
    if not entity_graph:
        return jsonify({'success': False, 'message': 'EntityDoesNotExist'})
    return_json = list()
    # connect with Employee role
    rest_logger.debug(f'Finding Employee role for Corporate Entity with primary ID: {entity_reldb.id}')
    emp_role_reldb = dbcall.query_role_by_(session_obj=db_sesh, name='Employee', corporate_entity_id=entity_reldb.id)
    emp_uuid_list = list()
    for emp in employees_l:
        try:
            email = emp['email'].lower()
        except KeyError:  # work with UUIDs
            emp_uuid_list.append(emp)
        else:  # work with email address

            invitee_u = dbcall.query_user_by_(session_obj=db_sesh, email=email)
            if invitee_u:
                # email to be invited already exists in DB
                invitee_u.assigned_roles.append(emp_role_reldb)
                db_sesh.add(invitee_u)
                return_json.append({
                    'invitedStatus': False,
                    'emailDeliveryStatus': False,
                    'uuid': invitee_u.uuid
                })
            else:
                name = emp['name']
                i = dbcall.query_invites_by_all(session_obj=db_sesh, email=email)
                if i:
                    return_json = {'success': False, 'message': 'InviteExists'}
                else:
                    invite_code = random_string(string_length=6)
                    i = MoneyVigilInvites(
                        code=invite_code,
                        email=email,
                        email_sent=False,
                        reusable=False,
                        reuseCount=None,
                        expiry=int(time.time()) + 7 * 24 * 3600,
                        used_at=None,
                        invited_by=get_auth_creds().uuid
                    )
                    inviter = dbcall.query_user_by_(session_obj=db_sesh, uuid=i.invited_by)

                    try:
                        email_status = send_invite_email(email, invite_code, name, inviter.name, inviter.email)
                    except:
                        rest_logger.error('Error sending invite email')
                        rest_logger.error(email)
                        email_status = False
                    invited_status = True
                    i.email_sent = email_status
                    u_uuid = str(uuid.uuid4())
                    # create entry in relational db
                    new_u = MoneyVigilUser(
                        name=name,
                        email=email,
                        password='dummy#',
                        activated=-1,
                        uuid=u_uuid,
                        activation_token='000000',  # dummy token
                        email_subscription=False
                    )

                    new_u.assigned_roles.append(emp_role_reldb)

                    db_sesh.add(new_u)
                    db_sesh.add(i)

                    # create entry in graph db
                    try:
                        u_ = User(name=name, email=email, uuid=u_uuid).save()
                    except neomodel.exceptions.UniqueProperty:  # email exists
                        u_ = None
                    return_json.append({
                        'invitedStatus': invited_status,
                        'emailDeliveryStatus': email_status,
                        'uuid': u_.uuid
                    })
        db_sesh.commit()
    uuid_update_status = None
    if emp_uuid_list:
        ret_status = assign_employees(db_sesh, emp_role_reldb, entity_uuid, emp_uuid_list)
        ret_status.pop('success', None)
        uuid_update_status = ret_status
    Session.remove()
    return jsonify({'success': True, 'inviteStatus': return_json, 'updateStatus': uuid_update_status})


def update_employees(request_json):
    """
    :param request.json['employees'] : Update employees to this entity.
           UUID's provided with optional ethereum addresses to connect to the Employee Role against the Corporate Entity
            [{"uuid": "34253478-45658-x56t", "eth_address": "0xaddr}]
    :param request.json['entityUUID'] : UUID of the corporate entity against which these owners will be added

    :return:

    Request body example:
    {
        "entityUUID": "10d6e91c-2781-47f3-80aa-fb99b167a78d",
        "employees": [
            {"uuid": "f5b413ac-1d1a-46d5-868d-37a06c98eb1e", "eth_address": "0x008604d4997a15a77f00ca37aa9f6a376e129dc5"},
        ]
    }
    """
    employees_l = request_json['employees']
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    rest_logger.debug('In subroputine')
    if len(employees_l) < 1:
        return {'success': False, 'message': 'One or more employees to be supplied'}

    entity_uuid = request_json['entityUUID']
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    entity_reldb = dbcall.query_entity_by_(session_obj=db_sesh, uuid=entity_uuid)
    if not entity_graph:
        return {'success': False, 'message': 'EntityDoesNotExist'}
    # connect with Employee role
    rest_logger.debug(f'Finding Employee role for Corporate Entity with primary ID: {entity_reldb.id}')
    emp_role_reldb = dbcall.query_role_by_(session_obj=db_sesh, name='Employee', corporate_entity_id=entity_reldb.id)
    ret_status = assign_employees(db_sesh, emp_role_reldb, entity_uuid, employees_l)
    ret_status.pop('success', None)
    Session.remove()
    return {'success': True, 'updateStatus': ret_status}, 201


@app.route('/invite', methods=['POST'])
def invite_main_entry():
    request_json = request.json
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    email = request_json['email'].lower()
    name = request_json['name']
    invitee_u = dbcall.query_user_by_(session_obj=db_sesh, email=email)
    return_json = dict()
    if invitee_u:
        return_json = {'success': False, 'message': 'UserExists',
                       'signedUp': True if invitee_u.activated == 1 else False}
    else:
        # create a new user entry
        invited_by_uuid = settings['NEO']['uuid']
        i = dbcall.query_invites_by_all(session_obj=db_sesh, email=email)
        if i:
            return_json = {'success': False, 'message': 'InviteExists'}
        else:
            invite_code = random_string(string_length=6)
            i = MoneyVigilInvites(
                code=invite_code,
                email=email,
                email_sent=False,
                reusable=False,
                reuseCount=None,
                expiry=int(time.time()) + 7 * 24 * 3600,
                used_at=None,
                invited_by=invited_by_uuid
            )
            # check remainingInviteQuota
            inviter = dbcall.query_user_by_(session_obj=db_sesh, uuid=invited_by_uuid)
            if inviter.remaining_invites > 0:
                email_status = send_invite_email(email, invite_code, name, inviter.name, inviter.email)
                invited_status = True
                inviter.remaining_invites = inviter.remaining_invites - 1
                i.email_sent = email_status
                db_sesh.add(inviter)
            elif inviter.remaining_invites == 0:
                invited_status = False
                email_status = False
                i.email_sent = None
            u_uuid = str(uuid.uuid4())
            # create entry in relational db
            new_u = MoneyVigilUser(
                name='',
                email=email,
                password='dummy#',
                activated=-1,
                uuid=u_uuid,
                activation_token='000000',  # dummy token
                email_subscription=False
            )
            db_sesh.add(new_u)
            db_sesh.add(i)
            db_sesh.commit()
            # create entry in graph db
            try:
                u_ = User(name=name, email=email, uuid=u_uuid).save()
            except neomodel.exceptions.UniqueProperty:  # email exists
                u_ = None
            return_json = {
                'success': True,
                'invitedStatus': invited_status,
                'emailDeliveryStatus': email_status,
                'uuid': u_.uuid,
                'remainingInvites': inviter.remaining_invites
            }
    Session.remove()
    ret_codes = {
        'UserExists': 403,
        'InviteExists': 403
    }
    if not return_json['success']:
        try:
            return_code = ret_codes[return_json['message']]
        except:
            return_code = 403
    else:
        return_code = 201
    return jsonify(return_json), return_code

def invite_add_user(request_json):
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    email = request_json['email'].lower()
    name = request_json['name']
    invitee_u = dbcall.query_user_by_(session_obj=db_sesh, email=email)
    return_json = dict()
    if invitee_u:
        return_json = {'success': False, 'message': 'UserExists',
                       'signedUp': True if invitee_u.activated == 1 else False}
    else:
        i = dbcall.query_invites_by_all(session_obj=db_sesh, email=email)
        if i:
            return_json = {'success': False, 'message': 'InviteExists'}
        else:
            invite_code = random_string(string_length=6)
            i = MoneyVigilInvites(
                code=invite_code,
                email=email,
                email_sent=False,
                reusable=False,
                reuseCount=None,
                expiry=int(time.time()) + 7 * 24 * 3600,
                used_at=None,
                invited_by=get_auth_creds().uuid
            )
            # check remainingInviteQuota
            inviter = dbcall.query_user_by_(session_obj=db_sesh, uuid=i.invited_by)
            if inviter.remaining_invites > 0:
                email_status = send_invite_email(email, invite_code, name, inviter.name, inviter.email)
                invited_status = True
                inviter.remaining_invites = inviter.remaining_invites - 1
                i.email_sent = email_status
                db_sesh.add(inviter)
            elif inviter.remaining_invites == 0:
                invited_status = False
                email_status = False
                i.email_sent = None
            u_uuid = str(uuid.uuid4())
            # create entry in relational db
            new_u = MoneyVigilUser(
                name=name,
                email=email,
                password='dummy#',
                activated=-1,
                uuid=u_uuid,
                activation_token='000000',  # dummy token
                email_subscription=False
            )
            db_sesh.add(new_u)
            db_sesh.add(i)
            db_sesh.commit()
            # create entry in graph db
            try:
                u_ = User(name=name, email=email, uuid=u_uuid).save()
            except neomodel.exceptions.UniqueProperty:  # email exists
                u_ = None
            return_json = {
                'success': True,
                'invitedStatus': invited_status,
                'emailDeliveryStatus': email_status,
                'uuid': u_.uuid,
                'remainingInvites': inviter.remaining_invites
            }
    Session.remove()
    return jsonify(return_json)


def create_entity(request_json):
    """
    :param request_json['name'] : name of entity to be registered
    :param request_json['email'] : email of entity to be registered
    :param request_json['deploy'] : boolean. If true, look for necessary deployment params: uuid/uuidhash, chainid
    :param request_json['walletAddress']: the eth address of the user firing the create request through which the first globalowner will be added
    :param request_json['uuid'] : OPTIONAL. used to initialize the contract with a pre-supplied UUID - identifies the corporate entity
    :param request_json['chainId'] :
    :param request_json['contractAddress'] : OPTIONAL. already deployed contract
    :return:

    Request body example:
   {
        "name": "Dummy Entity",
        "chainId": 8995,
        "deploy": true,
        "email": "entity42@bsdk.c0m",
        "walletAddress": "0x902abade63a5cb1b503fe389aea5906d18daaf2b"
    }
    """
    name = request_json['name']
    email = request_json['email']
    chain_id = request_json['chainId']
    s = Session()
    if s.query(MoneyVigilCorporateEntity).filter_by(email=email).first():
        return {'success': False, 'message': 'EmailExists'}, 403
    if s.query(MoneyVigilCorporateEntity).filter_by(name=name).first():
        return {'success': False, 'message': 'NameExists'}, 403
    if request_json['uuid']:
        gen_uuid = request_json['uuid']
    else:
        gen_uuid = str(uuid.uuid4())
    if not request_json['deploy']:  # use the supplied contract address if deploy flag is set to false
        contract_addr = request_json['contractAddress']
    else:
        contract_addr, txhash = deploy_acl_contract(entity_uuid=gen_uuid, chain_id=chain_id)
        if not contract_addr:
            Session.remove()
            return jsonify({'success': False, 'message': 'NoDeployACL'}), 500
        # register hook for one time tx monitoring
        # register hook for ACL contract events
        webhook_url = settings["ACL_WEBHOOK_ENPOINT"]
        ev_add_webhook(contract_address=contract_addr, url=webhook_url)
        # add deployment tx in a redis queue t
    contract_addr = to_normalized_address(contract_addr)
    # data model entries
    # graph DB
    # create a CorporateEntity node
    # connect the owner user node with this
    entity_graph = CorporateEntity(
        uuid=gen_uuid,
        uuidhash='0x' + keccak(text=gen_uuid).hex(),
        name=name,
        email=email,
        contract=contract_addr,
        chain_id=chain_id
    )
    entity_graph.save()
    # create a user node corresponding to this entity.
    # all expenses will be recorded in the future in the graph DB against this node
    gen_entity_user_uuid = str(uuid.uuid4())
    entity_user_graph = User(
        uuid=gen_entity_user_uuid,
        name=name,
        email=email
    )
    entity_user_graph.save()
    entity_graph.user_representation.connect(entity_user_graph)
    # populate default permissions for global roles
    # cache transient state of ACL contract yet to be mined along with the deploying user
    redis_master.set(TO_BE_MINED_ACL_CONTRACTS.format(entity_graph.uuidhash), to_normalized_address(request_json['walletAddress']))
    entity_info_hash = {
        'uuid': gen_uuid,
        'representationalUUID': gen_entity_user_uuid,
        'name': name,
        'email': email,
        'chainID': chain_id
    }
    redis_master.set(TO_BE_MINED_ENTITY_INFODUMP.format(entity_graph.uuidhash), json.dumps(entity_info_hash))

    e = EthereumAddress.nodes.first_or_none(address=to_normalized_address(request_json['walletAddress']))
    if e:
        e.connected_user[0].connected_entities.connect(entity_graph, {
            'address': to_normalized_address(to_normalized_address(request_json['walletAddress'])),
            'role': 'Employee'
        })
    return {
        'success': True,
        'entity': {
            'contract': contract_addr,
            'uuid': gen_uuid,
            'uuidHash': '0x' + keccak(text=gen_uuid).hex(),
            'chain_id': chain_id,
            'name': name,
        }
    }


def get_entity_employees(entity_uuid):
    dbw = DBCallsWrapper()
    s = Session()
    entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=entity_uuid)
    if not entity_reldb:
        return jsonify({'success': False})
    role_reldb = dbw.query_role_by_(session_obj=s, name='Employee', corporate_entity_id=entity_reldb.id)
    return_json = list()
    for u_ in role_reldb.assigned_users:
        user_data = {
            'uuid': u_.uuid,
            'name': u_.name,
            'email': u_.email,
            'activated': u_.activated,
            'emailSubscription': u_.email_subscription,
            'groups': [],
            'globalRoles': []
        }
        user_eth_addresses = set(map(lambda x: x.address, u_.eth_addresses))
        rest_logger.debug(f'Ethereum addresses for logged in user: {user_eth_addresses}')
        employee_role_eth_addresses = set(map(lambda x: x.address, role_reldb.assigned_eth_addresses))
        rest_logger.debug(f'Ethereum addresses for Employee role: {employee_role_eth_addresses}')
        emp_connected_eth_addresses = list(user_eth_addresses.intersection(employee_role_eth_addresses))
        rest_logger.debug(f'Intersection of aboce two: {emp_connected_eth_addresses}')
        user_data.update({'connectedAddresses': emp_connected_eth_addresses})
        for g in u_.groups:
            if g in entity_reldb.groups and g.approval_required:
                group_data = {
                    'uuid': g.uuid,
                    'name': g.name,
                    'currency': g.currency,
                    'approval_required': g.approval_required,
                    'roles': []
                }
                for r in g.roles:
                    if u_ in r.assigned_users:
                        # user_eth_addresses = set(map(lambda x: x.address, u_.eth_addresses))
                        role_eth_addresses = set(map(lambda x: x.address, r.assigned_eth_addresses))
                        connected_eth_address = list(user_eth_addresses.intersection(role_eth_addresses))
                        group_data['roles'].append({
                            'name': r.name,
                            'uuid': r.uuid,
                            'connectedAddresses': connected_eth_address
                        })
                user_data['groups'].append(group_data)
        # check if part of global roles
        global_roles = ['GlobalOwner', 'GlobalApprover', 'GlobalDisburser']
        assigned_global_roles = list()
        for _r in entity_reldb.roles:
            if u_ in _r.assigned_users and _r.name in global_roles:
                # assigned_global_roles.append({'name': _r.name, 'uuid': _r.uuid,
                #                               'permissions': list(map(lambda x: x.name, _r.assigned_permissions))})
                role_eth_addresses = set(map(lambda x: x.address, _r.assigned_eth_addresses))
                connected_eth_address = list(user_eth_addresses.intersection(role_eth_addresses))
                user_data['globalRoles'].append({'name': _r.name, 'permissions': list(map(lambda x: x.name, _r.assigned_permissions)), 'connectedAddresses': connected_eth_address})
        return_json.append(user_data)
    Session.remove()
    return jsonify({'success': True, 'users': return_json})


def add_global_owners(request_json, entity_uuid):
    owners_l = request_json['owners']
    if len(owners_l) < 1:
        return jsonify({'success': False, 'message': 'One or more owners to be supplied'})
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    if not entity_graph:
        return jsonify({'success': False, 'message': 'EntityDoesNotExist'})
    entity_contract_addr = entity_graph.contract
    entity_name = entity_graph.name
    # connect ownership with the right ethereum address in graph DB
    for owner in owners_l:
        owner_uuid = owner['uuid']
        owner_graph_node = User.nodes.first_or_none(uuid=owner_uuid)
        if not owner_graph_node:
            Session.remove()
            rest_logger.error('Could not find owner in graph DB. UUID: ')
            rest_logger.error(owner_uuid)
            return jsonify({
                'success': False,
                'entity': {
                    'contract': entity_contract_addr,
                    'uuid': entity_uuid,
                    'chain_id': entity_graph.chain_id,
                    'name': entity_name
                },
                'error': 'EntityOwnershipUpdateGraphDB'
            })
        else:
            # do a check whether supplied address is indeed registered against this user UUID
            found = False
            for e in owner_graph_node.ethereum_addresses:
                if e.address == to_normalized_address(owner['eth_address']):
                    found = True
                    break
            if found:
                owner_graph_node.connected_entities.connect(entity_graph, {
                    'address': to_normalized_address(owner['eth_address']),
                    'role': 'GlobalOwner'
                })
            else:
                rest_logger.error(
                    'Could not find ethereum address associated with owner in graph DB | UUID | Eth address ')
                rest_logger.error(owner_uuid)
                rest_logger.error(owner['eth_address'])
                return jsonify({
                    'success': False,
                    'entity': {
                        'contract': entity_contract_addr,
                        'uuid': entity_uuid,
                        'chain_id': entity_graph.chain_id,
                        'name': entity_name
                    },
                    'error': 'EntityOwnershipUpdateGraphDB'
                })
    # once graph connections have been verified and persisted, make a call to ethvigil APIs
    owners_eth_addr_l = list(map(lambda x: to_normalized_address(x['eth_address']), owners_l))
    tx = ev_add_entity_global_owners(contract_address=entity_contract_addr, owners_list=owners_eth_addr_l)
    if tx:
        return jsonify({'success': True, 'txHash': tx})
    else:
        return jsonify({'success': False})


def add_global_approvers(entity_uuid, request_json):
    approvers_l = request_json['approvers']
    if len(approvers_l) < 1:
        return jsonify({'success': False, 'message': 'One or more owners to be supplied'})
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    if not entity_graph:
        return jsonify({'success': False, 'message': 'EntityDoesNotExist'})
    entity_contract_addr = entity_graph.contract
    entity_name = entity_graph.name
    # connect ownership with the right ethereum address in graph DB
    for approver in approvers_l:
        approver_uuid = approver['uuid']
        approver_graph_node = User.nodes.first_or_none(uuid=approver_uuid)
        if not approver_graph_node:
            rest_logger.error('Could not find approver in graph DB. UUID: ')
            rest_logger.error(approver_uuid)
            return jsonify({
                'success': False,
                'entity': {
                    'contract': entity_contract_addr,
                    'uuid': entity_uuid,
                    'chain_id': entity_graph.chain_id,
                    'name': entity_name
                },
                'error': 'EntityApproverUpdateGraphDB'
            })
        else:
            # do a check whether supplied address is indeed registered against this user UUID
            found = False
            for e in approver_graph_node.ethereum_addresses:
                if e.address == to_normalized_address(approver['eth_address']):
                    found = True
                    break
            if found:
                approver_graph_node.connected_entities.connect(entity_graph, {
                    'address': to_normalized_address(approver['eth_address']),
                    'role': 'GlobalApprover'
                })
            else:
                rest_logger.error(
                    'Could not find ethereum address associated with approver in graph DB | UUID | Eth address ')
                rest_logger.error(approver_uuid)
                rest_logger.error(approver['eth_address'])
                return jsonify({
                    'success': False,
                    'entity': {
                        'contract': entity_contract_addr,
                        'uuid': entity_uuid,
                        'chain_id': entity_graph.chain_id,
                        'name': entity_name
                    },
                    'error': 'EntityApproverUpdateGraphDB'
                })
    # once graph connections have been verified and persisted, make a call to ethvigil APIs
    approvers_eth_addr_l = list(map(lambda x: to_normalized_address(x['eth_address']), approvers_l))
    tx = ev_add_entity_global_approvers(contract_address=entity_contract_addr, approvers_list=approvers_eth_addr_l)
    if tx:
        return jsonify({'success': True, 'txHash': tx})
    else:
        return jsonify({'success': False})


def add_global_disbursers(request_json, entity_uuid):
    disbursers_l = request_json['disbursers']
    if len(disbursers_l) < 1:
        return jsonify({'success': False, 'message': 'One or more disbursers to be supplied'})
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    if not entity_graph:
        return jsonify({'success': False, 'message': 'EntityDoesNotExist'})
    entity_contract_addr = entity_graph.contract
    entity_name = entity_graph.name
    # connect ownership with the right ethereum address in graph DB
    for disburser in disbursers_l:
        disburser_uuid = disburser['uuid']
        disburser_graph_node = User.nodes.first_or_none(uuid=disburser_uuid)
        if not disburser_graph_node:
            rest_logger.error('Could not find approver in graph DB. UUID: ')
            rest_logger.error(disburser_uuid)
            return jsonify({
                'success': False,
                'entity': {
                    'contract': entity_contract_addr,
                    'uuid': entity_uuid,
                    'chain_id': entity_graph.chain_id,
                    'name': entity_name
                },
                'error': 'EntityDisburserUpdateGraphDB'
            })
        else:
            # do a check whether supplied address is indeed registered against this user UUID
            found = False
            for e in disburser_graph_node.ethereum_addresses:
                if e.address == to_normalized_address(disburser['eth_address']):
                    found = True
                    break
            if found:
                disburser_graph_node.connected_entities.connect(entity_graph, {
                    'address': to_normalized_address(disburser['eth_address']),
                    'role': 'GlobalDisburser'
                })
            else:
                rest_logger.error(
                    'Could not find ethereum address associated with approver in graph DB | UUID | Eth address ')
                rest_logger.error(disburser_uuid)
                rest_logger.error(disburser['eth_address'])
                return jsonify({
                    'success': False,
                    'entity': {
                        'contract': entity_contract_addr,
                        'uuid': entity_uuid,
                        'chain_id': entity_graph.chain_id,
                        'name': entity_name
                    },
                    'error': 'EntityDisburserUpdateGraphDB'
                })
    # once graph connections have been verified and persisted, make a call to ethvigil APIs
    disbursers_eth_addr_l = list(map(lambda x: to_normalized_address(x['eth_address']), disbursers_l))
    tx = ev_add_entity_global_disbursers(contract_address=entity_contract_addr, disbursers_list=disbursers_eth_addr_l)
    if tx:
        return jsonify({'success': True, 'txHash': tx})
    else:
        return jsonify({'success': False})


def create_corporate_group(entity_uuid, request_json):
    """
        :param request.json['group'] <optional> supplied as UUID
        :param request.json['name'] group name
        :param request.json['currency'] group currency
        :param request.json['employee'] <optional> employee to be added {'uuid': , 'eth_address': <optional>}
                If eth_addr is not supplied, the hash of group_uuid+member_uuid will be used as private key to generate an address
        {'address': '0x00', 'role': 'GroupApprover'}
        :return:

        Request body example:
        {
            "entityUUID": "2555151e-4ce1-4476-bd2f-48cb5e57fba8",
            "name": "CorporateGroup5",
            "currency": "INR",
            "employee": {
                "uuid": "06647970-197f-462f-b2f8-81a705229679"
            }
        """
    return_json = dict()
    employee_uuid = request_json['employee']['uuid']
    try:
        group_uuid = request_json['group']
    except KeyError:
        group_uuid = str(uuid.uuid4())
    else:
        if not group_uuid:
            group_uuid = str(uuid.uuid4())
    group_eth_address = to_normalized_address(eth_account.Account.privateKeyToAccount(keccak(text=group_uuid)).address)
    # # -- group creation and connection to entity --- begin
    # graph DB operations
    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    g_graph = Group(
        name=request_json['name'],
        uuid=group_uuid,
        address=group_eth_address,
        currency=request_json['currency'],
        approval_required=True
    ).save()
    entity_graph.groups.connect(g_graph)  # connect this group to the entity
    # connect
    # relational DB operations
    s = Session()
    dbw = DBCallsWrapper()
    entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=entity_uuid)
    g_reldb = MoneyVigilGroup(
        name=request_json['name'],
        uuid=group_uuid,
        address=group_eth_address,
        currency=request_json['currency'],
        approval_required=True
    )
    g_reldb.corporate_entity = entity_reldb
    # connect corporate entity representational user to group
    entity_representation_reldb = dbw.query_user_by_(session_obj=s, email=entity_reldb.email)
    g_reldb.users.append(entity_representation_reldb)
    # connect user to group
    employee_reldb = dbw.query_user_by_(session_obj=s, uuid=employee_uuid)
    g_reldb.users.append(employee_reldb)
    s.add(g_reldb)
    # populate group specific role uuids
    for acl_role in ROLES_LIST['group']:
        acl_role_obj = MoneyVigilCorporateEntityRole(
            name=acl_role,
            uuid=str(uuid.uuid4()),
            corporate_entity_id=entity_reldb.id,
            group_uuid=g_reldb.uuid
        )
        s.add(acl_role_obj)
    s.commit()
    # populate group specific role permissions
    group_role_keys = ['GroupOwner', 'GroupApprover', 'GroupDisburser']
    for k in group_role_keys:
        rest_logger.debug(f'Setting default permissions for role {k}')
        entity_specific_role_reldb = dbw.query_role_by_(session_obj=s, name=k, corporate_entity_id=entity_reldb.id, group_uuid=g_reldb.uuid)
        for each_perm in DEFAULT_ROLE_PERMISSIONS[k]:
            perm_reldb = dbw.query_permission_by_(session_obj=s, name=each_perm, corporate_entity_id=entity_reldb.id)
            # find out permission entry
            if DEFAULT_ROLE_PERMISSIONS[k][each_perm]:  # if set as true
                rest_logger.debug('Set: Permission | Role')
                rest_logger.debug(each_perm)
                rest_logger.debug(k)
                perm_reldb.assigned_roles.append(entity_specific_role_reldb)
                s.add(perm_reldb)
            else:
                rest_logger.debug('Not being set: Permission | Role')
                rest_logger.debug(each_perm)
                rest_logger.debug(k)
    return_json.update({'success': True})
    return_json.update({
        'group': dict(
            name=request_json['name'],
            uuid=group_uuid,
            address=group_eth_address,
            currency=request_json['currency'],
            approval_required=True
        )
    })
    # # -- group creation and connection to entity --- end
    # # -- group connection to user representation of entity ---
    for r in entity_graph.user_representation:
        entity_user_repr_graph = r
        break
    # generate ethereum address from a private key keccak(group_uuid+user_uuid)
    entity_group_specific_addr = to_normalized_address(eth_account.account.Account.privateKeyToAccount(
        keccak(text=f'{group_uuid}{entity_user_repr_graph.uuid}')).address)
    g_graph.members.connect(entity_user_repr_graph, {'address': entity_group_specific_addr})
    g_graph.corporate_members.connect(entity_user_repr_graph, {
        'address': entity_group_specific_addr,
        'role': 'Employee'
    })
    # # --- connect employee to group --- begin
    try:
        employee_uuid = request_json['employee']['uuid']
    except KeyError:  # if employee information is not supplied or in bad format, move on
        pass
    employee_graph = User.nodes.first_or_none(uuid=employee_uuid)
    generated_eth_addr = False
    try:
        employee_eth_addr = to_normalized_address(request_json['employee']['eth_address'])
    except:
        employee_eth_addr = to_normalized_address(
            eth_account.Account.privateKeyToAccount(keccak(text=f'{group_uuid}{employee_uuid}')).address)
        generated_eth_addr = True

    if not generated_eth_addr:
        g_graph.corporate_members.connect(employee_graph, {
            'address': employee_eth_addr,
            'role': 'Employee'
        })
    else:
        # npt specifying an address for the group connection as an employee role
        g_graph.corporate_members.connect(employee_graph, {
            'role': 'Employee'
        })
    g_graph.members.connect(employee_graph, {'address': employee_eth_addr})
    # relational DB ops
    employee_reldb = dbw.query_user_by_(session_obj=s, uuid=employee_uuid)
    eth_addr_reldb = s.query(MoneyVigilUserEthereumAddresses).filter_by(address=employee_eth_addr).first()
    # do not add ethereum address to employee role if freshly generated
    if not generated_eth_addr and eth_addr_reldb:  # kinda redundant but sokay
        employee_role_reldb = None
        for role_reldb in employee_reldb.assigned_roles:
            if role_reldb.name == 'Employee':
                employee_role_reldb = role_reldb
                break
        employee_role_reldb.assigned_eth_addresses.append(eth_addr_reldb)
        s.add(employee_role_reldb)
        s.commit()
    else:
        # we gotta create an entry for this address
        # connect with the employee model object
        eth_wallet_name = f'{employee_reldb.name}_wallet{random.choice(range(1, 1000000))}'
        eth_addr_reldb = MoneyVigilUserEthereumAddresses(
            name=eth_wallet_name,
            address=employee_eth_addr,
            user_uuid=employee_uuid
        )
        s.add(eth_addr_reldb)
        s.commit()
        # graph DB ops - check if eth address already has a EthereumAddress node, and connected to the supplied user
        eth_addr_graph = EthereumAddress.nodes.first_or_none(address=employee_eth_addr)
        if not eth_addr_graph:
            eth_addr_graph = EthereumAddress(
                name=eth_wallet_name,
                address=employee_eth_addr
            ).save()
            eth_addr_graph.connected_user.connect(employee_graph)
        else:
            # if present, validate whether it is already connected to a different user. This can not be allowed.
            if employee_graph in eth_addr_graph.connected_user:
                pass  # do nothing, it is already available as a connected user
            elif len(eth_addr_graph.connected_user) >= 1:  # means the address is already associated with a user, and that does not happen to be the currently supplied user
                rest_logger.error('Supplied Ethereum address already connected to a different user | Eth address | Connected User')
                rest_logger.error(employee_eth_addr)
                rest_logger.error(eth_addr_graph.connected_user[0].uuid)
            else:
                eth_addr_graph.connected_user.connect(employee_graph)
    # create a vanilla group relationship connection
    employee_reldb.groups.append(g_reldb)
    s.add(employee_reldb)
    s.commit()
    return_json.update({
        'employee': {
            'uuid': employee_uuid,
            'address': employee_eth_addr
        }
    })
    # # --- connect employee to group --- end
    Session.remove()
    return jsonify(return_json)


def update_role_permissions(entity_uuid, role_uuid, request_json):
    s = Session()
    dbw = DBCallsWrapper()
    permissions_map = request_json['permissionsMap']
    entity_reldb = dbw.query_entity_by_(session_obj=s, uuid=entity_uuid)
    role_reldb = dbw.query_role_by_(session_obj=s, uuid=role_uuid)
    to_be_removed_perms = list()
    to_be_added_perms = list()
    for a in permissions_map:
        perm_name = a
        status = permissions_map[a]
        perm_reldb = dbw.query_permission_by_(session_obj=s, name=perm_name, corporate_entity_id=entity_reldb.id)
        # check if action is already assigned to role
        if perm_reldb in role_reldb.assigned_permissions:
            # do something only if it is being set as False
            if not status:
                to_be_removed_perms.append(perm_reldb)
        else:
            # if not present in allowed actions and permission to be set is allowed
            if status:
                to_be_added_perms.append(perm_reldb)
    removed_perms = list()
    added_perms = list()
    for _a in to_be_removed_perms:
        role_reldb.assigned_permissions.remove(_a)
        removed_perms.append(_a.name)

    for _a in to_be_added_perms:
        role_reldb.assigned_permissions.append(_a)
        added_perms.append(_a.name)

    s.add(role_reldb)
    s.commit()
    Session.remove()
    return jsonify({
        'success': True,
        'roleUUID': role_uuid,
        'removedPermissions': removed_perms,
        'addedPermissions': added_perms
    })


def add_group_owners(entity_uuid, group_uuid, request_json):
    """
       :param request.json['group'] - UUID of the corporate expense group
       :param request.json['owners'] : list of owners to be added against the group.
               Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf", "uuid": "234324-345435-34535-345345"}]
       :param request.json['entityUUID'] : UUID of the corporate entity against which these group owners will be added
       :return:

       Request body example:
       {
            "entityUUID": "f59c6572-5f81-4345-9c2c-997e1940ca87",
            "group": "c181704e-caee-4ea5-baf6-824b618090fe",
            "owners": [
                {"eth_address": "0x902abade63a5cb1b503fe389aea5906d18daaf2b", "uuid": "f5b413ac-1d1a-46d5-868d-37a06c98eb1e"}
                ]
        }
       """
    return add_group_role_wrapper(
        role_name='GroupOwner',
        role_list=request_json['owners'],
        entity_uuid=entity_uuid,
        group_uuid=group_uuid
    )


def add_group_approvers(entity_uuid, group_uuid, request_json):
    """
   :param request.json['group'] - UUID of the corporate expense group
   :param request.json['approvers'] : list of approvers to be added against the group.
           Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf", "uuid": "234324-345435-34535-345345"}]
   :param request.json['entityUUID'] : UUID of the corporate entity against which these group owners will be added
   :return:

   Request body example:
   {
        "entityUUID": "f59c6572-5f81-4345-9c2c-997e1940ca87",
        "group": "c181704e-caee-4ea5-baf6-824b618090fe",
        "approvers": [
            {"eth_address": "0x902abade63a5cb1b503fe389aea5906d18daaf2b", "uuid": "f5b413ac-1d1a-46d5-868d-37a06c98eb1e"}
            ]
    }
   """
    return add_group_role_wrapper(
        role_name='GroupApprover',
        role_list=request_json['approvers'],
        entity_uuid=entity_uuid,
        group_uuid=group_uuid
    )


def add_group_disbursers(entity_uuid, group_uuid, request_json):
    """
       :param request.json['group'] - UUID of the corporate expense group
       :param request.json['disbursers'] : list of approvers to be added against the group.
               Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf", "uuid": "234324-345435-34535-345345"}]
       :param request.json['entityUUID'] : UUID of the corporate entity against which these group owners will be added
       :return:

       Request body example:
       {
            "entityUUID": "f59c6572-5f81-4345-9c2c-997e1940ca87",
            "group": "c181704e-caee-4ea5-baf6-824b618090fe",
            "disbursers": [
                {"eth_address": "0x902abade63a5cb1b503fe389aea5906d18daaf2b", "uuid": "f5b413ac-1d1a-46d5-868d-37a06c98eb1e"}
                ]
        }
       """
    return add_group_role_wrapper(
        role_name='GroupDisburser',
        role_list=request_json['disbursers'],
        entity_uuid=entity_uuid,
        group_uuid=group_uuid
    )


def update_userinfo():
    """
    Updates user information in data models according to fields specified in request body.
    Supported fields:
        write-over updates: name, password, email, email_subscription
        append updates: walletAddresses. Example: "walletAddresses": [{ "name": "new_wallet33", "address": "0x4a20608f7821d13dCB61aE130753cD58B597b03b"}]


    Request example: (successful wallet address append, and email update)
    {
        "walletAddresses": [
            {
                "name": "new_wallet89",
                "address": "0x5d6D3f7691f53c8562f40ecBc6b63a01f23370FE"
            }

            ],
        "email": "anomitghosh@gmail.com"
    }
    Response:
    {
        "failed_fields": [],
        "success": true,
        "updated_fields": [
            "email",
            {
                "data": {
                    "address": "0x5d6D3f7691f53c8562f40ecBc6b63a01f23370FE",
                    "name": "new_wallet89"
                },
                "field": "walletAddresses"
            }
        ]
    }

    Request example: (failed user wallet address append - existing wallet address in DB)

    {
        "walletAddresses": [
            {
                "name": "new_wallet42",
                "address": "0x141A344B00BeE68F2d23884D3FB2f6526f463772"
            }

            ],
        "email": "anomitghosh@gmail.com"
    }
    Response:
    {
        "failed_fields": [
            {
                "data": {
                    "address": "0x141A344B00BeE68F2d23884D3FB2f6526f463772",
                    "name": "new_wallet42"
                },
                "field": "walletAddresses",
                "stage": "RelationalDB"
            }
        ],
        "success": false,
        "updated_fields": [
            "email"
        ]
    }
    """
    rest_logger.info(request.json)
    db_sesh = Session()
    user_node = get_auth_creds()
    request_json = request.json
    update_requested_fields = request_json.keys()
    updated_fields = list()
    failed_fields = list()
    linear_fields_l = ['name', 'password', 'email', 'email_subscription']
    linear_update_fields = set(update_requested_fields).intersection(set(linear_fields_l))
    success = True
    for field in linear_update_fields:
        update_value = request_json[field]
        if field == 'password':
            old_password = request_json[field]["oldPassword"]
            new_password = request_json[field]["newPassword"]
            # check old password
            if not bcrypt.checkpw(old_password, current_user.password):
                logging.error("Old password does not match stored value")
                success = False
                failed_fields.append(field)
                continue
            else:
                update_value = bcrypt.hashpw(new_password, bcrypt.gensalt(12))
            # clear out all authtokens
            tokens = redis_master.smembers(name=f'uuid:{current_user.uuid}:authtokens')
            if tokens:
                logged_in_token = request.headers.get('Auth-Token')
                for t in tokens:
                    t = t.decode('utf-8')
                    if t == logged_in_token:
                        continue  # do not invalidate current token
                    redis_master.delete(f'usertoken:{t}:toUUID')
                    rest_logger.info('Invalidated user token')
                    rest_logger.info(t)
        try:
            current_user.__setattr__(field, update_value)
            db_sesh.add(current_user)
            db_sesh.commit()
            if field not in ["email_subscription", "password"]:  # these fields are not present in graph DB user model
                user_node.__setattr__(field, update_value)
                user_node.save()
        except Exception as e:
            logging.error(f"Error updating {field}")
            logging.error(e)
            failed_fields.append(field)
            success = False
        else:
            updated_fields.append(field)
            success = True
    append_fields_l = ['walletAddresses']
    # reset success
    for field in set(update_requested_fields).intersection(set(append_fields_l)):
        success_l = True
        if field == 'walletAddresses':
            for w_a in request_json[field]:
                # verify address against supplied message and signature
                string_data_hashed = defunct_hash_message(w_a['msg'].encode('utf-8'))
                signed_data = w_a['sig']
                recovered_eth_address = Account.recoverHash(message_hash=string_data_hashed, signature=signed_data)
                recovered_eth_address = to_normalized_address(recovered_eth_address)
                if recovered_eth_address != to_normalized_address(w_a['address']):
                    return {'success': False, 'message': 'SigMismatch'}, 403
                # # -- create ethereum address entries --
                # relational DB
                eth_addr_reldb = MoneyVigilUserEthereumAddresses(
                    name=w_a['name'],
                    address=to_normalized_address(w_a['address']),
                    user_uuid=current_user.uuid
                )
                db_sesh.add(eth_addr_reldb)
                try:
                    db_sesh.commit()
                except (sqlalchemy.exc.IntegrityError, pymysql.err.IntegrityError):
                    db_sesh.rollback()
                    rest_logger.error(f'Relational DB: Exception encountered committing ethereum address {w_a["address"]} to user uuid {current_user.uuid}')
                    success = success and False
                    failed_fields.append({'field': field, 'data': w_a, 'stage': 'RelationalDB'})
                    success_l = False
                else:
                    success_l = True
                # find all roles assigned to this user, connect this ethereum address with all of them
                # graph DB
                try:
                    eth_addr_node = EthereumAddress(
                        name=w_a['name'],
                        address=to_normalized_address(w_a['address'])
                    ).save()
                    eth_addr_node.connected_user.connect(get_auth_creds())
                except Exception as e:
                    rest_logger.error(f'Graph DB: Exception encountered committing ethereum address {w_a["address"]} to user uuid {current_user.uuid}')
                    rest_logger.error(e)
                    failed_fields.append({'field': field, 'data': w_a, 'stage': 'GraphDB'})
                    success_l = success_l and False
                else:
                    success_l = success_l and True
                if success_l:
                    updated_fields.append({'field': field, 'data': w_a})
                success = success and success_l
    Session.remove()
    return jsonify({'success': success, 'updated_fields': updated_fields, 'failed_fields': failed_fields})


def assign_employees(db_sesh, emp_role_reldb, entity_uuid, employees_l):
    """
        :param employees_l: Add employees of this entity.
                Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf" | null, "uuid": "234324-345435-34535-345345"}]
        :param entity_uuid : UUID of the corporate entity against which these owners will be added
        :return:

    """
    if len(employees_l) < 1:
        return jsonify({'success': False, 'message': 'One or more employees to be supplied'})

    entity_graph = CorporateEntity.nodes.first_or_none(uuid=entity_uuid)
    if not entity_graph:
        return jsonify({'success': False, 'message': 'EntityDoesNotExist'})
    entity_contract_addr = entity_graph.contract
    entity_name = entity_graph.name
    # connect ownership with the right ethereum address in graph DB
    for employee in employees_l:
        emp_uuid = employee['uuid']
        emp_graph_node = User.nodes.first_or_none(uuid=emp_uuid)
        if not emp_graph_node:
            rest_logger.error('Could not find employee in graph DB. UUID: ')
            rest_logger.error(emp_uuid)
            return {
                'success': False,
                'entity': {
                    'contract': entity_contract_addr,
                    'uuid': entity_uuid,
                    'chain_id': entity_graph.chain_id,
                    'name': entity_name
                },
                'error': 'EntityEmployershipUpdateGraphDB'
            }
        else:
            # do a check whether supplied address is indeed registered against this user UUID
            if employee['eth_address']:
                found = False
                for e in emp_graph_node.ethereum_addresses:
                    if e.address == to_normalized_address(employee['eth_address']):
                        found = True
                        break
                if found:
                    emp_graph_node.connected_entities.connect(entity_graph, {
                        'address': to_normalized_address(employee['eth_address']),
                        'role': 'Employee'
                    })
                else:
                    rest_logger.error(
                        'Could not find ethereum address associated with employee in graph DB | UUID | Eth address ')
                    rest_logger.error(emp_uuid)
                    rest_logger.error(employee['eth_address'])
                    return {
                        'success': False,
                        'entity': {
                            'contract': entity_contract_addr,
                            'uuid': entity_uuid,
                            'chain_id': entity_graph.chain_id,
                            'name': entity_name
                        },
                        'error': 'EntityEmployershipUpdateGraphDB'
                    }
            else:
                emp_graph_node.connected_entities.connect(entity_graph, {
                    'address': 'null',
                    'role': 'Employee'
                })
                # add to relational DB here itself because this would not reach the webhook_listener since no transaction calls will be made
                dbw = DBCallsWrapper()
                emp_reldb = dbw.query_user_by_(session_obj=db_sesh, uuid=emp_uuid)
                emp_role_reldb.assigned_users.append(emp_reldb)
                db_sesh.add(emp_reldb)
                rest_logger.debug(f'Adding employee UUID {emp_uuid} to Employee role against entity {entity_uuid}')
    # once graph connections have been verified and persisted, make a call to ethvigil APIs
    employees_eth_addr_l = list(map(lambda x: to_normalized_address(x['eth_address']),
                                    list(filter(lambda x: x['eth_address'] is not None, employees_l))))
    tx = ev_add_entity_employees(contract_address=entity_contract_addr, employees_list=employees_eth_addr_l)
    if tx:
        return {'success': True, 'txHash': tx}
    else:
        return {'success': False}


def get_auth_creds():
    return User.nodes.first_or_none(uuid=current_user.uuid)


def get_user_uuid_by_email(email_addr):
    u = User.nodes.first_or_none(email=email_addr)
    if u:
        return u.uuid
    else:
        return None


def get_user_node_by_email(email_addr):
    u = User.nodes.first_or_none(email=email_addr)
    return u


def return_user1_is_owed_total(tx, user1_uuid, group_uuid):  # others who owe user1
    q = f"""
        match (u1:User {{uuid: '{user1_uuid}'}})
        match (u2:User)-[r:`OWES_{group_uuid}`]->(u1) return sum(r.amount)
    """
    result = tx.run(q)
    return result.single()[0]


def return_user1_owes_total(tx, user1_uuid, group_uuid):  # whom does user1 owe
    q = f"""
            match (u1:User {{uuid: '{user1_uuid}'}})
            match (u1)-[r:`OWES_{group_uuid}`]->(u2:User) return sum(r.amount)
        """
    result = tx.run(q)
    return result.single()[0]


def expand_messageobject(msgobj):
    """

    :param msgobj:
    :return: A string in tuple form containing the expanded object fields
    """
    action_type = msgobj['actionType']
    group = msgobj['group']
    member = msgobj['member']
    amount = msgobj['amount']
    bill = msgobj['bill']
    # metadata_hash = msgobj['metadataHash']
    timestamp = msgobj['timestamp']
    return json.dumps([action_type, group, member, amount, bill, timestamp])


def expensemap_to_splitmap(expense_map, group_uuid, total_amount):
    g = Group.nodes.first_or_none(uuid=group_uuid)
    if not g:
        return jsonify({'success': False, 'message': 'Invalid Group UUID'})
    simplified_balance_mapping = dict()
    mapped_uuids = dict()  # map user uuids to group specific ethereum addresses
    final_settlement = dict()
    for user_uuid in expense_map:
        user_node = User.nodes.first_or_none(uuid=user_uuid)
        if not user_node:
            return jsonify({'success': False, 'message': f'Invalid member UUID {user_uuid}'})
        # find group specific address
        rel = g.members.relationship(user_node)
        user_grp_addr = rel.address
        # print(f'Group specific address for {user_uuid} : {user_grp_addr}')
        mapped_uuids[user_uuid] = rel.address
        # simplified_balance_mapping[user_grp_addr] = expense_map[user_uuid]['paid'] - expense_map[user_uuid]['owes']
        rest_logger.debug('Simplified balance mapping')
        rest_logger.debug(simplified_balance_mapping)
        simplified_balance_mapping[user_grp_addr] = expense_map[user_uuid]['owes'] - expense_map[user_uuid]['paid']
    # print("Simplified balance mapping (lending model, not owed model): ", simplified_balance_mapping)
    rest_logger.info("Simplified balance mapping (owed model, not lending model): ")
    rest_logger.info(simplified_balance_mapping)
    rest_logger.info("Mapped UUIDs: ")
    rest_logger.info(mapped_uuids)
    # find out if one person has paid the entire bill. In that case, do not simplify further
    filtered_payer = list(filter(lambda x: expense_map[x]["paid"] == total_amount, expense_map))
    if len(filtered_payer) == 1:
        rest_logger.info("-----Only one payer for the entire bill!-----")
        # found one person who paid it all
        # create a final settlement where everyone else pays their owed amount to filtered_payer
        filtered_payer = filtered_payer[0]
        filtered_payer = mapped_uuids[filtered_payer]  # convert to group specific ethereum address for this user
        final_settlement[filtered_payer] = dict()
        for each in simplified_balance_mapping:
            if each != filtered_payer:
                final_settlement[filtered_payer].update({each: simplified_balance_mapping[each]})
    else:
        while True:
            if all(val == 0 for val in simplified_balance_mapping.values()):
                break
            negative_key = random.choice(
                list(
                    filter(lambda x: simplified_balance_mapping[x] < 0, simplified_balance_mapping)))  # pick a creditor
            positive_key = random.choice(
                list(filter(lambda x: simplified_balance_mapping[x] > 0, simplified_balance_mapping)))  # pick a debitor
            # min of(some owed value for a fat cat, some owes value for a poor boy)
            diff_val = min(-1 * simplified_balance_mapping[negative_key], simplified_balance_mapping[positive_key])
            if negative_key in final_settlement:
                final_settlement[negative_key].update({positive_key: diff_val})
            else:
                final_settlement[negative_key] = {positive_key: diff_val}
            simplified_balance_mapping[negative_key] += diff_val
            simplified_balance_mapping[positive_key] -= diff_val
            # print('Overall balance mapping: ', simplified_balance_mapping)
    rest_logger.info('Final settlement mapping: ')
    rest_logger.info(final_settlement)
    return final_settlement


def reverse_splitmap(prev_splitmap):
    reversed_splitmap = dict()
    for creditor in prev_splitmap:
        for debitor in prev_splitmap[creditor]:
            entry = {creditor: prev_splitmap[creditor][debitor]}
            if debitor in reversed_splitmap:
                reversed_splitmap[debitor].update(entry)
            else:
                reversed_splitmap[debitor] = entry
    return reversed_splitmap


def simplify_map(input_map, simplified_map):
    # mutates simplified_map
    for creditor in input_map:
        for debitor in input_map[creditor].keys():
            if creditor in simplified_map:
                simplified_map[creditor] -= input_map[creditor][debitor]
            else:
                simplified_map[creditor] = -1 * input_map[creditor][debitor]
            if debitor in simplified_map:
                simplified_map[debitor] += input_map[creditor][debitor]
            else:
                simplified_map[debitor] = input_map[creditor][debitor]


def merge_splitmaps(map1, map2):
    # Usage:
    # map1 - current bill split map
    # map2 - previous bill reversed split map
    final_settlement = dict()
    simplified_map = dict()  # owed model, not lending model i.e. creditors < 0, debitors > 0
    # simplify debts across both maps
    # simplified_map gets mutated
    simplify_map(map1, simplified_map)
    rest_logger.debug('Simplified map for current bill')
    rest_logger.debug(simplified_map)
    simplify_map(map2, simplified_map)
    rest_logger.debug('Simplified map for reversal of previous bill')
    rest_logger.debug(simplified_map)
    # do an initial check if the split maps cancel out
    # in that case, recreate the split map with the same creditor debitor mappings and amount = 0.00
    if all(val == 0 for val in simplified_map.values()):
        for creditor in map1.keys():
            for debitor in map1[creditor].keys():
                update_val = {debitor: 0}
                if creditor not in final_settlement.keys():
                    final_settlement[creditor] = update_val
                else:
                    final_settlement[creditor].update(update_val)
        return final_settlement
    while True:
        if all(val == 0 for val in simplified_map.values()):
            break
        negative_key = random.choice(
            list(
                filter(lambda x: simplified_map[x] < 0, simplified_map)))  # pick a creditor
        positive_key = random.choice(
            list(filter(lambda x: simplified_map[x] > 0, simplified_map)))  # pick a debitor
        # min of(some owed value for a fat cat, some owes value for a poor boy)
        diff_val = min(-1 * simplified_map[negative_key], simplified_map[positive_key])
        if negative_key in final_settlement:
            final_settlement[negative_key].update({positive_key: diff_val})
        else:
            final_settlement[negative_key] = {positive_key: diff_val}
        simplified_map[negative_key] += diff_val
        simplified_map[positive_key] -= diff_val
    return final_settlement


def get_simplified_debt_graph(group_uuid):
    """
    get the precomputed debt/split graph structure for a specific group
    :param group_uuid: group UUID
    :return: None in case the cache is not filled/computed
    """
    simplified_splitmap_cachekey = SIMPLIFIED_GROUPDEBT_CACHE_KEY.format(settings['contractAddress'], group_uuid)
    rest_logger.info('Attempting to get simplified debt/split graph for Group at key ')
    rest_logger.info(simplified_splitmap_cachekey)
    simplified_splitmap = redis_master.get(name=simplified_splitmap_cachekey)
    return simplified_splitmap


def get_connected_groups_and_users(user_node, flat=False):
    connections = list()
    flat_connections = list()
    for g in user_node.groups:
        if not flat:
            g_members = []
            for m in g.members:
                g_members.append({'uuid': m.uuid, 'name': m.name, 'email': m.email})
            connections.append({
                'group': {'uuid': g.uuid, 'name': g.name, 'currency': g.currency},
                'members': g_members
            }
            )
        else:
            for m in g.members:
                flat_connections.append({'uuid': m.uuid, 'name': m.name, 'email': m.email})
    if not flat:
        return connections
    else:
        return flat_connections


def return_user1_is_owed(tx, user1_uuid, group_uuid):  # others who owe user1
    q = f"""
        match (u1:User {{uuid: '{user1_uuid}'}})
        match (u2:User)-[r:`OWES_{group_uuid}`]->(u1) return r, u2
    """
    result = tx.run(q)
    return result


def return_user1_owes(tx, user1_uuid, group_uuid):  # whom does user1 owe
    q = f"""
            match (u1:User {{uuid: '{user1_uuid}'}})
            match (u1)-[r:`OWES_{group_uuid}`]->(u2:User) return r, u2
        """
    result = tx.run(q)
    return result

def get_user_by_email(email):
    db_sesh = Session()
    dbcall = DBCallsWrapper()
    request_json = request.json
    try:
        u = get_user_node_by_email(email)
    except neomodel.exceptions.DeflateError:
        return jsonify({'success': False})
    else:
        if u:
            # check relational DB
            u_db = dbcall.query_user_by_(session_obj=db_sesh, email=email)
            Session.remove()
            return jsonify({
                'success': True,
                'user': {
                    'uuid': u.uuid,
                    'name': u.name,
                    'signedUp': u_db.activated if u_db else False
                }
            })
        else:
            return jsonify({'success': False})