from dynaconf import settings
import requests
import logging
import json
from eth_account.account import Account
from eth_account.messages import defunct_hash_message
from eth_utils import keccak
import sys
import coloredlogs

formatter = logging.Formatter(u"%(levelname)-8s %(name)-4s %(asctime)s,%(msecs)d %(module)s-%(funcName)s: %(message)s")

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.setFormatter(formatter)

evapi_logger = logging.getLogger(__name__)
evapi_logger.setLevel(logging.DEBUG)
evapi_logger.addHandler(stdout_handler)
evapi_logger.addHandler(stderr_handler)

coloredlogs.install('DEBUG', logger=evapi_logger)

def ev_add_entity_global_owners(contract_address, owners_list):
    """
    This adds new 'global' owners to the ALCDispatcher contract
    :param contract_address: the instance of the contract
    :param owners_list: list of owners
    :return: True if tx goes through, else false
    """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addGlobalOwners'
    method_args = {'new_owners': json.dumps(owners_list)}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding global owners on contract {contract_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False


def ev_add_entity_employees(contract_address, employees_list):
    """
    This adds new 'global' owners to the ALCDispatcher contract
    :param contract_address: the instance of the contract
    :param employees_list: list of owners
    :return: True if tx goes through, else false
    """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addEmployees'
    method_args = {'new_employees': json.dumps(employees_list)}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding entity employees on contract {contract_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False
    
    
def deploy_acl_contract(entity_uuid, chain_id):
    msg = "Trying to deploy"
    message_hash = defunct_hash_message(text=msg)
    sig_msg = Account.signHash(message_hash, settings['privatekey'])
    with open('./contracts/ACLDispatcher.sol', 'r') as f:
        contract_code = f.read()
    constructor_inputs = []
    company_uuid_hash = '0x' + keccak(text=entity_uuid).hex()
    constructor_inputs.append(company_uuid_hash)
    constructor_inputs.append(chain_id)
    deploy_params = {
        'msg': msg,
        'sig': sig_msg.signature.hex(),
        'name': 'ACLDispatchHub',
        'inputs': constructor_inputs,
        'code': contract_code
    }
    print('Deploying with constructor arguments: ')
    print(constructor_inputs)
    # API call to deploy
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    r = requests.post(settings['REST_API_ENDPOINT'] + '/deploy', json=deploy_params, headers=headers)
    rj = r.json()
    print('Deployed contract results')
    print(rj)
    if r.status_code == requests.codes.ok:
        return rj['data']['contract'], rj['data']['txhash']
    else:
        return None


def ev_add_webhook(contract_address, url):
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    msg = 'dummystr'
    message_hash = defunct_hash_message(text=msg)
    sig_msg = Account.signHash(message_hash, settings['privatekey'])
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": settings['ETHVIGIL_API_KEY'],
        "type": "web",
        "contract": contract_address,
        "web": url
    }
    # register the hook to get a hook ID on ethvigil
    r = requests.post(url=f'{settings["REST_API_ENDPOINT"]}/hooks/add', json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if not r['success']:
            evapi_logger.error('Could not register webhook with Ethvigil API')
            return None
        else:
            evapi_logger.debug('Succeeded in registering webhook with Ethvigil API. Hook ID: ')
            hook_id = r['data']['id']
            evapi_logger.debug(hook_id)
    else:
        evapi_logger.error('Could not register webhook with Ethvigil API')

    # enable hook on all events
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": settings['ETHVIGIL_API_KEY'],
        "type": "web",
        "contract": contract_address,
        "web": url,
        "id": hook_id,
        "events": ["*"]
    }
    r = requests.post(url=f'{settings["REST_API_ENDPOINT"]}/hooks/updateEvents', json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if r['success']:
            evapi_logger.debug('Succeded in adding hook to monitor all events')
        else:
            evapi_logger.error('Failed to add hook monitoring on all events...')
            return None
    else:
        evapi_logger.error('Failed to add hook monitoring on all events...')
        return


def ev_add_entity_global_approvers(contract_address, approvers_list):
    """
    This adds new 'global' approvers to the ALCDispatcher contract
    :param contract_address: the instance of the contract
    :param approvers_list: list of owners
    :return: True if tx goes through, else false
    """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addGlobalApprovers'
    method_args = {'new_approvers': json.dumps(approvers_list)}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding global approvers on contract {contract_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False


def ev_add_entity_global_disbursers(contract_address, disbursers_list):
    """
    This adds new 'global' disbursers to the ALCDispatcher contract
    :param contract_address: the instance of the contract
    :param disbursers_list: list of owners
    :return: True if tx goes through, else false
    """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addGlobalDisbursers'
    method_args = {'new_disbursers': json.dumps(disbursers_list)}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding global disbursers on contract {contract_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False


def ev_add_entity_group_owners(contract_address, group_address, users_list):
    """
        This adds new owners to a group connected to a corporate entity
        :param contract_address: the instance of the contract
        :param users_list: list of owners
        :return: True if tx goes through, else false
        """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addGroupOwners'
    method_args = {'new_owners': json.dumps(users_list), 'group': group_address}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding group owners on contract {contract_address}: group {group_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False


def ev_add_entity_group_approvers(contract_address, group_address, users_list):
    """
        This adds new approvers to a group connected to a corporate entity
        :param contract_address: the instance of the contract
        :param users_list: list of owners
        :return: True if tx goes through, else false
        """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addGroupApprovers'
    method_args = {'new_approvers': json.dumps(users_list), 'group': group_address}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding group approvers on contract {contract_address}: group: {group_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False


def ev_add_entity_group_disbursers(contract_address, group_address, users_list):
    """
    This adds new disbursers to a group connected to a corporate entity
    :param contract_address: the instance of the contract
    :param users_list: list of owners
    :return: True if tx goes through, else false
    """
    api_key = settings['ETHVIGIL_API_KEY']
    method_name = 'addGroupDisbursers'
    method_args = {'new_disbursers': json.dumps(users_list), 'group': group_address}
    method_endpoint = settings['REST_API_ENDPOINT'] + f'/contract/{contract_address}/{method_name}'
    evapi_logger.debug(f'Adding group disbursers on contract {contract_address}: group: {group_address}: {method_args}')
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    r = requests.post(url=method_endpoint, json=method_args, headers=headers)
    evapi_logger.debug(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data'][0]['txHash']
    else:
        return False


def ev_add_group_member(group_address, user_address):
    """
    Makes call to the MoneyVigil contract via EthVigil API to add members to a group
    :param group_address:
    :param user_address:
    :return:
    """
    contract_address = settings['contractAddress']
    api_key = settings['ETHVIGIL_API_KEY']
    headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'X-API-KEY': api_key}
    method_api_endpoint = f'{settings["REST_API_ENDPOINT"]}/contract/{contract_address}/addGroupMember'
    method_args = {
        'group': group_address,
        'member': user_address
    }
    evapi_logger.info('Sending method args to addGroupMember')
    evapi_logger.info(method_args)
    r = requests.post(url=method_api_endpoint, json=method_args, headers=headers)
    evapi_logger.info(r.text)
    rj = r.json()
    if rj['success']:
        txhash = rj['data'][0]['txHash']
        evapi_logger.info('New member added to Group. User eth address | TxHash ')
        evapi_logger.info(user_address)
        evapi_logger.info(txhash)
    else:
        evapi_logger.error('Failed to add User to Group | User eth address | Group eth address')
        evapi_logger.error(user_address)
        evapi_logger.error(group_address)
    return rj