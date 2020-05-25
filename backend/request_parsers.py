from flask_restx import reqparse, inputs

_get_user_info_parser = reqparse.RequestParser()
_get_user_info_parser.add_argument('email')

_post_user_parser = reqparse.RequestParser()
_post_user_parser.add_argument('email', location='json', required=True, help='supply email')
_post_user_parser.add_argument('name', location='json', required=True, help='supply name')

"""
    :param 'name' : name of entity to be registered
    :param 'email' : email of entity to be registered
    :param 'deploy' : boolean. If true, look for necessary deployment params: uuid/uuidhash, chainid
    :param 'walletAddress' : the eth address of the user firing the create request through which the first globalowner will be added
    :param 'uuid' : OPTIONAL. used to initialize the contract with a pre-supplied UUID - identifies the corporate entity
    :param 'chainId' :
    :param 'contractAddress' : OPTIONAL. already deployed contract
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
_post_entity_parser = reqparse.RequestParser()
_post_entity_parser.add_argument('name', required=True, help='supply corporate entity name', location='json')
_post_entity_parser.add_argument('email', required=True, help='supply corporate entity email', location='json')
_post_entity_parser.add_argument('deploy', type=inputs.boolean, required=True, help='supply corporate entity email', location='json')
_post_entity_parser.add_argument('uuid', required=False, help='supply corporate entity UUID if already generated', location='json')
_post_entity_parser.add_argument('chainId', type=int, required=False, help='chain ID on which contract will be deployed', location='json')
_post_entity_parser.add_argument('walletAddress', required=True, help='the eth address of the user firing the create request through which the first globalowner will be added', location='json')


_post_entity_employee_parser = reqparse.RequestParser()
_post_entity_employee_parser.add_argument('employees', type=list, required=True, location='json', help='''
Email addresses provided. [{"email": "", "name": "Anomit"},...]
           --OR--
           UUID's provided with optional ethereum addresses to connect to the Employee Role against the Corporate Entity
           [{"uuid": "34253478-45658-x56t", "eth_address": null}]
''')

_post_entity_approvers_parser = reqparse.RequestParser()
_post_entity_approvers_parser.add_argument('approvers', required=True, type=list, location='json', help='''
Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf", "uuid": "234324-345435-34535-345345"}]
''')

_post_entity_disbursers_parser = reqparse.RequestParser()
_post_entity_disbursers_parser.add_argument('disbursers', required=True, type=list, location='json', help='''
Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf", "uuid": "234324-345435-34535-345345"}]
''')

_post_entity_owners_parser = reqparse.RequestParser()
_post_entity_owners_parser.add_argument('owners', required=True, type=list, location='json', help='''
Ethereum addresses and UUIDs provided. [{"eth_address": "0xdfdfdf", "uuid": "234324-345435-34535-345345"}]
''')


_post_entity_group_parser = reqparse.RequestParser()
_post_entity_group_parser.add_argument('group', required=False, location='json', help='<optional> pre-supplied groupUUID for group to be created')
_post_entity_group_parser.add_argument('name', required=True, location='json', help='Group name')
_post_entity_group_parser.add_argument('currency', required=True, location='json', help='Group currency')
_post_entity_group_parser.add_argument('employee', required=True, type=dict,location='json', help='''
<optional> employee to be added {'uuid': , 'eth_address': <optional>}
If eth_addr is not supplied, the hash of group_uuid+member_uuid will be used as private key to generate an address
''')

_put_entity_role_permissions = reqparse.RequestParser()
_put_entity_role_permissions.add_argument('permissionsMap', type='dict', required=True, help='mapping of permissions to boolean, to be set or unset on the role UUID',
                                          default='''
                                          {
        "permissionsMap": {
            "CAN_APPROVE_BILL": false,
            "CAN_ADD_GROUP": true,
            "CAN_ADD_APPROVER": true,
            "CAN_ADD_DISBURSER": true
        }
    }
                                          ''')


_post_group_members = reqparse.RequestParser()
_post_group_members.add_argument('member', required=True, location='json', help='Another user UUID to be added against the logged in user to a group')
_post_group_members.add_argument('name', required=False, location='json', help='<optional> if supplied and new group is to be created, this is used as group name')
_post_group_members.add_argument('currency', required=True, location='json', help='group currency')
_post_group_members.add_argument('approval_required', type=inputs.boolean,required=True, location='json', help='group meant for corporate expense recording and reimbursements')


_post_new_bill = reqparse.RequestParser()
_post_new_bill.add_argument('expenseMap', required=True, type=dict, location='json', help='mappings `{uuid: {paid: , owes: }}`')
_post_new_bill.add_argument('group', required=True, location='json', help='Group UUID')
_post_new_bill.add_argument('description', required=True, location='json', help='Bill description')
_post_new_bill.add_argument('date', required=True, location='json', help='Bill date')
_post_new_bill.add_argument('totalAmount', required=True, location='json', help='Bill totalAmount', type=int)
_post_new_bill.add_argument('fileHash', required=True, location='json', help='Uploaded file hash')
_post_new_bill.add_argument('reimbursement', required=False, type=inputs.boolean, location='json', help='A reimbursement bill or not')


_put_update_bill = reqparse.RequestParser()
_put_update_bill.add_argument('expenseMap', required=True, type=dict, location='json', help=' mappings `{uuid: {paid: , owes: }}`')
_put_update_bill.add_argument('group', required=True, location='json', help='Group UUID')
_put_update_bill.add_argument('description', required=True, location='json', help='Bill description')
_put_update_bill.add_argument('date', required=True, location='json', help='Bill date')
_put_update_bill.add_argument('totalAmount', required=True, location='json', help='Bill totalAmount', type=int)
_put_update_bill.add_argument('fileHash', required=True, location='json', help='Uploaded file hash')

"""
    :param request.json['prevBillUUID'] -- list of mappings {uuid: {paid: , owes: }}
    :param request.json['date'] -- date of reversal
    :return:
        {
            'success': [True | False],
            'txHash': 0x160bits,
            'bill': {
                'uuid': ,
                'uuidHash': ,
                'prevBill': {'uuid': prev_bill_uuid, 'uuidHash': prev_bill_uuid_hash},
                'metadata': ,
                'expenseMap': {empty dict},
                'state': ['pending' | 'created' | 'submitted']
            }
        }
    """
_delete_bill = reqparse.RequestParser()
_delete_bill.add_argument('date', required=True, location='json', help='date of reversal')

_post_bill_action = reqparse.RequestParser()
_post_bill_action.add_argument('action', required=True, location='json', help='`approval` or `disbursal`')
_post_bill_action.add_argument('message', required=True, type=dict, location='json', help='The JSON message object representing EIP-712 signing')
_post_bill_action.add_argument('signature', required=True, location='json', help='The 32 bytes blob representing EIP-712 signed message object')
_post_bill_action.add_argument('signer', required=True, location='json', help='The etherum address signing this message object')

PARSERS = {
    'user': {
        'get': _get_user_info_parser,
        'post': _post_user_parser
    },
    'corporate_entity': {
        'post': _post_entity_parser,

    },
    'corporate_entity_user': {
        'post': _post_entity_employee_parser,
        'put': _post_entity_employee_parser
    },

    'corporate_entity_owner': {
        'post': _post_entity_owners_parser
    },

    'corporate_entity_disburser': {
        'post': _post_entity_disbursers_parser
    },

    'corporate_entity_approver': {
        'post':  _post_entity_approvers_parser
    },

    'corporate_entity_role_permissions': {
        'put': _put_entity_role_permissions
    },

    'corporate_entity_group': {
        'post': _post_entity_group_parser
    }
}
