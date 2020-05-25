from neomodel import (config, StructuredNode, StructuredRel, StringProperty, IntegerProperty, BooleanProperty,
                      DateTimeProperty, RelationshipTo, RelationshipFrom, JSONProperty, cardinality)
from uuid import uuid4
from dynaconf import settings
from eth_utils import keccak

config.DATABASE_URL = settings['NEO4J']['URL']


class MemberOf(StructuredRel):
    address = StringProperty(required=True)


class BillOf(StructuredRel):
    timestamp = DateTimeProperty()
    billUUIDHash = StringProperty()


class EntityRelation(StructuredRel):  # model relation to entities like global owner, global approver etc
    address = StringProperty(required=False)
    role = StringProperty(required=True)


class CorporateGroupRelation(StructuredRel):  # model group relations like Approver etc. other than just MEMBER_OF
    address = StringProperty(required=False)
    role = StringProperty(required=True)


class User(StructuredNode):
    uuid = StringProperty(unique_index=True, default=uuid4)
    name = StringProperty()
    email = StringProperty(required=True, unique_index=True)
    groups = RelationshipTo('Group', 'MEMBER_OF', model=MemberOf)
    connected_entities = RelationshipTo('CorporateEntity', 'ENTITY_RELATION', model=EntityRelation)
    connected_corporate_groups = RelationshipTo('Group', 'CORPORATE_GROUP_RELATION', model=CorporateGroupRelation)
    ethereum_addresses = RelationshipTo('EthereumAddress', 'ETHEREUM_ADDRESSES')


class EthereumAddress(StructuredNode):
    address = StringProperty(required=True, unique_index=True)
    name = StringProperty(required=True)
    connected_user = RelationshipFrom('User', 'ETHEREUM_ADDRESSES', cardinality=cardinality.One)


class Group(StructuredNode):
    uuid = StringProperty(unique_index=True, default=uuid4)
    address = StringProperty()
    name = StringProperty()
    currency = StringProperty(required=True)
    approval_required = BooleanProperty()
    members = RelationshipFrom('User', 'MEMBER_OF', model=MemberOf)
    corporate_entity = RelationshipTo('CorporateEntity', 'MEMBER_OF_CORPORATE_ENTITY', cardinality=cardinality.One)  # can belong to only one corporate entity
    corporate_members = RelationshipFrom('User', 'CORPORATE_GROUP_RELATION', model=CorporateGroupRelation)
    bills = RelationshipFrom('Bill', 'BILL_OF', model=BillOf)


class Bill(StructuredNode):
    STATES = {
        '-1': 'created',
        '0': 'mined',
        '1': 'pendingSubmission',
        '2': 'submitted',
        '3': 'pendingApproval',
        '4': 'approved',
        '5': 'pendingDisbursal',
        '6': 'disbursed',
        '7': 'requiresApproval',
        '8': 'requiresDisbursal'
    }
    uuid = StringProperty(unique_index=True)
    uuidhash = StringProperty(unique_index=True)
    metadata = JSONProperty(required=True)
    expenseMap = JSONProperty(required=True)
    createdBy = StringProperty(required=True)
    # -1 for created, 0 for mined, 1 for pending approval, 2 for all splits submitted fully
    state = StringProperty(required=True, choices=STATES)
    group = RelationshipTo('Group', 'BILL_OF', model=BillOf, cardinality=cardinality.One)  # can belong to only one grp
    parentBill = RelationshipTo('Bill', 'CHILD_OF', cardinality=cardinality.One)  # can have only one parent bill
    childBills = RelationshipFrom('Bill', 'CHILD_OF')


class CorporateEntity(StructuredNode):
    uuid = StringProperty(unique_index=True)
    uuidhash = StringProperty(unique_index=True)
    name = StringProperty(required=True)
    email = StringProperty(required=True)
    contract = StringProperty()  # ACL contract
    treasuryContract = StringProperty()
    chain_id = IntegerProperty()
    groups = RelationshipFrom('Group', 'MEMBER_OF_CORPORATE_ENTITY')  # groups attached to this corporate entity
    # owners = RelationshipFrom('User', 'OWNER_OF_CORPORATE_ENTITY', model=OwnerOfEntity)
    connected_users = RelationshipFrom('User', 'ENTITY_RELATION', model=EntityRelation)
    user_representation = RelationshipTo('User', 'ENTITY_USER_REPRESENTATION', cardinality=cardinality.One)
