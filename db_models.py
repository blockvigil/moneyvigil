from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, Table
from sqlalchemy.orm import relationship

Base = declarative_base()


# connects users and groups in a many-to-many relationship
UserGroupAssociationTable = Table('user_group_assoc', Base.metadata,
    Column('user_uuid', String(255), ForeignKey('user.uuid')),
    Column('group_uuid', String(255), ForeignKey('groups.uuid'))
)

UserEventsAssociationTable = Table('user_events_assoc', Base.metadata,
    Column('user_uuid', String(255), ForeignKey('user.uuid')),
    Column('ethvigil_event_id', Integer, ForeignKey('events.ethvigil_event_id'))
)

OwnerCorporateEntityTable = Table('user_entity_assoc', Base.metadata,
                                  Column('user_uuid', String(255), ForeignKey('user.uuid')),
                                  Column('corporate_entity', String(255), ForeignKey('corporate_entities.uuid'))
                                  )  # maintain a mapping of users who own entity(s)

EthAddressOwnerCorporateEntityTable = Table('eth_addr_entity_assoc', Base.metadata,
                                  Column('eth_address', String(255), ForeignKey('user_ethereum_addresses.address')),
                                  Column('corporate_entity', String(255), ForeignKey('corporate_entities.uuid'))
                                  )  # maintain a mapping of users who own entity(s)

CorporateEntityRolesTable = Table('entity_roles_assoc', Base.metadata,
                                  Column('corporate_entity', String(255), ForeignKey('corporate_entities.uuid')),
                                  Column('role_uuid', String(255), ForeignKey('user.uuid'))
                                  )  # maintain a mapping of role ids assigned to a corporate entity

GroupRolesTable = Table('group_roles_assoc', Base.metadata,
                        Column('group_uuid', String(255), ForeignKey('groups.uuid')),
                        Column('role_uuid', String(255), ForeignKey('corporate_entities_roles.uuid')))


UserCorporateRolesAssocTab = Table('user_roles_assoc', Base.metadata,
                                   Column('user_uuid', String(255), ForeignKey('user.uuid')),
                                   Column('role_uuid', String(255), ForeignKey('corporate_entities_roles.uuid'))
                                   )  # maintain a mapping of role uuid's assigned to a certain user

EthAddressRoleAssocTable = Table('eth_addr_role_assoc', Base.metadata,
                                 Column('eth_address', String(255), ForeignKey('user_ethereum_addresses.address')),
                                 Column('role_uuid', String(255), ForeignKey('corporate_entities_roles.uuid'))
                                  )  # maintain a mapping of ethereum addresses assigned to corporate entity roles


RolesToPermissionsAssocTable = Table('roles_permissions_assoc', Base.metadata,
                                 Column('role_uuid', String(255), ForeignKey('corporate_entities_roles.uuid')),
                                 Column('permissions_id', Integer, ForeignKey('corporate_entities_permissions.id'))
                                 )


class MoneyVigilUser(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(255), unique=True, nullable=False)
    name = Column(String(255))
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    activated = Column(Integer, nullable=False, default=0)
    activation_token = Column(String(255), nullable=False)
    activated_at = Column(Integer, default=0, nullable=False)
    activation_expiry = Column(Integer, default=0, nullable=False)
    remaining_invites = Column(Integer, nullable=False, default=0)
    email_subscription = Column(Boolean, nullable=False, default=1)
    rewards = relationship("MoneyVigilReward", back_populates="attached_user")
    bills = relationship("MoneyVigilBill", back_populates="attached_user")
    groups = relationship("MoneyVigilGroup", secondary=UserGroupAssociationTable, backref="users")
    activities = relationship("MoneyVigilActivity", backref="user")

    def get_id(self):
        return self.id

    def is_active(self):
        return True

    def is_annonymous(self):
        return False

    def is_authenticated(self):
        return True


class MoneyVigilInvites(Base):
    __tablename__ = 'invites'
    id = Column(Integer, primary_key=True)
    code = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    email_sent = Column(Boolean, nullable=True, default=0)
    reusable = Column(Boolean, nullable=False)
    reuseCount = Column(Integer, nullable=True)
    expiry = Column(Integer, nullable=True)
    used_at = Column(Integer, nullable=True)
    invited_by = Column(String(255), ForeignKey('user.uuid'))


class MoneyVigilUnsubscribeTokens(Base):
    __tablename__ = 'unsubscribe_tokens'
    id = Column(Integer, primary_key=True)
    code = Column(String(255), unique=True, nullable=False)
    user = Column(String(255), ForeignKey('user.uuid'))
    attached_user = relationship('MoneyVigilUser', backref='unsubscribe_token')


class MoneyVigilReward(Base):
    __tablename__ = 'rewards'
    id = Column(Integer, primary_key=True)
    points = Column(Integer, nullable=True)
    associated_metadata = Column(Text)
    to_user_uuid = Column(String(255), ForeignKey('user.uuid'))
    attached_user = relationship("MoneyVigilUser")
    activity_id = Column(Integer, ForeignKey('activities.id'))


class MoneyVigilBill(Base):
    __tablename__ = 'bills'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(255), unique=True)
    uuid_hash = Column(String(255), unique=True)
    prev_uuid_hash = Column(String(255), ForeignKey('bills.uuid_hash'), nullable=True)
    state = Column(String(2))
    expense_map = Column(Text)
    associated_metadata = Column(Text)  # keyword collision, renaming metadata to associated_metadata
    initial_txhash = Column(String(255), ForeignKey('transactions.tx_hash'), nullable=True)
    final_txhash = Column(String(255), ForeignKey('transactions.tx_hash'), nullable=True)
    created_by = Column(String(255), ForeignKey('user.uuid'))
    bill_of = Column(String(255), ForeignKey('groups.uuid'))
    attached_user = relationship("MoneyVigilUser")
    attached_group = relationship("MoneyVigilGroup")
    prev_bill = relationship("MoneyVigilBill", backref='child_bills', remote_side=[uuid_hash])
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


class MoneyVigilGroup(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(255), unique=True)
    name = Column(String(255))
    currency = Column(String(255))
    address = Column(String(255))
    approval_required = Column(Boolean, default=0)
    corporate_entity_id = Column(Integer, ForeignKey('corporate_entities.id'), nullable=True)
    bills = relationship("MoneyVigilBill", back_populates="attached_group")


class MoneyVigilEvent(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    ethvigil_event_id = Column(Integer, unique=True)
    event_name = Column(String(255), nullable=True)
    tx_hash = Column(String(255), ForeignKey('transactions.tx_hash'))
    users = relationship("MoneyVigilUser", secondary=UserEventsAssociationTable, backref="events")
    activities = relationship('MoneyVigilActivity')


class MoneyVigilTransaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True)
    tx_hash = Column(String(255), unique=True)
    block_num = Column(Integer, nullable=True)
    transaction_index = Column(Integer, nullable=True)
    to_address = Column(String(255), nullable=True)
    from_address = Column(String(255), nullable=True)
    events = relationship("MoneyVigilEvent", backref="transaction")


class MoneyVigilActivity(Base):
    __tablename__ = 'activities'
    id = Column(Integer, primary_key=True)
    associated_event_id = Column(Integer, ForeignKey('events.ethvigil_event_id'))
    associated_metadata = Column(Text, nullable=True)
    rewards = relationship('MoneyVigilReward', backref='activity')
    for_user_uuid = Column(String(255), ForeignKey('user.uuid'))


class MoneyVigilCorporateEntity(Base):
    __tablename__ = 'corporate_entities'
    id = Column(Integer, primary_key=True)
    uuid = Column(String(255), unique=True, nullable=False)
    uuidhash = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    owners = relationship('MoneyVigilUser', secondary=OwnerCorporateEntityTable, backref='owned_entities')
    eth_addr_owners = relationship('MoneyVigilUserEthereumAddresses', secondary=EthAddressOwnerCorporateEntityTable, backref='owned_entities')
    contract = Column(String(255))  # ACL contract
    treasury_contract = Column(String(255))
    chain_id = Column(Integer)
    groups = relationship('MoneyVigilGroup', backref='corporate_entity')
    deployed = Column(Boolean)


class MoneyVigilCorporateEntityRole(Base):
    __tablename__ = 'corporate_entities_roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    uuid = Column(String(255), unique=True)
    corporate_entity_id = Column(Integer, ForeignKey('corporate_entities.id'), nullable=False)
    group_uuid = Column(String(255), ForeignKey('groups.uuid'), nullable=True)
    assigned_users = relationship('MoneyVigilUser', secondary=UserCorporateRolesAssocTab, backref='assigned_roles')  # might be redundant
    assigned_eth_addresses = relationship('MoneyVigilUserEthereumAddresses', secondary=EthAddressRoleAssocTable, backref='assigned_roles')
    connected_entity = relationship('MoneyVigilCorporateEntity', backref='roles')
    connected_group = relationship('MoneyVigilGroup', backref='roles')


"""
TODO: Introduce action groups of CRUD on resources.
Resources can be
    - the entity itself
    - individual groups
    - expenses 
"""


class MoneyVigilCorporateEntityPermission(Base):
    __tablename__ = 'corporate_entities_permissions'
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    corporate_entity_id = Column(Integer, ForeignKey('corporate_entities.id'), nullable=False)
    # a json serialized message  that can have multiple extensible uses in the future
    # for eg: if the action is connected to further abstractions like sub-entities, groups etc
    specific_sublinkage = Column(Text, nullable=True)
    assigned_entity = relationship('MoneyVigilCorporateEntity', backref='allowed_permissions')
    assigned_roles = relationship('MoneyVigilCorporateEntityRole', secondary=RolesToPermissionsAssocTable, backref='assigned_permissions')


class MoneyVigilUserEthereumAddresses(Base):
    __tablename__ = 'user_ethereum_addresses'
    id = Column(Integer, primary_key=True)
    name = Column(String(255))  # some name to refer the stored addresses by
    address = Column(String(255), unique=True)
    user_uuid = Column(String(255), ForeignKey('user.uuid'), nullable=False)
    connected_user = relationship('MoneyVigilUser', backref='eth_addresses')