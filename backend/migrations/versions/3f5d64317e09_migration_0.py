"""Migration 0

Revision ID: 3f5d64317e09
Revises: 
Create Date: 2019-05-29 15:44:38.648614

"""
from alembic import op
from db_models import *
from db_session import *

# revision identifiers, used by Alembic.
revision = '3f5d64317e09'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    Base.metadata.create_all(engine)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    Base.metadata.drop_all(engine)
    # ### end Alembic commands ###
