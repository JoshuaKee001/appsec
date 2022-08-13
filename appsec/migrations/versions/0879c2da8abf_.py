"""empty message

Revision ID: 0879c2da8abf
Revises: 
Create Date: 2022-08-13 15:09:20.917286

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0879c2da8abf'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('failedaccess', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'failedaccess')
    # ### end Alembic commands ###
