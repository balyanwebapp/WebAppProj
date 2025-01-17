"""empty message

Revision ID: 6e8ca4b1e897
Revises: 9f3229bc1cba
Create Date: 2024-06-26 16:27:22.744126

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6e8ca4b1e897'
down_revision = '9f3229bc1cba'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('email_verified')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email_verified', sa.BOOLEAN(), nullable=False))

    # ### end Alembic commands ###
