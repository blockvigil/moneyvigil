import tenacity
from db_models import MoneyVigilUser, MoneyVigilUnsubscribeTokens, MoneyVigilInvites, MoneyVigilGroup, MoneyVigilBill,\
    MoneyVigilCorporateEntity, MoneyVigilCorporateEntityRole, MoneyVigilCorporateEntityPermission
import sqlalchemy.exc
import logging
import sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class DBCallsWrapper(object):

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_user_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilUser).filter_by(**kwargs).first()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_group_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilGroup).filter_by(**kwargs).first()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_all_users(self, session_obj):
        return session_obj.query(MoneyVigilUser).all()

    @tenacity.retry(
            stop=tenacity.stop_after_attempt(3),
            wait=tenacity.wait_fixed(3),
            reraise=True,
            retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
            before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
        )
    def query_all_groups(self, session_obj):
        return session_obj.query(MoneyVigilGroup).all()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_unsubscribetoken_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilUnsubscribeTokens).filter_by(**kwargs).first()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_bill_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilBill).filter_by(**kwargs).first()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_invites_by_all(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilInvites).filter_by(**kwargs).all()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
        retry=tenacity.retry_if_exception_type(sqlalchemy.exc.OperationalError),
        before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG)
    )
    def query_entity_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilCorporateEntity).filter_by(**kwargs).first()

    def query_role_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilCorporateEntityRole).filter_by(**kwargs).first()

    def query_roles_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilCorporateEntityRole).filter_by(**kwargs).all()

    def query_permission_by_(self, session_obj, *args, **kwargs):
        return session_obj.query(MoneyVigilCorporateEntityPermission).filter_by(**kwargs).first()