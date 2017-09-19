# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from tasknode.app import websight_app
from tasknode.tasks.base import DatabaseTask
from lib.sqlalchemy import get_user_name_and_email_from_order, get_admin_emails, \
    get_name_email_and_verification_token_for_user, get_user_activation_token, \
    get_admin_contacts_for_organization, get_user_tuples_for_organization
from lib.smtp import SmtpEmailHelper

logger = get_task_logger(__name__)


#USED
@websight_app.task(bind=True, base=DatabaseTask)
def email_org_users_for_order_completion(self, order_uuid=None, org_uuid=None, org_name=None):
    """
    Send emails to all of the users associated with the organization that owns the specified order
    indicating that the order has been completed.
    :param order_uuid: The UUID of the order that finished.
    :param org_uuid: The UUID of the organization that the order is associated with.
    :param org_name: The name of the organization that the order is associated with.
    :return: None
    """
    logger.info(
        "Now sending emails for completion of order %s to all users of the parent organization."
        % (order_uuid,)
    )
    org_user_tuples = get_user_tuples_for_organization(org_uuid=org_uuid, db_session=self.db_session)
    smtp_helper = SmtpEmailHelper.instance()
    smtp_helper.send_emails_for_completed_order_to_users(
        order_uuid=order_uuid,
        org_uuid=org_uuid,
        org_name=org_name,
        org_contact_tuples=org_user_tuples,
    )
    logger.info(
        "Emails for completed order %s sent to %s users associated with organization."
        % (order_uuid, len(org_user_tuples))
    )


#USED
@websight_app.task(bind=True, base=DatabaseTask)
def email_order_user_for_order_completion(self, order_uuid=None, org_uuid=None, org_name=None):
    """
    Send an email to the user that kicked off the given order indicating that the order has been
    completed.
    :param order_uuid: The UUID of the order that finished.
    :param org_uuid: The UUID of the organization that the order is associated with.
    :param org_name: The name of the organization that the order is associated with.
    :return: None
    """
    logger.info(
        "Now sending email to order owner for order %s."
        % (order_uuid,)
    )
    user = self.order.user
    org_contact_tuples = [(user.first_name, user.email_address)]
    smtp_helper = SmtpEmailHelper.instance()
    smtp_helper.send_emails_for_completed_order_to_users(
        order_uuid=order_uuid,
        org_uuid=org_uuid,
        org_name=org_name,
        org_contact_tuples=org_contact_tuples,
    )
    logger.info(
        "Email sent to owning user for order %s."
        % (order_uuid,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def send_emails_for_org_user_invite(
        self,
        org_uuid=None,
        org_name=None,
        user_uuid=None,
        user_name=None,
        user_email=None,
        user_is_new=False,
):
    """
    Handle the sending of emails as a result of the given user being granted access to the given
    organization.
    :param org_uuid: The UUID of the organization that the user was added to.
    :param org_name: The name of the organization that the user was added to.
    :param user_uuid: The UUID of the user that was added.
    :param user_name: The name of the user that was added.
    :param user_email: The email address of the user that was added.
    :param user_is_new: Whether or not the user was created by the invitation process, or if the
    user already existed.
    :return: None
    """
    logger.info(
        "Now handling sending emails for user %s invitation to organization %s."
        % (user_uuid, org_uuid)
    )
    smtp_helper = SmtpEmailHelper.instance()
    if user_is_new:
        activation_token = get_user_activation_token(user_uuid=user_uuid, db_session=self.db_session)
        smtp_helper.send_email_for_new_user_org_invite(
            activation_token=activation_token,
            org_name=org_name,
            org_uuid=org_uuid,
            user_email=user_email,
            user_uuid=user_uuid,
        )
    else:
        smtp_helper.send_email_for_user_org_invite(
            user_name=user_name,
            user_email=user_email,
            org_name=org_name,
            org_uuid=org_uuid,
        )
    org_admin_contacts = get_admin_contacts_for_organization(db_session=self.db_session, org_uuid=org_uuid)
    smtp_helper.send_admin_emails_for_user_invite(
        org_uuid=org_uuid,
        org_name=org_name,
        invited_user_email=user_email,
        invited_user_name=user_name,
        admin_contact_tuples=org_admin_contacts,
    )


@websight_app.task(bind=True, base=DatabaseTask)
def send_emails_for_placed_order(self, order_uuid=None, receipt_description=None):
    """
    Handle the sending of emails as a result of the given order being placed.
    :param order_uuid: The UUID of the order that was placed.
    :param receipt_description: A description of the receipt for the order.
    :return: None
    """
    logger.info(
        "Now handling sending emails for placement of order %s."
        % (order_uuid,)
    )
    user_name, user_email = get_user_name_and_email_from_order(order_uuid=order_uuid, db_session=self.db_session)
    if not user_name:
        user_name = "Web Sight User"
    admin_emails = get_admin_emails(self.db_session)
    smtp_helper = SmtpEmailHelper.instance()
    smtp_helper.send_emails_for_placed_order(
        user_name=user_name,
        user_email=user_email,
        admin_emails=admin_emails,
        order_receipt_description=receipt_description,
    )
    logger.info(
        "All emails sent for placed order %s."
        % (order_uuid,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def send_emails_for_user_signup(self, user_uuid=None):
    """
    Handle the sending of emails as a result of the given user signing up.
    :param user_uuid: The UUID of the user that signed up.
    :return: None
    """
    logger.info(
        "Now handling sending emails for user %s signing up."
        % (user_uuid,)
    )
    user_name, user_email, verification_token = get_name_email_and_verification_token_for_user(
        user_uuid=user_uuid,
        db_session=self.db_session,
    )
    if not user_name:
        user_name = "Web Sight User"
    admin_emails = get_admin_emails(self.db_session)
    smtp_helper = SmtpEmailHelper.instance()
    smtp_helper.send_emails_for_user_signup(
        user_email=user_email,
        verification_token=verification_token,
        user_name=user_name,
        user_uuid=user_uuid,
        admin_emails=admin_emails,
    )
    logger.info(
        "All emails sent for user %s signing up."
        % (user_uuid,)
    )
