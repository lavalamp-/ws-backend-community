# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lib.config import ConfigManager
from lib.singleton import Singleton
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from django.core.mail import send_mail

config = ConfigManager.instance()


@Singleton
class SmtpEmailHelper(object):
    """
    This class will send emails, using the credentials in tasknode/tasknode.cfg
    """

    def __init__(self):
        self.smtp_username = config.smtp_username
        self.smtp_password = config.smtp_password
        self.smtp_host = config.smtp_endpoint

    def create_plain_message(self, template_name, template_data):
        """
        This will create a plain text email using the provided template_name and data
        :param template_name: The template to populate
        :param template_data: The data to use to populate
        :return: A string represtation of the plain text email
        """
        template = open('lib/smtp/email_templates/' + template_name + '.txt')
        content = template.read()
        for key in template_data.keys():
            content = content.replace(key, template_data[key])
        return content

    def create_html_message(self, template_name, template_data):
        """
        This will populate and html email template, based on the provided name and data
        :param template_name: The template to populate
        :param template_data: The data to populate the template with
        :return: A string representation of the populated html template
        """
        template = open('lib/smtp/email_templates/'+template_name+'.html')
        content = template.read()
        for key in template_data.keys():
            content = content.replace(key, template_data[key].replace("\n", "<br>"))
        return content

    def send(self, to_address, subject, plain_message, html_message):
        """
        This is the base send message, that will send an email
        :param to_address: This is the address being emailed
        :param subject: The email subject
        :param html_message: The html message
        """

        send_mail(subject,
                  plain_message,
                  self.smtp_username,
                  [to_address],
                  html_message=html_message,
                  fail_silently=False)

    def send_admin_emails_for_user_invite(
            self,
            org_uuid=None,
            org_name=None,
            invited_user_email=None,
            invited_user_name=None,
            admin_contact_tuples=None,
    ):
        """
        Send emails to all of the administrative users for the given organization notifying them that
        the given user has been granted access to the organization.
        :param org_uuid: The UUID of the organization that the user was added to.
        :param org_name: The name of the organization that the user was added to.
        :param invited_user_email: The email address of the user that was added.
        :param invited_user_name: The name of the user that was added.
        :param admin_contact_tuples: A list of tuples containing (1) the user first name and (2) the user
        email address for all administrative users associated with the given organization.
        :return: None
        """
        subject = "A new user was added to %s" % (org_name,)
        if not invited_user_name:
            invited_user_name = "No Name Supplied"
        template_data = {
            "[INVITED_NAME]": invited_user_name,
            "[INVITED_EMAIL]": invited_user_email,
            "[ORG_NAME]": org_name,
            "[ORG_UUID]": org_uuid,
            "[DOMAIN_REPLACE]": config.rest_domain,
        }
        for first_name, admin_email in admin_contact_tuples:
            template_data["[ADMIN_NAME]"] = first_name
            html_message = self.create_html_message("org_user_added", template_data)
            plain_message = self.create_plain_message("org_user_added", template_data)
            self.send(admin_email, subject, plain_message, html_message)

    def send_email_for_new_user_org_invite(
            self,
            activation_token=None,
            org_name=None,
            org_uuid=None,
            user_email=None,
            user_uuid=None,
    ):
        """
        Send an email to the given user informing them that they have been added to the given organization.
        :param activation_token: The token that the user should use to activate their account.
        :param org_name: The name of the organization that the user was added to.
        :param org_uuid: The UUID of the organization that the user was added to.
        :param user_email: The user's email address.
        :param user_uuid: The UUID of the user that was invited.
        :return: None
        """
        subject = "You're Invited to View %s's Data on Web Sight" % (org_name,)
        template_data = {
            "[ORG_NAME]": org_name,
            "[ACTIVATION_TOKEN]": activation_token,
            "[ORG_UUID]": org_uuid,
            "[DOMAIN_REPLACE]": config.rest_domain,
            "[USER_UUID]": user_uuid,
        }
        html_message = self.create_html_message("new_user_org_invite", template_data)
        plain_message = self.create_plain_message("new_user_org_invite", template_data)
        self.send(user_email, subject, plain_message, html_message)

    def send_email_for_user_org_invite(self, user_name=None, user_email=None, org_name=None, org_uuid=None):
        """
        Send an email to the given user informing them that they have been added to the given organization.
        :param user_name: The user's name.
        :param user_email: The user's email address.
        :param org_name: The name of the organization that the user was added to.
        :param org_uuid: The UUID of the organization that the user was added to.
        :return: None
        """
        subject = "%s's Data Has Been Shared With You on Web Sight" % (org_name,)
        template_data = {
            "[ORG_NAME]": org_name,
            "[ORG_UUID]": org_uuid,
            "[USER_NAME]": user_name,
            "[DOMAIN_REPLACE]": config.rest_domain,
        }
        html_message = self.create_html_message("user_org_invite", template_data)
        plain_message = self.create_plain_message("user_org_invite", template_data)
        self.send(user_email, subject, plain_message, html_message)

    def send_emails_for_placed_order(
            self,
            user_name=None,
            user_email=None,
            admin_emails=None,
            order_receipt_description=None,
    ):
        """
        Send all of the necessary emails for the placement of the given order.
        :param user_name: The user's name.
        :param user_email: The user's email address.
        :param admin_emails: A list of email addresses for all Web Sight administrative users.
        :param order_receipt_description: A description of the receipt for the order.
        :return: None
        """
        subject = "Web Sight Order Placed"
        template_name = "user_order_placed"
        template_data = {
            "[NAME_REPLACE]": user_name,
            "[RECEIPT_REPLACE]": order_receipt_description,
        }
        html_message = self.create_html_message(template_name, template_data)
        plain_message = self.create_plain_message(template_name, template_data)
        self.send(user_email, subject, plain_message, html_message)
        template_name = "admin_order_placed"
        template_data = {
            "[RECEIPT_REPLACE]": order_receipt_description,
        }
        html_message = self.create_html_message(template_name, template_data)
        plain_message = self.create_plain_message(template_name, template_data)
        for admin_email in admin_emails:
            self.send(admin_email, subject, plain_message, html_message)

    def send_emails_for_user_signup(
            self,
            user_email=None,
            verification_token=None,
            user_name=None,
            user_uuid=None,
            admin_emails=None,
    ):
        """
        Send all of the necessary emails related to when a user signs up.
        :param user_email: The email of the user that signed up.
        :param verification_token: The verification token for the user to verify their email through.
        :param user_name: The user's first name.
        :param user_uuid: The user's UUID.
        :param admin_emails: A list of administrative email addresses to notify of the new user sign up.
        :return: None
        """
        template_data = {
            "[TOKEN_REPLACE]": verification_token,
            "[NAME_REPLACE]": user_name,
            "[USER_UUID_REPLACE]": user_uuid,
            "[DOMAIN_REPLACE]": config.rest_domain,
        }
        html_message = self.create_html_message("verify_email", template_data)
        plain_message = self.create_plain_message("verify_email", template_data)
        self.send(user_email, "Web Sight - Verify Your Email Address", plain_message, html_message)
        template_data = {
            "[USER_EMAIL_REPLACE]": user_email,
            "[USER_NAME_REPLACE]": user_name,
            "[DOMAIN_REPLACE]": config.rest_domain,
        }
        html_message = self.create_html_message("user_signed_up", template_data)
        plain_message = self.create_plain_message("user_signed_up", template_data)
        for admin_email in admin_emails:
            self.send(admin_email, "Web Sight - User Signed Up!", plain_message, html_message)

    def send_forgot_password_email(self, to_address, forgot_password_token, name, user_uuid):
        """
         This will send the forgot password email
        :param to_address: The email address to send the email to
        :param forgot_password_token: The forgot password token
        :param name: The user's name
        :param user_uuid: The user's uuid, used for verification
        """
        subject = "Websight.io Reset Password"
        template_name = 'forgot_password'
        template_data = {
            '[TOKEN_REPLACE]': forgot_password_token,
            '[NAME_REPLACE]': name,
            '[USER_UUID_REPLACE]': user_uuid,
            '[DOMAIN_REPLACE]': config.rest_domain,
        }
        html_message = self.create_html_message(template_name, template_data)
        plain_message = self.create_plain_message(template_name, template_data)
        self.send(to_address, subject, plain_message, html_message)

    def send_verification_email(self, to_address, verification_token, name, user_uuid):
        """
         This will send the verification email, after a user signs up
        :param to_address: The email address to send the email to
        :param verification_token: The email verification token
        :param name: The user's name
        :param user_uuid: The user's uuid
        """
        subject = "Websight.io Email Verification"
        template_name = 'verify_email'
        template_data = {
            '[TOKEN_REPLACE]': verification_token,
            '[NAME_REPLACE]': name,
            '[USER_UUID_REPLACE]': user_uuid
        }
        html_message = self.create_html_message(template_name, template_data)
        plain_message = self.create_plain_message(template_name, template_data)
        self.send(to_address, subject, plain_message, html_message)

    def send_invite_email(self, to_address, verification_token, user_uuid):
        """
         This will send the invite email, after a new user is added to the system
        :param to_address: The email address to send the email to
        :param verification_token: The email verification token
        :param user_uuid: The user's uuid
        """
        subject = "You are Invited to join Websight.io"
        template_name = 'invite_email'
        template_data = {
            '[TOKEN_REPLACE]': verification_token,
            '[USER_UUID_REPLACE]': user_uuid,
            '[DOMAIN_REPLACE]': config.rest_domain,
        }
        html_message = self.create_html_message(template_name, template_data)
        plain_message = self.create_plain_message(template_name, template_data)
        self.send(to_address, subject, plain_message, html_message)

    def test_authentication(self):
        """
        Check to see whether or not the currently configured SMTP credentials can be used
        to authenticate to the remote service.
        :return: True if the current configured SMTP credentials can be used to authenticate to
        the remote service, False otherwise.
        """
        connection = smtplib.SMTP(config.smtp_host, config.smtp_port)
        connection.ehlo()
        connection.starttls()
        try:
            connection.login(config.smtp_username, config.smtp_password)
            return True
        except smtplib.SMTPAuthenticationError:
            return False
