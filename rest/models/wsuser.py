# -*- coding: utf-8 -*-
from .base import BaseWsModel
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
import uuid


class WsUser(AbstractUser, BaseWsModel):
    """
    This extends the base django User, adding more information
    """

    #These are all of the valid special characters a password can have
    SPECIAL_CHARACTERS = "~`!@#$%^&*()_-+={}[]:>;',</?*+"

    # This is the invalid password error message
    INVALID_PASSWORD_COMPLEXITY_ERROR_MESSAGE = ('Password does not meet complexity requirements. ' +
        'Passwords must be longer than 8 characters, ' +
        'contain at least 1 upper case character, ' +
        'contain at least 1 number,' +
        'and contain at least 1 special character.')


    # Columns

    # Right now accounts are required to be manually approved, in the future this may not be checked
    account_manually_approved = models.BooleanField(default=False)
    # This is set when the account is created, this is used to verify the account originally
    email_registration_code = models.UUIDField(default=uuid.uuid4, editable=False)
    email_verified = models.BooleanField(default=False)

    forgot_password_code = models.UUIDField(default=uuid.uuid4, null=True)
    forgot_password_date = models.DateTimeField(default=timezone.now, blank=True, null=True)
    is_enterprise_user = models.BooleanField(default=False, null=False)

    @staticmethod
    def validate_password_complexity(password):
        """
            This method will return true if the password is complex enough
            Current rules are as follows:
            - 8 Characters minimum
            - 1 Upper Case
            - 1 Number
            - 1 Special Character
        """
        is_valid = True

        #This should only be passed a string
        if not (type(password) == str or type(password) == unicode):
            is_valid = False

        # 8 Characters minimum
        if len(password) < 8:
            is_valid = False

        # 1 Upper Case Character
        if not any(x.isupper() for x in password):
            is_valid = False

        # 1 Number
        if not any(x.isdigit() for x in password):
            is_valid = False

        # 1 Special Character
        if not any(x in list(WsUser.SPECIAL_CHARACTERS) for x in password):
            is_valid = False

        return is_valid

    @property
    def organizations(self):
        """
        Get a list containing all of the organizations that this user is associated with.
        :return: a list containing all of the organizations that this user is associated with.
        """
        to_return = set()
        for auth_group in self.auth_groups.all():
            to_return.add(auth_group.organization)
        return list(to_return)

    # Foreign Keys
    class Meta:
        app_label = "rest"
