# -*- coding: utf-8 -*-
from __future__ import absolute_import
from datetime import timedelta
from django.contrib.auth.models import Group
from django.utils import timezone
from django.contrib.auth import get_user_model
from lib.config import ConfigManager

from rest_framework import serializers
from rest.lib.exception import WsRestNonFieldException, WsRestFieldException
from lib.smtp.smtp import SmtpEmailHelper
import uuid
from lib import RandomHelper
from tasknode.tasks import send_emails_for_user_signup

config = ConfigManager.instance()
UserModel = get_user_model()


class AdminManageUsersSerializer(serializers.Serializer):
    """
     This will get all non admin users, and return the list to the view for serilization
    """

    def validate(self, attrs):
        users = UserModel.objects.filter(is_superuser=False).order_by('email').all()

        attrs['users'] = users
        return attrs


class AdminManageUsersEnableDisableSerializer(serializers.Serializer):
    """
     This enable or disable a user in the system
    """

    user_uuid = serializers.UUIDField(
        required=True,
        help_text="A user's UUID."
    )
    enabled = serializers.BooleanField(
        required=True,
        help_text="Whether the account should be enabled or disabled."
    )

    def validate(self, attrs):
        user_uuid = attrs['user_uuid']
        enabled = attrs['enabled']

        user = UserModel.objects.filter(uuid=user_uuid).first()

        if user:
            user.account_manually_approved = enabled
            user.save()
        else:
            raise WsRestNonFieldException('No user with that uuid found.')
        return attrs


class AdminManageUsersDeleteUserSerializer(serializers.Serializer):
    """
     This will delete a user from the system
    """

    user_uuid = serializers.UUIDField(
        required=True,
        help_text="A user's UUID."
    )

    def validate(self, attrs):
        user_uuid = attrs['user_uuid']
        user = UserModel.objects.filter(uuid=user_uuid).first()

        if user:
            if not user.is_superuser:
                user.delete()
            else:
                raise WsRestNonFieldException('Admin users can not be deleted.')
        else:
            raise WsRestNonFieldException('No user with that uuid found.')
        return attrs


class AdminManageUsersResendVerificationEmailSerializer(serializers.Serializer):
    """
     This will resend a user's verification email
    """

    user_uuid = serializers.UUIDField(
        required=True,
        help_text="A user's UUID."
    )

    def validate(self, attrs):
        user_uuid = attrs['user_uuid']
        user = UserModel.objects.filter(uuid=user_uuid).first()

        if user:
            #Reset the verification code
            user.email_registration_code = RandomHelper.get_cryptographic_uuid()
            user.save()

            # Send verification email
            send_emails_for_user_signup.delay(user_uuid=user_uuid)
        else:
            raise WsRestNonFieldException('No user with that uuid found.')
        return attrs