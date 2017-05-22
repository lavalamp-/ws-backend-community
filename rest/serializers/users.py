# -*- coding: utf-8 -*-
from __future__ import absolute_import
from datetime import timedelta
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from lib.config import ConfigManager

from rest_framework import serializers
from rest.lib.exception import WsRestNonFieldException, WsRestFieldException
from lib.smtp.smtp import SmtpEmailHelper
from lib.recaptcha import RecaptchaHelper
from lib import RandomHelper
import uuid
from tasknode.tasks import send_emails_for_user_signup

config = ConfigManager.instance()
UserModel = get_user_model()


class VerifyEmailSerializer(serializers.Serializer):
    """
     This is used to verify a users email, after they first sign up
    """

    email_token = serializers.UUIDField(required=True)
    user_uuid = serializers.UUIDField(required=True)

    def validate(self, attrs):
        email_token = attrs.get('email_token')
        user_uuid = attrs.get('user_uuid')

        user = get_object_or_404(UserModel, pk=user_uuid)

        if user:
            if str(user.email_registration_code) == str(email_token):
                # The email code is valid, activate this user
                user.email_verified = True
                user.save()
            else:
                # Found a user but invalid registration code
                raise WsRestNonFieldException('Invalid email registration code.')
        else:
            # No user with that uuid, but same error message,
            #   we don't want to expose unnessecary information
            raise WsRestNonFieldException('Invalid email registration code.')
        return attrs


class SetupAccountSerializer(serializers.Serializer):
    """
     This is used to setup an invited user's account
    """

    email_token = serializers.UUIDField(required=True)
    user_uuid = serializers.UUIDField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    recaptcha_response = serializers.CharField(read_only=True)

    def validate(self, attrs):
        email_token = attrs.get('email_token')
        user_uuid = attrs.get('user_uuid')
        first_name = attrs.get('first_name')
        last_name = attrs.get('last_name')
        password = attrs.get('password')
        recaptcha_response = self.initial_data.get('recaptcha_response', "")
        recaptcha_is_valid = False

        if recaptcha_response:
            recaptcha_is_valid = RecaptchaHelper.is_valid_response(recaptcha_response)

        if not recaptcha_is_valid:
            raise WsRestNonFieldException('Supplied recaptcha token is invalid!')

        if not UserModel.validate_password_complexity(password):
            raise WsRestNonFieldException(UserModel.INVALID_PASSWORD_COMPLEXITY_ERROR_MESSAGE)

        user = get_object_or_404(UserModel, pk=user_uuid)

        if user:
            if str(user.email_registration_code) == str(email_token):
                # The email code is valid, setup account information and validate user
                user.first_name = first_name
                user.last_name = last_name
                user.email_verified = True
                user.save()

                user.set_password(password)
                user.save()
            else:
                # Found a user but invalid registration code
                raise WsRestNonFieldException('Invalid email registration code.')
        else:
            # No user with that uuid, but same error message,
            #   we don't want to expose unnessecary information
            raise WsRestNonFieldException('Invalid email registration code.')
        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    """
     This starts the forgot password process and sends the reset email
    """

    email_address = serializers.EmailField(required=True)

    def validate(self, attrs):
        email_address = attrs.get('email_address')
        user = get_object_or_404(UserModel, email=email_address)
        # Start the forgot password reset process
        user.forgot_password_code = RandomHelper.get_cryptographic_uuid()
        user.forgot_password_date = timezone.now()
        user.save()

        # Send the forgot password email
        smtp_helper = SmtpEmailHelper.instance()
        smtp_helper.send_forgot_password_email(user.email,
           str(user.forgot_password_code),
           user.first_name,
           str(user.uuid))
        return attrs


class VerifyForgotPasswordSerializer(serializers.Serializer):
    """
     This is used to reset a user's password, using the link from their email
    """

    email_token = serializers.UUIDField(required=True)
    user_uuid = serializers.UUIDField(required=True)
    new_password = serializers.CharField(required=True)

    def validate(self, attrs):
        email_token = attrs.get('email_token')
        user_uuid = attrs.get('user_uuid')
        new_password = attrs.get('new_password')

        user = get_object_or_404(UserModel, pk=user_uuid)

        if str(user.forgot_password_code) == str(email_token):
            #If the new password meets compexity requirements
            if UserModel.validate_password_complexity(new_password):
                #If the new password isn't the current password
                if not user.check_password(new_password):
                    #If the user has reset their password, within the reset timeout window
                    if timezone.now() < timedelta(minutes=config.gen_reset_password_timeout_minutes) + user.forgot_password_date:
                        # The email code is valid, activate this user
                        user.set_password(new_password)
                        #invalidate the token, so they can't change it again
                        user.forgot_password_code = None
                        user.save()
                    else:
                        raise WsRestNonFieldException('This reset password code has expired.')
                else:
                    raise WsRestNonFieldException('The new password code must be different then your current password.')
            else:
                raise WsRestNonFieldException(UserModel.INVALID_PASSWORD_COMPLEXITY_ERROR_MESSAGE)
        else:
            # Found a user but invalid registration code
            raise WsRestNonFieldException('Invalid reset password code.')
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """
    This serializer validates the inputs, used to create new users
    """

    password = serializers.CharField(write_only=True)
    username = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    recaptcha_response = serializers.CharField(read_only=True)

    def create(self, validated_data):

        is_valid_password = UserModel.validate_password_complexity(validated_data['password'])

        recaptcha_is_valid = False

        recaptcha_response = self.initial_data.get('recaptcha_response', "")
        if recaptcha_response:
            recaptcha_is_valid = RecaptchaHelper.is_valid_response(recaptcha_response)

        if not is_valid_password:
            raise WsRestNonFieldException(UserModel.INVALID_PASSWORD_COMPLEXITY_ERROR_MESSAGE)

        if not recaptcha_is_valid:
            raise WsRestNonFieldException('Supplied recaptcha token is invalid!')

        try:
            user = UserModel.objects.create(
                username=validated_data['username'],
                #Right now your username is your email, if this changes we need to change this
                email=validated_data['username'],
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name']
            )
            user.set_password(validated_data['password'])
            user.email_registration_code = RandomHelper.get_cryptographic_uuid()
            user.save()

            #Send verification email
            send_emails_for_user_signup.delay(unicode(user.uuid))

            return user
        except IntegrityError as ie:
            raise WsRestNonFieldException('A user with this username already exists!')
        except Exception as e:
            raise WsRestNonFieldException(e.message)
        return None

    class Meta:
        model = UserModel
        fields = ("first_name", "last_name", "username", "password", "email", "recaptcha_response")

