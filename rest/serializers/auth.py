from rest_framework.authtoken.serializers import AuthTokenSerializer

from django.utils import timezone
from wselasticsearch.models import LoginAttemptModel
from wselasticsearch.ops import get_login_attempts_for_ip_address_within_threshold
from lib import DjangoUtils
from rest_framework.fields import empty
from rest_framework import serializers
from rest.lib.exception import WsRestNonFieldException, WsRestFieldException
from rest_framework import serializers

from django.contrib.auth import get_user_model, authenticate
from lib.config import ConfigManager

UserModel = get_user_model()
config = ConfigManager.instance()


class WsAuthTokenSerializer(AuthTokenSerializer):
    """
     This searializer will login the user, and handle the various failure cases
    """

    username = serializers.EmailField(
        required=True,
        help_text="The email address of the user to authenticate as.",
    )
    password = serializers.CharField(
        required=True,
        help_text="The password to authenticate with.",
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                # From Django 1.10 onwards the `authenticate` call simply
                # returns `None` for is_active=False users.
                # (Assuming the default `ModelBackend` authentication backend.)
                if not user.is_active:
                    raise WsRestNonFieldException('User account is disabled.')

                # A verification email is sent when an account is created,
                #    this must be clicked before the user can login
                if not user.email_verified:
                    raise WsRestNonFieldException('User account has not had it\'s email verified')

            else:
                exception = WsRestNonFieldException('Unable to log in with provided credentials.')
                ip_address = None
                user_agent = None
                login_attempt = LoginAttemptModel(ip_address, user_agent, timezone.now())
                login_attempt.save(config.es_default_index)

                # Attempt to find any past login attempts from
                #   elastic search for this ip, within the threshold
                attempts = get_login_attempts_for_ip_address_within_threshold(ip_address, config.es_default_index)

                if attempts.results_count >= config.recaptcha_login_attempt_threshold:
                    # Recaptcha required
                    exception.require_recaptcha()

                raise exception
        else:
            raise WsRestNonFieldException('Must include "username" and "password".')

        attrs['user'] = user
        return attrs
