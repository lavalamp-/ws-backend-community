from rest_framework import serializers
from rest.lib.exception import WsRestNonFieldException, WsRestFieldException
from django.contrib.auth import get_user_model

UserModel = get_user_model()


class ChangePasswordSerialzer(serializers.Serializer):

    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate(self, attrs):

        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')

        user = self.instance.user

        if not user:
            raise WsRestNonFieldException('You must be logged in to change your password.')
        elif not user.is_authenticated:
            raise WsRestNonFieldException('You must be logged in to change your password.')
        # If the user's current password is the supplied password
        elif not user.check_password(current_password):
            raise WsRestFieldException('The supplied current password is not valid.', 'current_password')
        # If the new password meets the password requirements
        elif not UserModel.validate_password_complexity:
            raise WsRestFieldException(UserModel.INVALID_PASSWORD_COMPLEXITY_ERROR_MESSAGE, 'new_password')
        elif current_password == new_password:
            raise WsRestFieldException('The new password needs to be different than the current password.',
                                       'new_password')
        # Change the password
        else:
            user.set_password(new_password)
            user.save()
            attrs["user"] = user

        return attrs
