# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers
from datetime import datetime

from lib import RegexLib
from .base import WsBaseModelSerializer
import rest.models


class PaymentTokenSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for the PaymentToken model.
    """

    expiration_month = serializers.IntegerField(max_value=12, min_value=1)
    expiration_year = serializers.IntegerField(max_value=datetime.now().year + 20, min_value=datetime.now().year)
    token_type = serializers.ChoiceField(choices=["stripe"], allow_blank=False)
    user = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())

    def validate_card_last_four(self, value):
        """
        Validate the contents of the given value for use as the last four digits of a credit
        card number.
        :param value: The value to validate.
        :return: The value
        """
        if not RegexLib.card_last_four_regex.match(value):
            raise serializers.ValidationError(
                "%s is not valid for last four digits of a credit card number"
                % (value,)
            )
        return value

    def validate_token_value(self, value):
        """
        Validate the contents of the given value for use as a token.
        :param value: The value to validate.
        :return: The value.
        """
        if self.initial_data.get("token_type") == "stripe":
            if not RegexLib.stripe_payment_token_regex.match(value):
                raise serializers.ValidationError(
                    "%s is not a valid stripe token"
                    % (value,)
                )
        return value

    class Meta:
        model = rest.models.PaymentToken
        fields = (
            "uuid",
            "created",
            "name",
            "token_type",
            "token_value",
            "card_type",
            "expiration_month",
            "expiration_year",
            "card_last_four",
            "user",
            "can_be_charged",
        )
        read_only_fields = (
            "uuid",
            "created",
            "user",
            "can_be_charged",
        )
