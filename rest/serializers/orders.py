# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from .base import WsBaseModelSerializer
import rest.models


class OrderSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for the Order rest model.
    """

    user = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())
    networks = serializers.SlugRelatedField(many=True, read_only=True, slug_field="network_cidr")
    domain_names = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")

    def create(self, validated_data):
        """
        Perform the creation of this order.
        :param validated_data: The validated data sanitized by this serializer.
        :return: The newly-created Order.
        """
        if "payment_token" in validated_data:
            return rest.models.Order.objects.create_from_token_user_and_organization(
                payment_token=validated_data["payment_token"],
                user=validated_data["user"],
                organization=validated_data["organization"],
            )
        else:
            return rest.models.Order.objects.create_from_user_and_organization(
                user=validated_data["user"],
                organization=validated_data["organization"],
            )

    class Meta:
        model = rest.models.Order
        fields = (
            "created",
            "uuid",
            "started_at",
            "completed_at",
            "user_email",
            "order_tier_name",
            "order_tier_price",
            "scoped_domains_count",
            "scoped_endpoints_count",
            "scoped_endpoints_size",
            "price_currency",
            "order_cost",
            "charge_amount",
            "transaction_id",
            "has_been_charged",
            "charged_at",
            "user",
            "networks",
            "domain_names",
            "payment_last_four",
            "payment_exp_month",
            "payment_exp_year",
            "is_enterprise_order",
        )
        read_only_fields = (
            "created",
            "uuid",
            "started_at",
            "completed_at",
            "user_email",
            "order_tier_name",
            "order_tier_price",
            "scoped_domains_count",
            "scoped_endpoints_count",
            "scoped_endpoints_size",
            "price_currency",
            "order_cost",
            "charge_amount",
            "transaction_id",
            "has_been_charged",
            "charged_at",
            "user",
            "payment_last_four",
            "payment_exp_month",
            "payment_exp_year",
            "is_enterprise_order",
        )
        extra_kwargs = {
            "organization": {"read_only": True},
            "payment_token": {"read_only": True},
        }

