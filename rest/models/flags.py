# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models
import uuid
from base64 import b64encode, b64decode
import json

from .base import BaseWsModel


class FlagManager(models.Manager):
    """
    This is a manager class for handling operations around the creation of Flag models.
    """

    def from_elasticsearch_query(self, query=None, **kwargs):
        """
        Create and return a flag based on the contents of the given Elasticsearch query object.
        :param query: An Elasticsearch query class to retrieve filters from.
        :param kwargs: Keyword arguments to pass to create.
        :return: The newly-created object.
        """
        kwargs["query_dict"] = query.to_query_dict()["query"]
        kwargs["doc_types"] = query.doc_type
        return self.from_query_dict(**kwargs)

    def from_query_dict(self, query_dict=None, **kwargs):
        """
        Create and return a flag based on the contents of the given dictionary representing an Elasticsearch
        query dictionary.
        :param query_dict: An Elasticsearch query dictionary.
        :param args: Positional arguments to pass to super.create.
        :param kwargs: Keyword arguments to pass to super.create.
        :return: The newly-created object.
        """
        query_string = json.dumps(query_dict)
        kwargs["query"] = b64encode(query_string)
        return self.create(**kwargs)


class BaseFlag(BaseWsModel):
    """
    This is a base model class for all model classes that represent flag information.
    """

    # Management

    objects = FlagManager()

    # Columns

    name = models.CharField(max_length=32, null=False)
    tag = models.UUIDField(default=uuid.uuid4, editable=False)
    description = models.CharField(max_length=256, null=True)
    flag_type = models.CharField(max_length=16, default="canned")
    query = models.CharField(max_length=2048, null=True)
    func_name = models.CharField(max_length=256, null=True)
    weight = models.IntegerField(default=1)
    doc_types = models.CharField(max_length=2048, null=True)
    applies_to = models.CharField(max_length=32)

    # Meta

    class Meta:
        abstract = True

    # Methods

    def to_json(self):
        """
        Conver the contents of this flag into a JSON dictionary.
        :return: The contents of this flag as a JSON dictionary.
        """
        attrs = [
            "name",
            "tag",
            "description",
            "flag_type",
            "query",
            "func_name",
            "weight",
            "doc_types",
            "applies_to",
        ]
        return {x: getattr(self, x) for x in attrs}

    # Properties

    @property
    def query_dict(self):
        """
        Get a Python dictionary representing the Elasticsearch query that this flag contains.
        :return: a Python dictionary representing the Elasticsearch query that this flag contains.
        """
        return json.loads(b64decode(self.query))

    # Representation

    def __repr__(self):
        return "<%s - %s (%s weight) (%s)>" % (
            self.__class__.__name__,
            self.name,
            self.weight,
            self.uuid,
        )


class OrganizationFlag(BaseFlag):
    """
    This is a model class for representing a flag that is configured for an organization.
    """

    # Columns

    # Meta

    class Meta:
        unique_together = (
            ("tag", "organization"),
        )

    # Foreign Keys

    organization = models.ForeignKey(
        "rest.Organization",
        related_name="flags",
        on_delete=models.CASCADE,
    )


class DefaultFlag(BaseFlag):
    """
    This is a model class for representing a flag that is one of the defaults provided by Web Sight.
    """

    # Columns

    # Meta
