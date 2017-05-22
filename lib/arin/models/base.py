# -*- coding: utf-8 -*-
from __future__ import absolute_import


class BaseArinResourceModel(object):
    """
    This is a base class for all resource types returned by the ARIN API.
    """

    # Class Members

    # Instantiation

    # Static Methods

    def __init__(self, resource):
        self._resource = resource

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_attribute(self, key):
        """
        Get the given attribute from self.resource by the given key.
        :param key: The key to retrieve.
        :return: The value associated with key if such a value exists in self.resource, otherwise None.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def handle(self):
        """
        Get the handle associated with this organization.
        :return: the handle associated with this organization.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def name(self):
        """
        Get the name of this organization.
        :return: the name of this organization.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def ref(self):
        """
        Get the URL to request to retrieve full details about this resource.
        :return: the URL to request to retrieve full details about this resource.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def resource(self):
        """
        Get the JSON object that this model class is currently wrapping.
        :return: the JSON object that this model class is currently wrapping.
        """
        return self._resource

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.name, self.ref)


class BaseArinSummaryResourceModel(BaseArinResourceModel):
    """
    This is a base class for resource models that provide summary details (ie: are returned in a list).
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_attribute(self, key):
        return self.resource.get(key, None)

    # Private Methods

    # Properties

    @property
    def handle(self):
        return self._get_attribute("@handle")

    @property
    def name(self):
        return self._get_attribute("@name")

    @property
    def ref(self):
        return self._get_attribute("$")

    # Representation and Comparison


class BaseArinDetailResourceModel(BaseArinResourceModel):
    """
    This is a base class for resource models that provide summary details (ie: are returned one at a time).
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_attribute(self, key):
        to_return = self.resource.get(key, None)
        if to_return is not None:
            return to_return.get("$", None)
        else:
            return None

    # Private Methods

    # Properties

    @property
    def handle(self):
        return self._get_attribute("handle")

    @property
    def name(self):
        return self._get_attribute("name")

    @property
    def ref(self):
        return self._get_attribute("ref")

    # Representation and Comparison
