# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWrapper


class CidrRangeWrapper(BaseWrapper):
    """
    This class contains functionality for wrapping a network CIDR range.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(CidrRangeWrapper, self).__init__(*args, **kwargs)
        self._address = None
        self._mask_length = None
        self._parsed_octets = None

    # Static Methods

    # Class Methods

    @classmethod
    def from_cidr_range(cls, address=None, mask_length=None):
        """
        Create and return a new CidrRangeWrapper based on the given address and mask length.
        :param address: The address that serves as the base of the range.
        :param mask_length: The length of the CIDR mask.
        :return: A new CidrRangeWrapper wrapping the contents fo the given arguments.
        """
        return CidrRangeWrapper("%s/%s" % (address, mask_length))

    # Public Methods

    # Protected Methods

    # Private Methods

    def __get_parsed_octets(self):
        """
        Get a list of integers representing the octets contained within the given
        CIDR range. Note that these octets will reflect the mask length, and will
        zero out any of the initial range's data that is masked out.
        :return: a list of integers representing the octets contained within the
        given CIDR range. Note that these octets will reflect the mask length,
        and will zero out any of the initial range's data that is masked out.
        """
        address_split = self.address.split(".")
        cur_mask_size = self.mask_length
        to_return = []
        for octet in address_split:
            if cur_mask_size >= 8:
                to_return.append(int(octet))
            else:
                shift_length = 8 - cur_mask_size
                to_return.append(int(octet) >> shift_length << shift_length)
            cur_mask_size = max(cur_mask_size - 8, 0)
        return to_return

    # Properties

    @property
    def address(self):
        """
        Get the address base contained within the CIDR ranges.
        :return: the address base contained within the CIDR ranges.
        """
        if self._address is None:
            self._address = self.wrapped_data[:self.wrapped_data.find("/")]
        return self._address

    @property
    def mask_length(self):
        """
        Get the length of the CIDR mask for the wrapped range.
        :return: The length of the CIDR mask for the wrapped range.
        """
        if self._mask_length is None:
            self._mask_length = int(self.wrapped_data[self.wrapped_data.find("/")+1:])
        return self._mask_length

    @property
    def parsed_address(self):
        """
        Get a string representing the contents of self.address masked out to the length
        of self.mask_length.
        :return: a string representing the contents of self.address masked out to the
        length of self.mask_length.
        """
        return ".".join([str(x) for x in self.parsed_octets])

    @property
    def parsed_cidr_range(self):
        """
        Get a string representing this CIDR range with the proper mask applied.
        :return: a string representing this CIDR range with the proper mask applied.
        """
        return "%s/%s" % (self.parsed_address, self.mask_length)

    @property
    def parsed_octets(self):
        """
        Get a list of integers representing the octets contained within the given
        CIDR range. Note that these octets will reflect the mask length, and will
        zero out any of the initial range's data that is masked out.
        :return: a list of integers representing the octets contained within the
        given CIDR range. Note that these octets will reflect the mask length,
        and will zero out any of the initial range's data that is masked out.
        """
        if self._parsed_octets is None:
            self._parsed_octets = self.__get_parsed_octets()
        return self._parsed_octets

    @property
    def wrapped_type(self):
        return "CIDR Range"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.parsed_cidr_range)

