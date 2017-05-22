# -*- coding: utf-8 -*-
from __future__ import absolute_import

from netaddr import IPNetwork

from lib import ValidationHelper, IPBlacklist
from lib.exception import ValidationError
from .base import BaseUploadWrapper
from ..base import BaseWrapper
from ..network import CidrRangeWrapper


class NetworksCsvWrapper(BaseUploadWrapper):
    """
    This is a wrapper class for CSV files uploaded by Web Sight users that contain information about
    network ranges.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._rows = None
        self._errored_rows = None
        super(NetworksCsvWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    def get_new_networks_for_organization(self, organization):
        """
        Get a tuple containing (1) a list of NetworkSerializer objects for all of the network ranges contained
        within the wrapped CSV file that are not already represented for the organization, (2) a list of the rows
        that were excluded as they are already represented within the organization, (3) a list of the rows that
        were blacklisted, and (4) a list of the rows that were invalid.
        :param organization: The organization to analyze.
        :return: A tuple containing (1) a list of NetworkSerializer objects for all of the network ranges contained
        within the wrapped CSV file that are not already represented for the organization, (2) a list of the rows
        that were excluded as they are already represented within the organization, (3) a list of the rows that
        were blacklisted, and (4) a list of the rows that were invalid.
        """
        from rest.models import Network
        existing_networks = []
        for network in organization.networks.all():
            existing_networks.append((
                network.uuid,
                network.name,
                IPNetwork("%s/%s" % (network.address, network.mask_length)),
            ))
        new_rows = []
        skipped_rows = []
        for row in self.valid_rows:
            row_network = IPNetwork(row.cidr_range)
            if any([row_network in network for uuid, name, network in existing_networks]):
                skipped_rows.append(row)
            else:
                new_rows.append(row)
        new_networks = []
        for row in new_rows:
            new_networks.append(Network.objects.create(
                organization=organization,
                name=row.name,
                mask_length=row.mask_length,
                address=row.address,
            ))
        return new_networks, skipped_rows, self.blacklisted_rows, self.errored_rows

    # Protected Methods

    def _process_data(self):
        valid_rows = []
        invalid_rows = []
        for line in [x.strip() for x in self.wrapped_data.strip().split("\n")]:
            try:
                valid_rows.append(NetworksCsvRowWrapper(line))
            except ValidationError:
                invalid_rows.append(line)
        self._rows = valid_rows
        self._errored_rows = invalid_rows

    # Private Methods

    # Properties

    @property
    def blacklisted_rows(self):
        """
        Get a list containing all of the networks found in the CSV file that are blacklisted.
        :return: a list containing all of the networks found in the CSV file that are blacklisted.
        """
        return filter(lambda x: x.is_blacklisted, self.rows)

    @property
    def errored_rows(self):
        """
        Get a list containing all of the rows in self.wrapped_data that did not pass validation.
        :return: a list containing all of the rows in self.wrapped_data that did not pass validation.
        """
        return self._errored_rows

    @property
    def rows(self):
        """
        Get a list of NetworksCsvRowWrappers wrapping all of the rows found in the wrapped CSV file.
        :return: a list of NetworksCsvRowWrappers wrapping all of the rows found in the wrapped CSV file.
        """
        return self._rows

    @property
    def valid_rows(self):
        """
        Get a list containing all of the networks found in the CSV file that are valid.
        :return: A list containing all of the networks found in the CSV file that are valid.
        """
        return filter(lambda x: x.is_valid, self.rows)

    @property
    def wrapped_type(self):
        return "Networks CSV File"

    # Representation and Comparison


class NetworksCsvRowWrapper(BaseWrapper):
    """
    This is a wrapper class for wrapping individual CSV rows contained within NetworksCsvWrapper bodies.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(NetworksCsvRowWrapper, self).__init__(*args, **kwargs)
        self._name = None
        self._name_retrieved = False
        self._address = None
        self._mask_length = None
        self._parsed_address = None
        self._is_blacklisted = None

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _validate_data(self):
        ValidationHelper.validate_networks_csv_row(self.wrapped_data)

    # Private Methods

    # Properties

    @property
    def address(self):
        """
        Get the network address associated with this network CSV row.
        :return: the network address associated with this network CSV row.
        """
        if self._address is None:
            if self.row_type == "double":
                row_split = self.wrapped_data.split(",")
                address_segment = row_split[1].strip()
                self._address = address_segment[:address_segment.find("/")]
            elif self.row_type == "triple":
                row_split = self.wrapped_data.split(",")
                self._address = row_split[1].strip()
            else:
                raise ValueError(
                    "Unsure how to parse address out of row type %s."
                    % (self.row_type,)
                )
        return self._address

    @property
    def cidr_range(self):
        """
        Get a string representing the CIDR range that this entry contains.
        :return: a string representing the CIDR range that this entry contains.
        """
        return "%s/%s" % (self.parsed_address, self.mask_length)

    @property
    def is_blacklisted(self):
        """
        Get whether or not the CIDR range represented by this networks CSV row is blacklisted.
        :return: whether or not the CIDR range represented by this networks CSV row is blacklisted.
        """
        if self._is_blacklisted is None:
            blacklist = IPBlacklist.instance()
            self._is_blacklisted = blacklist.is_cidr_range_blacklisted(self.cidr_range)
        return self._is_blacklisted

    @property
    def is_valid(self):
        """
        Get whether or not the contents of this CSV row are valid for use as a network in the
        Web Sight back-end system.
        :return: whether or not the contents of this CSV row are valid for use as a network in
        the Web Sight back-end system.
        """
        return not self.is_blacklisted

    @property
    def mask_length(self):
        """
        Get the length of the network mask associated with this network CSV row.
        :return: the length of the network mask associated with this network CSV row.
        """
        if self._mask_length is None:
            if self.row_type == "double":
                row_split = self.wrapped_data.split(",")
                address_segment = row_split[1].strip()
                self._mask_length = int(address_segment[address_segment.find("/") + 1:])
            elif self.row_type == "triple":
                row_split = self.wrapped_data.split(",")
                self._mask_length = int(row_split[2].strip())
            else:
                raise ValueError(
                    "Unsure how to parse mask length out of row type %s."
                    % (self.row_type,)
                )
        return self._mask_length

    @property
    def name(self):
        """
        Get the name associated with the network depicted by this CSV row.
        :return: the name associated with the network depicted by this CSV row.
        """
        if not self._name_retrieved:
            row_split = self.wrapped_data.split(",")
            name_segment = row_split[0].strip()
            if name_segment == "":
                self._name = None
            else:
                self._name = name_segment
            self._name_retrieved = True
        return self._name

    @property
    def parsed_address(self):
        """
        Get an instance of self.address that is masked out by self.mask_length.
        :return: an instance of self.address that is masked out by self.mask_length.
        """
        if self._parsed_address is None:
            cidr_wrapper = CidrRangeWrapper.from_cidr_range(address=self.address, mask_length=self.mask_length)
            self._parsed_address = cidr_wrapper.parsed_address
        return self._parsed_address

    @property
    def row_type(self):
        """
        Get the type of row that this wrapper contains.
        :return: the type of row that this wrapper contains.
        """
        if self.wrapped_data.count(",") == 1:
            return "double"
        elif self.wrapped_data.count(",") == 2:
            return "triple"
        else:
            raise ValueError(
                "A total of %s commas were found in row - unsure how to proceed."
                % (self.wrapped_data.count(","),)
            )

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.cidr_range)
