# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
from base64 import b64decode

from lib.sqlalchemy import DefaultFlag, OrganizationFlag
from ..helper import ElasticsearchHelper


class DataFlagger(object):
    """
    This is a class that handles the application of a flag's contents to Elasticsearch
    data.
    """

    # Class Members

    # Instantiation

    def __init__(self, flag):
        self._flag = flag
        self._filters = []

    # Static Methods

    @staticmethod
    def from_flag_uuid(flag_uuid=None, db_session=None, flag_type=None):
        """
        Create and return a DataFlagger based on the contents of the given flag.
        :param flag_uuid: The UUID of the flag to retrieve.
        :param db_session: A SQLAlchemy session.
        :param flag_type: The type of flag that flag_uuid is related to.
        :return: A newly-created DataFlagger wrapping the given flag.
        """
        if flag_type == "default":
            flag = DefaultFlag.by_uuid(db_session=db_session, uuid=flag_uuid)
        else:
            flag = OrganizationFlag.by_uuid(db_session=db_session, uuid=flag_uuid)
        return DataFlagger(flag)

    # Class Methods

    # Public Methods

    def apply_flag_to_organization(self, org_uuid=None, db_session=None):
        """
        Apply the flag that this class contains to the given organization.
        :param org_uuid: The UUID of the organization to apply the flag to.
        :param db_session: A SQLAlchemy session.
        :return: The Elasticsearch response.
        """
        helper = ElasticsearchHelper.instance()
        query_dict = self.__get_query_dictionary_with_filters()
        return helper.connection.update_by_query(
            index=org_uuid,
            doc_type=self.flag.doc_types,
            body=query_dict,
        )

    def filter_by_ip_address_scan(self, ip_address_scan_uuid):
        """
        Filter the data that will be updated by this flagger to only those results gathered during
        the given IP address scan.
        :param ip_address_scan_uuid: The UUID of the IP address scan to filter the update on.
        :return: None
        """
        self._filters.append({
            "must": {
                "term": {
                    "ip_address_scan_uuid": ip_address_scan_uuid,
                }
            }
        })

    def filter_by_network_service_scan(self, network_service_scan_uuid):
        """
        Filter the data that will be updated by this flagger to only those results gathered during
        the given network service scan.
        :param network_service_scan_uuid: The UUID of the network service scan to filter the update on.
        :return: None
        """
        self._filters.append({
            "must": {
                "term": {
                    "network_service_scan_uuid": network_service_scan_uuid,
                }
            }
        })

    def filter_by_web_service_scan(self, web_service_scan_uuid):
        """
        Filter the data that will be updated by this flagger to only those results gathered during the
        given web service scan.
        :param web_service_scan_uuid: The UUID of the web service scan to filter the update on.
        :return: None
        """
        self._filters.append({
            "must": {
                "term": {
                    "web_service_scan_uuid": web_service_scan_uuid,
                }
            }
        })

    # Protected Methods

    # Private Methods

    def __get_flag_dictionary(self):
        """
        Get a dictionary that represents the data associated with self.flag that is associated with
        Elasticsearch documents.
        :return: A dictionary that represents the data associated with self.flag that is associated with
        Elasticsearch documents.
        """
        return {
            "flag_name": self.flag.name,
            "flag_tag": self.flag.tag,
            "flag_weight": self.flag.weight,
        }

    def __get_query_dictionary(self):
        """
        Get a dictionary representing the Elasticsearch query that this flagger is configured to run.
        :return: A dictionary representing the Elasticsearch query that this flagger is configured to run.
        """
        return {
            "query": self.flag_query_dictionary,
            "script": self.__get_script_dictionary(),
        }

    def __get_query_dictionary_with_filters(self):
        """
        Get the query dictionary to use for the update clause with all of the filters found in self.filters
        applied.
        :return: The query dictionary to use for the update clause with all of the filters found in self.filters
        applied.
        """
        to_return = self.__get_query_dictionary()
        for cur_filter in self.filters:
            filter_type = cur_filter.keys()[0]
            if filter_type not in to_return["query"]["bool"]:
                to_return["query"]["bool"][filter_type] = []
            to_return["query"]["bool"][filter_type].append(cur_filter[filter_type])
        return to_return

    def __get_script_dictionary(self):
        """
        Get a dictionary representing the script Elasticsearch query component that this flagger uses to add
        the flag to relevant data.
        :return: A dictionary representing the script Elasticsearch query component that this flagger uses to add
        the flag to relevant data.
        """
        return {
            "inline": "if (ctx._source.containsKey(\"flags\") && ctx._source.flags != null) { ctx._source.flags.add(params.new_flag); } else { ctx._source.flags = [params.new_flag]; }",
            "lang": "painless",
            "params": {
                "new_flag": self.__get_flag_dictionary(),
            }
        }

    # Properties

    @property
    def filters(self):
        """
        Get a list of filter dictionaries that will be applied to the update.
        :return: a list of filter dictionaries that will be applied to the update.
        """
        return self._filters

    @property
    def flag(self):
        """
        Get the flag that this class is intended to apply.
        :return: the flag that this class is intended to apply.
        """
        return self._flag

    @property
    def flag_query_dictionary(self):
        """
        Get a dictionary representing the query components contained within self.flag.
        :return: a dictionary representing the query components contained within self.flag.
        """
        return json.loads(b64decode(self.flag.query))

    @property
    def query_dictionary(self):
        """
        Get a dictionary representing the Elasticsearch query dictionary that will apply this flag to
        collected data.
        :return: a dictionary representing the Elasticsearch query dictionary that will apply this flag to
        collected data.
        """
        return self.__get_query_dictionary()

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (
            self.__class__.__name__,
            self.flag.name,
            self.flag.uuid,
        )

