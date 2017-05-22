# -*- coding: utf-8 -*-
from __future__ import absolute_import


def flag_ip_addresses_outside_of_ranges(org_uuid=None, flag=None, db_session=None):
    """
    Apply the given flag to all of the Elasticsearch data associated with the given organization
    that is collected for IP addresses outside of the ranges defined by the organization.
    :param org_uuid: The UUID of the organization to apply the flag to.
    :param flag: The flag to apply to the organization's data.
    :param db_session: A SQLAlchemy session.
    :return: The Elasticsearch response.
    """
    pass
