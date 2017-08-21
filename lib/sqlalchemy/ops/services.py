# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import ConversionHelper, DatetimeHelper
from lib.sqlalchemy import NetworkServiceScan, NetworkService, Organization, IpAddress, Network
from .base import update_model_instance


#TESTME
def create_new_network_service_scan(network_service_uuid=None, db_session=None):
    """
    Create and return a new NetworkServiceScan object and ensure that it's related to the
    given NetworkService.
    :param network_service_uuid: The UUID of the NetworkService to associate the NetworkServiceScan with.
    :param db_session: A SQLAlchemy session.
    :return: The newly-created NetworkServiceScan.
    """
    network_service_uuid = ConversionHelper.string_to_unicode(network_service_uuid)
    to_return = NetworkServiceScan.new(
        network_service_id=network_service_uuid,
        started_at=DatetimeHelper.now(),
    )
    db_session.add(to_return)
    return to_return


def get_latest_network_service_scan_uuids_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of all of the most recent network service scans for the given organization.
    :param org_uuid: The UUID of the organization to retrieve network service scans for.
    :param db_session: A SQLAlchemy session.
    :return: A list of all of the most recent network service scans for the given organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    results = db_session.query(NetworkServiceScan.uuid, NetworkServiceScan.ended_at)\
        .join(NetworkService, NetworkServiceScan.network_service_id == NetworkService.uuid)\
        .join(IpAddress, NetworkService.ip_address_id == IpAddress.uuid)\
        .join(Network, IpAddress.network_id == Network.uuid)\
        .join(Organization, Network.organization_id == Organization.uuid)\
        .filter(Organization.uuid == org_uuid)\
        .filter(NetworkServiceScan.ended_at != None)\
        .all()
    to_return = {}
    for scan_uuid, scan_ended_time in results:
        if scan_uuid not in to_return:
            to_return[scan_uuid] = scan_ended_time
        else:
            if scan_ended_time > to_return[scan_uuid]:
                to_return[scan_uuid] = scan_ended_time
    return to_return.keys()


def get_protocol_from_network_service(network_service_uuid=None, db_session=None):
    """
    Get the protocol associated with the given network service.
    :param network_service_uuid: The UUID of the NetworkService to query.
    :param db_session: A SQLAlchemy session.
    :return: The protocol associated with the given network service.
    """
    network_service_uuid = ConversionHelper.string_to_unicode(network_service_uuid)
    result = db_session.query(NetworkService.protocol)\
        .filter(NetworkService.uuid == network_service_uuid)\
        .one()
    return result[0]


def get_related_uuids_from_network_service_scan(network_service_scan_uuid=None, db_session=None):
    """
    Get a tuple containing (1) the organization UUID and (2) the network service UUID for the
    given network service scan.
    :param network_service_scan_uuid: The UUID of the network service scan to query.
    :param db_session: A SQLAlchemy session.
    :return: A tuple containing (1) the organization UUID and (2) the network service UUID for the
    given network service scan.
    """
    network_service_scan_uuid = ConversionHelper.string_to_unicode(network_service_scan_uuid)
    result = db_session.query(NetworkServiceScan.uuid, Organization.uuid, NetworkService.uuid)\
        .join(NetworkService, NetworkServiceScan.network_service_id == NetworkService.uuid)\
        .join(IpAddress, NetworkService.ip_address_id == IpAddress.uuid)\
        .join(Network, IpAddress.network_id == Network.uuid)\
        .join(Organization, Network.organization_id == Organization.uuid)\
        .filter(NetworkServiceScan.uuid == network_service_scan_uuid)\
        .one()
    return result[1], result[2]


def update_network_service_scan(scan_uuid=None, update_dict=None, db_session=None):
    """
    Update the given Scan with the given fields.
    :param scan_uuid: The UUID of the NetworkServiceScan to update.
    :param update_dict: A dictionary containing key-value pairs to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=NetworkServiceScan,
        model_uuid=scan_uuid,
        update_dict=update_dict,
    )


#TESTME
def update_network_service_scan_completed(scan_uuid=None, db_session=None):
    """
    Update the given NetworkServiceScan to reflect that scanning has concluded.
    :param scan_uuid: The UUID of the NetworkServiceScan to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "ended_at": DatetimeHelper.now()
    }
    update_network_service_scan(scan_uuid=scan_uuid, update_dict=update_dict, db_session=db_session)
