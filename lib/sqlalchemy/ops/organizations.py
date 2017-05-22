# -*- coding: utf-8 -*-
from __future__ import absolute_import

import sqlalchemy.exc
from netaddr import IPAddress as NetAddrIPAddress, IPNetwork
import logging

from ..models import Network, OrganizationConfig, Organization, IpAddress, \
    NetworkService, OrganizationNetworkScan, NetworkService, ScanPort, WsUser, WsAuthGroup
from lib import ConversionHelper, DatetimeHelper
from .exception import NoResultFoundError
from .base import update_model_instance, is_unique_constraint_exception

logger = logging.getLogger(__name__)


def create_network_scan_for_organization(db_session=None, org_uuid=None):
    """
    Create a new NetworkScan object, associate it with the given organization, and return it.
    :param db_session: A SQLAlchemy session.
    :param org_uuid: The UUID of the organization to associate the network scan with.
    :return: The newly-created NetworkScan object.
    """
    new_scan = OrganizationNetworkScan.new(
        started_at=DatetimeHelper.now(),
        organization_id=org_uuid,
    )
    db_session.add(new_scan)
    return new_scan


def get_admin_contacts_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the first name and (2) the email address for all administrative users
    associated with the given organization.
    :param org_uuid: The UUID of the organization to get the administrative contacts for.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the first name and (2) the email address for all administrative users
    associated with the given organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    auth_group = db_session.query(WsAuthGroup)\
        .join(Organization, WsAuthGroup.organization_id == Organization.uuid)\
        .filter(Organization.uuid == org_uuid)\
        .filter(WsAuthGroup.name == u"org_admin")\
        .one()
    to_return = []
    for user in auth_group.users:
        to_return.append((user.first_name, user.email))
    return to_return


def get_all_organization_uuids(db_session):
    """
    Get a list containing all of the organization UUIDs in the configured database.
    :param db_session: A SQLAlchemy session.
    :return: A list containing all of the organization UUIDs in the configured database.
    """
    to_return = db_session.query(Organization.uuid).all()
    return [x[0] for x in to_return]


def get_containing_network_uuid_for_organization(org_uuid=None, input_ip_address=None, db_session=None):
    """
    Get the UUID of the Network that contains the given IP address for the given
    organization.
    :param org_uuid: The UUID of the organization to query.
    :param input_ip_address: A string containing an IP address.
    :param db_session: A SQLAlchemy session.
    :return: The UUID of the Network that contains the given IP address for the given
    organization.
    """
    network_tuples = get_network_tuples_for_organization(org_uuid=org_uuid, db_session=db_session)
    ip_address = NetAddrIPAddress(input_ip_address)
    for uuid, net_address, mask_length in network_tuples:
        network = IPNetwork("%s/%s" % (net_address, mask_length))
        if ip_address in network:
            return uuid
    raise NoResultFoundError(
        "No result found for organization %s and address %s." % (org_uuid, input_ip_address)
    )


def get_enabled_network_ranges_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the network and (2) the CIDR mask for all of the networks
    associated with the given Organization that are currently enabled for scanning.
    :param org_uuid: The UUID of the Organization to query.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the network and (2) the CIDR mask for all of the networks
    associated with the given Organization that are currently enabled for scanning.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(Network.address, Network.mask_length) \
        .filter(Network.organization_id == org_uuid) \
        .filter(Network.scanning_enabled == True) \
        .filter(Network.added_by == "user") \
        .all()


def get_endpoint_information_for_org_network_service(service_uuid=None, db_session=None):
    """
    Get a tuple containing (1) the IP address, (2) the port, and (3) the protocol for the given
    NetworkService
    :param service_uuid: The NetworkService UUID to retrieve data for.
    :param db_session: A SQLAlchemy session.
    :return: A tuple containing (1) the IP address, (2) the port, and (3) the protocol for the given
    NetworkService
    """
    service_uuid = ConversionHelper.string_to_unicode(service_uuid)
    result = db_session.query(
        IpAddress.address,
        NetworkService.port,
        NetworkService.protocol,
    )\
        .join(NetworkService, NetworkService.ip_address_id == IpAddress.uuid)\
        .filter(NetworkService.uuid == service_uuid)\
        .one()
    return tuple(result)


def get_ip_address_from_org_network(
        network_uuid=None,
        address=None,
        address_type=None,
        db_session=None,
):
    """
    Get the IpAddress from the referenced Network matching the given address
    and address type.
    :param network_uuid: The UUID of the network to retrieve the IP address from.
    :param address: The IP address.
    :param address_type: The IP address type.
    :param db_session: A SQLAlchemy session.
    :return: The IpAddress from the referenced Network matching the given address
    and address type.
    """
    network_uuid = ConversionHelper.string_to_unicode(network_uuid)
    address = ConversionHelper.string_to_unicode(address)
    address_type = ConversionHelper.string_to_unicode(address_type)
    return db_session.query(IpAddress)\
        .filter(IpAddress.address == address)\
        .filter(IpAddress.address_type == address_type)\
        .filter(IpAddress.network_id == network_uuid)\
        .one()


def get_network_ranges_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the network and (2) the CIDR mask for all of the networks
    associated with the given Organization.
    :param org_uuid: The UUID of the Organization to query.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the network and (2) the CIDR mask for all of the networks
    associated with the given Organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(Network.address, Network.mask_length) \
        .filter(Network.organization_id == org_uuid) \
        .all()


def get_network_scan_interval_for_organization(org_uuid=None, db_session=None):
    """
    Get the amount of time in seconds that tasks should wait before running network scans against
    an organization again.
    :param org_uuid: The UUID of the organization to retrieve the interval for.
    :param db_session: A SQLAlchemy session.
    :return: The amount of time in seconds that tasks should wait before running network scans against
    an organization again.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    to_return = db_session.query(OrganizationConfig.network_scan_interval)\
        .filter(OrganizationConfig.organization_id == org_uuid)\
        .one()
    return to_return[0]


def get_network_service_from_org_ip(
        ip_uuid=None,
        port=None,
        protocol=None,
        db_session=None,
):
    """
    Get the NetworkService from the referenced IpAddress matching the given port
    and protocol.
    :param ip_uuid:
    :param port:
    :param protocol:
    :param db_session:
    :return: The NetworkService from the referenced IpAddress matching the given port
    and protocol.
    """
    ip_uuid = ConversionHelper.string_to_unicode(ip_uuid)
    protocol = ConversionHelper.string_to_unicode(protocol)
    return db_session.query(NetworkService)\
        .filter(NetworkService.protocol == protocol)\
        .filter(NetworkService.port == port)\
        .filter(NetworkService.ip_address_id == ip_uuid)\
        .one()


def get_network_service_scan_interval_for_organization(org_uuid=None, db_session=None):
    """
    Get the amount of time in seconds that tasks should wait before investigating the state
    of a network service again for the specified organization.
    :param org_uuid: The UUID of the organization to retrieve the interval for.
    :param db_session: A SQLAlchemy session.
    :return: The amount of time in seconds that tasks should wait before investigating the state
    of a network service again for the specified organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    to_return = db_session.query(OrganizationConfig.network_service_scan_interval)\
        .filter(OrganizationConfig.organization_id == org_uuid)\
        .one()
    return to_return[0]


def get_network_tuples_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the UUID, (2) the address, and (3) the mask length for all of
    the networks owned by the given organization.
    :param org_uuid: The UUID of the organization to query.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the UUID, (2) the address, and (3) the mask length for
    all of the networks owned by the given organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(
        Network.uuid,
        Network.address,
        Network.mask_length,
    )\
        .filter(Network.organization_id == org_uuid)\
        .all()


def get_networks_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of all the Network objects owned by the given Organization.
    :param org_uuid: The UUID of the Organization to retrieve networks for.
    :param db_session: A SQLAlchemy session.
    :return: A list of all the Network objects owned by the given Organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(Network)\
        .filter(Network.organization_id == org_uuid)\
        .all()


def get_organization_by_uuid(org_uuid=None, db_session=None):
    """
    Get the organization referenced by the given UUID if such an organization exists, otherwise None.
    :param org_uuid: The UUID of the organization to retrieve.
    :param db_session: A SQLAlchemy session.
    :return: The organization referenced by the given UUID if such an organization exists,
    otherwise None.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(Organization)\
        .filter(Organization.uuid == org_uuid)\
        .one_or_none()


def get_org_ip_address_monitoring_status(ip_uuid=None, db_session=None, with_for_update=False):
    """
    Get whether or not the given IpAddress is currently being monitored.
    :param ip_uuid: The UUID of the IpAddress to query.
    :param db_session: A SQLAlchemy session.
    :param with_for_update: Whether or not to include a FOR UPDATE clause in the query.
    :return: Whether or not the given IpAddress is currently being monitored.
    """
    ip_uuid = ConversionHelper.string_to_unicode(ip_uuid)
    query = db_session.query(IpAddress.is_monitored)\
        .filter(IpAddress.uuid == ip_uuid)
    if with_for_update:
        query = query.with_for_update()
    results = query.one()
    return results[0]


def get_org_network_service_monitoring_status(service_uuid=None, db_session=None, with_for_update=False):
    """
    Get whether or not the given NetworkService is currently being monitored.
    :param service_uuid: The UUID of the NetworkService to query.
    :param db_session: A SQLAlchemy session.
    :param with_for_update: Whether or not to include a FOR UPDATE clause in the query.
    :return: Whether or not the given NetworkService is currently being monitored.
    """
    service_uuid = ConversionHelper.string_to_unicode(service_uuid)
    query = db_session.query(NetworkService.is_monitored)\
        .filter(NetworkService.uuid == service_uuid)
    if with_for_update:
        query = query.with_for_update()
    results = query.one()
    return results[0]


def get_or_create_ip_address_from_org_network(
        network_uuid=None,
        address=None,
        address_type=None,
        db_session=None,
):
    """
    Get an IpAddress from the given network matching the given address and address_type if
    such an IP address record exists. If it does not, create it. This method makes use of a database unique
    constraint to address race conditions.
    :param network_uuid: The UUID of the network to retrieve the IP address from.
    :param address: The IP address.
    :param address_type: The IP address type.
    :param db_session: A SQLAlchemy session.
    :return: An IpAddress for the given network with the given address and address type.
    """
    network_uuid = ConversionHelper.string_to_unicode(network_uuid)
    address = ConversionHelper.string_to_unicode(address)
    address_type = ConversionHelper.string_to_unicode(address_type)
    new_ip_address = IpAddress.new(
        network_id=network_uuid,
        address=address,
        address_type=address_type,
        is_monitored=False,
        scanning_status=False,
    )
    try:
        db_session.add(new_ip_address)
        db_session.commit()
        return new_ip_address
    except sqlalchemy.exc.IntegrityError as e:
        if not is_unique_constraint_exception(e):
            raise e
        db_session.rollback()
        return get_ip_address_from_org_network(
            network_uuid=network_uuid,
            address=address,
            address_type=address_type,
            db_session=db_session,
        )


def get_or_create_network_service_from_org_ip(
        ip_uuid=None,
        port=None,
        protocol=None,
        db_session=None,
        discovered_by="network scan",
):
    """
    Get an NetworkService from the given IpAddress matching the given port and
    protocol if such an IP address object exists. If it does not, create and return it. This method makes
    use of the database unique constraint to address race conditions.
    :param ip_uuid: The UUID of the IpAddress to query.
    :param port: The port to query.
    :param protocol: The protocol to query.
    :param db_session: A SQLAlchemy session.
    :param discovered_by: How the network service was discovered.
    :return: An IpAddress for the given port, protocol, and IpAddress.
    """
    ip_uuid = ConversionHelper.string_to_unicode(ip_uuid)
    protocol = ConversionHelper.string_to_unicode(protocol)
    new_network_service = NetworkService.new(
        ip_address_id=ip_uuid,
        port=port,
        protocol=protocol,
        is_monitored=False,
        scanning_status=False,
        discovered_by=discovered_by,
    )
    try:
        db_session.add(new_network_service)
        db_session.commit()
        return new_network_service
    except sqlalchemy.exc.IntegrityError as e:
        if not is_unique_constraint_exception(e):
            raise e
        db_session.rollback()
        return get_network_service_from_org_ip(
            ip_uuid=ip_uuid,
            port=port,
            protocol=protocol,
            db_session=db_session,
        )


def get_ports_to_scan_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the port number and (2) the protocol to scan for all
    ports that should be scanned for the given organization.
    :param org_uuid: The UUID of the organization to retrieve ports for.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the port number and (2) the protocol to scan for all
    ports that should be scanned for the given organization.
    """
    results = db_session.query(ScanPort.port_number, ScanPort.protocol)\
        .join(Organization, ScanPort.organization_id == Organization.uuid)\
        .filter(Organization.uuid == org_uuid)\
        .all()
    return [tuple(x) for x in results]


def get_tcp_scan_ports_for_org(org_uuid=None, db_session=None):
    """
    Get a list of integers representing the TCP ports configured to be scanned for the given
    organization.
    :param org_uuid: The UUID of the organization to retrieve ports for.
    :param db_session: A SQLAlchemy session.
    :return: A list of integers representing the TCP ports configured to be scanned for the given
    organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    results = db_session.query(ScanPort.port_number)\
        .filter(ScanPort.protocol == u"tcp")\
        .filter(ScanPort.included == True)\
        .filter(ScanPort.organization_id == org_uuid)\
        .all()
    return [x[0] for x in results]


def get_udp_scan_ports_for_org(org_uuid=None, db_session=None):
    """
    Get a list of integers representing the UDP ports configured to be scanned for the given
    organization.
    :param org_uuid: The UUID of the organization to retrieve ports for.
    :param db_session: A SQLAlchemy session.
    :return: A list of integers representing the UDP ports configured to be scanned for the given
    organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    results = db_session.query(ScanPort.port_number)\
        .filter(ScanPort.protocol == u"udp")\
        .filter(ScanPort.included == True)\
        .filter(ScanPort.organization_id == org_uuid)\
        .all()
    return [x[0] for x in results]


def update_network_scan(scan_uuid=None, update_dict=None, db_session=None):
    """
    Update the referenced NetworkScan via the contents of the given dictionary.
    :param scan_uuid: The UUID of the NetworkScan to update.
    :param update_dict: A dictionary containing key-value pairs to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=OrganizationNetworkScan,
        model_uuid=scan_uuid,
        update_dict=update_dict,
    )


def update_network_scan_completed(scan_uuid=None, db_session=None):
    """
    Update the given NetworkScan to reflect that scanning has concluded.
    :param scan_uuid: The UUID of the NetworkScan to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "ended_at": DatetimeHelper.now()
    }
    update_network_scan(scan_uuid=scan_uuid, update_dict=update_dict, db_session=db_session)


def update_org_ip_address(ip_uuid=None, update_dict=None, db_session=None):
    """
    Update the given IpAddress with the given fields.
    :param ip_uuid: The UUID of the IpAddress to update.
    :param update_dict: A dictionary containing key-value pairs to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=IpAddress,
        model_uuid=ip_uuid,
        update_dict=update_dict,
    )


def update_org_ip_address_monitoring_state(ip_uuid=None, state=None, db_session=None):
    """
    Update the given IpAddress's current monitoring status.
    :param ip_uuid: The UUID of the IpAddress to update.
    :param state: The state to set.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "is_monitored": state,
    }
    update_org_ip_address(
        ip_uuid=ip_uuid,
        update_dict=update_dict,
        db_session=db_session,
    )


def update_org_network_service(service_uuid=None, update_dict=None, db_session=None):
    """
    Update the given NetworkService with the given fields.
    :param service_uuid: The UUID of the NetworkService to update.
    :param update_dict: A dictionary containing key-value pairs to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=NetworkService,
        model_uuid=service_uuid,
        update_dict=update_dict,
    )


def update_org_network_service_monitoring_state(service_uuid=None, state=None, db_session=None):
    """
    Update the given NetworkService's current monitoring status.
    :param service_uuid: The UUID of the NetworkService to update.
    :param state: The state to set.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "is_monitored": state,
    }
    update_org_network_service(
        service_uuid=service_uuid,
        update_dict=update_dict,
        db_session=db_session,
    )
