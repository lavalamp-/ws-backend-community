# -*- coding: utf-8 -*-
from __future__ import absolute_import

from sqlalchemy import func
import sqlalchemy.exc

from ..models import Network, IpAddress, NetworkService, NetworkServiceScan, Organization, IpAddressScan
from lib import ConversionHelper, RandomHelper, ConfigManager, DatetimeHelper
from lib.parsing import CidrRangeWrapper
from .exception import NoResultFoundError
from .organizations import get_containing_network_uuid_for_organization, get_or_create_ip_address_from_org_network
from .base import update_model_instance, is_unique_constraint_exception

config = ConfigManager.instance()


#TESTME
def check_network_service_scanning_status(db_session=None, service_uuid=None, update_status=True):
    """
    Check to see whether or not the given network service is currently being scanned. If it is not, then
    modify it to show that it is. Return a boolean depicting whether or not scanning code should proceed
    with scanning the given network service.
    :param db_session: A SQLAlchemy session.
    :param service_uuid: The UUID of the network service in question.
    :param update_status: Whether or not to update the current scanning state of the network service.
    :return: True if scanning should be performed for the given network service, False otherwise.
    """
    db_session.execute("begin;")
    current_scanning_status = get_network_service_scanning_status(
        db_session=db_session,
        service_uuid=service_uuid,
        with_for_update=True,
    )
    if current_scanning_status:
        db_session.execute("end;")
        return False
    last_completed_scan = get_last_completed_network_service_scan(
        db_session=db_session,
        service_uuid=service_uuid,
    )
    if not last_completed_scan or not config.task_enforce_network_service_scan_interval:
        do_scan = True
    else:
        now = DatetimeHelper.now().replace(tzinfo=last_completed_scan.tzinfo)
        elapsed_seconds = (now - last_completed_scan.ended_at).total_seconds()
        if elapsed_seconds > config.task_minimum_network_service_scan_interval:
            do_scan = True
        else:
            do_scan = False
    if do_scan and update_status:
        update_network_service_scanning_status(status=True, service_uuid=service_uuid, db_session=db_session)
        db_session.commit()
    db_session.execute("end;")
    return do_scan


#TESTME
def check_ip_address_scanning_status(db_session=None, ip_address_uuid=None, update_status=True):
    """
    Check to see whether the given IP address is currently being scanned. If it is not, then modify it to
    show that it is. Return a boolean depicting whether or not scanning should proceed for the given IP
    address.
    :param db_session: A SQLAlchemy session.
    :param ip_address_uuid: The UUID of the IP address in question.
    :param update_status: Whether or not to update the IP address' scanning status.
    :return: True if scanning should be performed for the given IP address, False otherwise.
    """
    db_session.execute("begin;")
    current_scanning_status = get_ip_address_scanning_status(
        db_session=db_session,
        ip_address_uuid=ip_address_uuid,
        with_for_update=True,
    )
    if current_scanning_status:
        db_session.execute("end;")
        return False
    last_completed_scan = get_last_completed_ip_address_scan(db_session=db_session, ip_address_uuid=ip_address_uuid)
    if not last_completed_scan or not config.task_enforce_ip_address_scan_interval:
        do_scan = True
    else:
        now = DatetimeHelper.now().replace(tzinfo=last_completed_scan.ended_at.tzinfo)
        elapsed_seconds = (now - last_completed_scan.ended_at).total_seconds()
        if elapsed_seconds > config.task_minimum_ip_address_scan_interval:
            do_scan = True
        else:
            do_scan = False
    if do_scan and update_status:
        update_ip_address_scanning_status(db_session=db_session, ip_address_uuid=ip_address_uuid, scanning_status=True)
        db_session.commit()
    db_session.execute("end;")
    return do_scan


#TESTME
def create_ip_address_scan_for_ip(ip_address_uuid):
    """
    Create and return a new IP address scan associated with the given IP address.
    :param ip_address_uuid: The UUID of the IP address to associate the scan with.
    :return: A newly-created IP address scan associated with the given IP address.
    """
    ip_address_uuid = ConversionHelper.string_to_unicode(ip_address_uuid)
    return IpAddressScan.new(
        ip_address_id=ip_address_uuid,
        started_at=DatetimeHelper.now(),
    )


def count_included_networks_for_organization(org_uuid=None, db_session=None):
    """
    Get the number of networks that are currently configured as in-scope for the given
    organization.
    :param org_uuid: The UUID of the organization to check.
    :param db_session: A SQLAlchemy session.
    :return: The number of networks that are currently configured as in-scope for the given organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    to_return = db_session.query(func.count(Network.uuid))\
        .filter(Network.organization_id == org_uuid)\
        .filter(Network.scanning_enabled == True)\
        .filter(Network.added_by == u"user")\
        .one()
    return to_return[0]


def create_network_for_organization(name=None, address=None, mask_length=None, org_uuid=None):
    """
    Create and return a new Network object that's been associated with the given organization.
    :param name: The name to associate with the network.
    :param address: The address to associate with the network.
    :param mask_length: The mask length to associate with the network.
    :param org_uuid: The UUID of the organization to add the network to.
    :return: The newly-created Network.
    """
    if name is None:
        name = "Auto-gen Network %s" % (RandomHelper.get_random_token_of_length(10))
    cidr_wrapper = CidrRangeWrapper.from_cidr_range(address=address, mask_length=mask_length)
    address = ConversionHelper.ipv4_to_class_c_prefix(address)
    return Network.new(
        name=name,
        address=address,
        mask_length=mask_length,
        organization_id=org_uuid,
        scanning_enabled=True,
        added_by="ws",
        endpoint_count=pow(2, 32 - mask_length),
        cidr_range=cidr_wrapper.parsed_cidr_range,
        times_scanned=0,
    )


def get_address_from_ip_address(ip_address_uuid=None, db_session=None):
    """
    Get the IP address from the database record referenced by ip_address_uuid.
    :param ip_address_uuid: The UUID of the IpAddress to query.
    :param db_session: A SQLAlchemy session.
    :return: The IP address associated with the given IpAddress record.
    """
    ip_address_uuid = ConversionHelper.string_to_unicode(ip_address_uuid)
    result = db_session.query(IpAddress.address)\
        .filter(IpAddress.uuid == ip_address_uuid)\
        .one()
    return result[0]


#TESTME
def get_ip_address_for_organization(
        db_session=None,
        org_uuid=None,
        ip_address=None,
        address_type="ipv4",
        network_mask_length=24,
):
    """
    Create (or query) all of the necessary database objects for the given IP address to be
    associated with the given organization.
    :param db_session: A SQLAlchemy session.
    :param org_uuid: The UUID of the organization to create the IP address for.
    :param ip_address: The IP address.
    :param address_type: The IP address type.
    :param network_mask_length: The size of the network to place the IP address in if a new network
    has to be created.
    :return: An IP address model object owned by the given organization.
    """
    try:
        network_uuid = get_containing_network_uuid_for_organization(
            org_uuid=org_uuid,
            input_ip_address=ip_address,
            db_session=db_session,
        )
    except NoResultFoundError:
        network = create_network_for_organization(
            address=ip_address,
            mask_length=network_mask_length,
            org_uuid=org_uuid,
        )
        try:
            db_session.add(network)
            db_session.commit()
            network_uuid = network.uuid
        except sqlalchemy.exc.IntegrityError as e:
            if not is_unique_constraint_exception(e):
                raise e
            db_session.rollback()
            network_uuid = get_containing_network_uuid_for_organization(
                org_uuid=org_uuid,
                input_ip_address=ip_address,
                db_session=db_session,
            )
    ip_address = get_or_create_ip_address_from_org_network(
        network_uuid=network_uuid,
        address=ip_address,
        address_type=address_type,
        db_session=db_session,
    )
    return ip_address


def get_ip_address_scanning_status(db_session=None, ip_address_uuid=None, with_for_update=False):
    """
    Get the current scanning status associated with the given IP address.
    :param db_session: A SQLAlchemy session.
    :param ip_address_uuid: The UUID of the IP address to query.
    :param with_for_update: Whether or not the SQL query should include a with_for_update clause.
    :return: Whether or not the given IP address is currently being scanned.
    """
    ip_address_uuid = ConversionHelper.string_to_unicode(ip_address_uuid)
    query = db_session.query(IpAddress.scanning_status)\
        .filter(IpAddress.uuid == ip_address_uuid)
    if with_for_update:
        query = query.with_for_update()
    result = query.one()
    return result[0]


def get_last_completed_ip_address_scan(db_session=None, ip_address_uuid=None):
    """
    Get the last IpAddressScan that was completed for the given IP address.
    :param db_session: A SQLAlchemy session.
    :param ip_address_uuid: The UUID of the IP address to query.
    :return: the last IpAddressScan that was completed for the given IP address if such a scan exists,
    otherwise None.
    """
    ip_address_uuid = ConversionHelper.string_to_unicode(ip_address_uuid)
    return db_session.query(IpAddressScan)\
        .filter(IpAddressScan.ended_at != None)\
        .filter(IpAddressScan.ip_address_id == ip_address_uuid)\
        .order_by(IpAddressScan.ended_at.desc())\
        .first()


def get_last_completed_network_service_scan(db_session=None, service_uuid=None):
    """
    Get the last NetworkServiceScan that was completed for the given network service, if such a
    scan exists.
    :param db_session: A SQLAlchemy session.
    :param service_uuid: The UUID of the network service to retrieve data for.
    :return: The last NetworkServiceScan that was completed for the given network service if such a
    scan exists, otherwise None.
    """
    service_uuid = ConversionHelper.string_to_unicode(service_uuid)
    return db_session.query(NetworkServiceScan)\
        .filter(NetworkServiceScan.ended_at != None)\
        .filter(NetworkServiceScan.uuid == service_uuid)\
        .order_by(NetworkServiceScan.ended_at.desc())\
        .first()


def get_network_service_scanning_status(db_session=None, service_uuid=None, with_for_update=False):
    """
    Get whether or not the given network service is currently being scanned.
    :param db_session: A SQLAlchemy session.
    :param service_uuid: The UUID of the NetworkService in question.
    :param with_for_update: Whether or not to apply a with_for_update clause to the query.
    :return: A boolean depicting whether or not the given network service is currently being
    scanned.
    """
    service_uuid = ConversionHelper.string_to_unicode(service_uuid)
    query = db_session.query(NetworkService.scanning_status)\
        .filter(NetworkService.uuid == service_uuid)
    if with_for_update:
        query = query.with_for_update()
    result = query.one()
    return result[0]


def get_org_uuid_from_network_service_scan(db_session=None, scan_uuid=None):
    """
    Get the UUID of the organization that owns the given network service scan.
    :param db_session: A SQLAlchemy session.
    :param scan_uuid: The UUID of the network service scan to query.
    :return: The UUID of the organization that owns the given network service scan.
    """
    scan_uuid = ConversionHelper.string_to_unicode(scan_uuid)
    result = db_session.query(NetworkServiceScan.uuid, Organization.uuid)\
        .join(NetworkService, NetworkService.uuid == NetworkServiceScan.network_service_id)\
        .join(IpAddress, IpAddress.uuid == NetworkService.ip_address_id)\
        .join(Network, Network.uuid == IpAddress.network_id)\
        .join(Organization, Organization.uuid == Network.organization_id)\
        .filter(NetworkServiceScan.uuid == scan_uuid)\
        .one()
    return result[1]


def update_ip_address(ip_address_uuid=None, update_dict=None, db_session=None):
    """
    Update the given IP address with the given dictionary.
    :param ip_address_uuid: The UUID of the IP address to update.
    :param update_dict: A dictionary of key-value pairs to update the IP address with.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=IpAddress,
        model_uuid=ip_address_uuid,
        update_dict=update_dict,
    )


def update_ip_address_scan(scan_uuid=None, update_dict=None, db_session=None):
    """
    Update the given IP address scan with the given dictionary.
    :param scan_uuid: The UUID of the IP address scan to update.
    :param update_dict: A dictionary of key-value pairs to update the IP address scan with.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=IpAddressScan,
        model_uuid=scan_uuid,
        update_dict=update_dict,
    )


#TESTME
def update_ip_address_scan_completed(scan_uuid=None, db_session=None):
    """
    Update the given IP address scan to indicate that the scan has completed.
    :param scan_uuid: The UUID of the IP address scan to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "ended_at": DatetimeHelper.now(),
    }
    update_ip_address_scan(scan_uuid=scan_uuid, db_session=db_session, update_dict=update_dict)


#TESTME
def update_ip_address_scanning_status(ip_address_uuid=None, db_session=None, scanning_status=None):
    """
    Update the scanning status for the given IP address to the given value.
    :param ip_address_uuid: The UUID of the IP address to update.
    :param db_session: A SQLAlchemy session.
    :param scanning_status: The state to set the scanning_status of the IP address to.
    :return: None
    """
    update_dict = {
        "scanning_status": scanning_status,
    }
    update_ip_address(
        ip_address_uuid=ip_address_uuid,
        db_session=db_session,
        update_dict=update_dict,
    )


def update_network_service(service_uuid=None, update_dict=None, db_session=None):
    """
    Update the given network service with the given dictionary.
    :param service_uuid: The UUID of the network service to update.
    :param update_dict: A dictionary of key-value pairs to update the network service with.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=NetworkService,
        model_uuid=service_uuid,
        update_dict=update_dict,
    )


#TESTME
def update_network_service_scanning_status(status=None, service_uuid=None, db_session=None):
    """
    Update the given network service scan to reflect the given scanning status.
    :param status: A boolean depicting whether or not the network service is being scanned.
    :param service_uuid: The UUID of the network service.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "scanning_status": status,
    }
    update_network_service(service_uuid=service_uuid, update_dict=update_dict, db_session=db_session)

