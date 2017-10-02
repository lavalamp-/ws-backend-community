# -*- coding: utf-8 -*-
from __future__ import absolute_import

from sqlalchemy import func
import sqlalchemy.exc

from ..models import Organization, DomainName, DomainNameScan, IpAddress
from lib import ConversionHelper, DatetimeHelper, ConfigManager
from .base import update_model_instance, is_unique_constraint_exception

config = ConfigManager.instance()


def add_ip_address_to_domain_name(domain_uuid=None, db_session=None, ip_address=None, address_type="ipv4"):
    """
    Ensure that the ip_addresses relationship associated with the given domain name contains the
    given IP address and return the IP address model object.
    :param domain_uuid: The UUID of the domain name.
    :param db_session: A SQLAlchemy session.
    :param ip_address: The IP address.
    :param address_type: The type of IP address.
    :return: The IP address model.
    """

    #TODO this probably results in race conditions - unique condition on join table?

    domain_name = DomainName.by_uuid(db_session=db_session, uuid=domain_uuid)
    existing_ip = filter(lambda x: x.address == ip_address, domain_name.ip_addresses)
    if existing_ip:
        return existing_ip[0]
    new_ip = IpAddress.new(
        address=ip_address,
        address_type=address_type,
        is_monitored=False,
    )
    domain_name.ip_addresses.append(new_ip)
    db_session.commit()
    return new_ip


#TESTME
def check_domain_name_scanning_status(db_session=None, domain_uuid=None, update_status=True):
    """
    Check to see whether the given domain name is currently being scanned. If it is not, then modify it to
    show that it is. Return a boolean depicting whether or not scanning could should proceed with scanning
    the given domain name.
    :param db_session: A SQLAlchemy session.
    :param domain_uuid: The UUID of the domain name to check.
    :param update_status: Whether or not to update the status of the domain name's current scanning state
    during the check.
    :return: True if scanning should be performed for the given network service, False otherwise.
    """
    db_session.execute("begin;")
    current_scanning_status = get_domain_name_scanning_status(
        db_session=db_session,
        domain_uuid=domain_uuid,
        with_for_update=True,
    )
    if current_scanning_status:
        db_session.execute("end;")
        return False
    last_completed_scan = get_last_completed_domain_name_scan(db_session=db_session, domain_uuid=domain_uuid)
    if not last_completed_scan or not config.task_enforce_domain_name_scan_interval:
        do_scan = True
    else:
        now = DatetimeHelper.now().replace(tzinfo=last_completed_scan.ended_at.tzinfo)
        elapsed_seconds = (now - last_completed_scan.ended_at).total_seconds()
        if elapsed_seconds > config.task_minimum_domain_name_scan_interval:
            do_scan = True
        else:
            do_scan = False
    if do_scan and update_status:
        update_domain_name_scanning_status(db_session=db_session, domain_uuid=domain_uuid, scanning_status=True)
        db_session.commit()
    db_session.execute("end;")
    return do_scan


def count_included_domains_for_organization(org_uuid=None, db_session=None):
    """
    Get the number of domain names that are currently configured as in-scope for the given
    organization.
    :param org_uuid: The UUID of the organization.
    :param db_session: A SQLAlchemy session.
    :return: The number of domain names that are currently configured as in-scope for the
    given organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    to_return = db_session.query(func.count(DomainName.uuid))\
        .filter(DomainName.organization_id == org_uuid)\
        .filter(DomainName.scanning_enabled == True)\
        .filter(DomainName.added_by == u"user")\
        .one()
    return to_return[0]


def create_domain_for_organization(org_uuid=None, name=None, added_by="user"):
    """
    Create and return a new DomainName associated with the given organization.
    :param org_uuid: The UUID of the organization to associated the domain with.
    :param name: The name to give the domain name.
    :param added_by: How the domain name was added to the database.
    :return: The newly-created domain name.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return DomainName.new(
        organization_id=org_uuid,
        name=name,
        is_monitored=False,
        scanning_enabled=True,
        times_scanned=0,
        added_by=added_by,
        scanning_status=False,
    )


#TESTME
def create_domain_scan_for_domain(domain_uuid):
    """
    Create and return a new DomainNameScan object associated with the given domain name.
    :param domain_uuid: The UUID of the DomainName to associate the scan with.
    :return: The newly-created DomainNameScan object.
    """
    domain_uuid = ConversionHelper.string_to_unicode(domain_uuid)
    return DomainNameScan.new(
        domain_name_id=domain_uuid,
        started_at=DatetimeHelper.now(),
    )


#TESTME
def get_all_domains_for_organization(org_uuid=None, db_session=None):
    """
    Get a list of strings representing all of the domain names owned by the given
    organization.
    :param org_uuid: The UUID of the organization to retrieve domain names for.
    :param db_session: A SQLAlchemy session.
    :return: A list of strings representing all of the domain names owned by the given
    organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    results = db_session.query(DomainName.name)\
        .join(Organization, DomainName.organization_id == Organization.uuid)\
        .filter(Organization.uuid == org_uuid)\
        .all()
    return [x[0] for x in results]


def get_all_included_domain_uuids_for_organization(org_uuid=None, db_session=None):
    """
    Get a list containing all of the UUIDs associated with all of the domain names associated with
    the given organization.
    :param org_uuid: The UUID of the organization to retrieve domain UUIDs for.
    :param db_session: A SQLAlchemy session.
    :return: A list containing all of the UUIDs associated with all of the domain names associated with
    the given organization.
    """
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    results = db_session.query(DomainName.uuid)\
        .join(Organization, DomainName.organization_id == Organization.uuid)\
        .filter(Organization.uuid == org_uuid)\
        .filter(DomainName.scanning_enabled == True)\
        .filter(DomainName.added_by == u"user")\
        .all()
    return [x[0] for x in results]


def get_domain_by_name_from_organization(db_session=None, name=None, org_uuid=None):
    """
    Get a domain name owned by the given organization matching the given name.
    :param db_session: A SQLAlchemy session.
    :param name: The name of the domain to retrieve.
    :param org_uuid: The UUID of the organization that owns the domain name.
    :return: a domain name owned by the given organization matching the given name.
    """
    name = ConversionHelper.string_to_unicode(name)
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(DomainName)\
        .filter(DomainName.name == name)\
        .filter(DomainName.organization_id == org_uuid)\
        .one()


def get_domain_name_scanning_status(db_session=None, domain_uuid=None, with_for_update=False):
    """
    Get whether or not the referenced domain name is currently being scanned.
    :param db_session: A SQLAlchemy session.
    :param domain_uuid: The UUID of the domain name.
    :param with_for_update: Whether or not to apply a with_for_update clause to the query.
    :return: True if the referenced domain name is currently being scanned, False otherwise.
    """
    domain_uuid = ConversionHelper.string_to_unicode(domain_uuid)
    query = db_session.query(DomainName.scanning_status).filter(DomainName.uuid == domain_uuid)
    if with_for_update:
        query = query.with_for_update()
    result = query.one()
    return result[0]


def get_domain_uuid_from_domain_scan(db_session=None, domain_scan_uuid=None):
    """
    Get the UUID of the domain name that was scanned during the given domain name scan.
    :param db_session: A SQLAlchemy session.
    :param domain_scan_uuid: The UUID of the domain name scan to query.
    :return: The UUID of the domain name that was scanned during the given domain name scan.
    """
    domain_scan_uuid = ConversionHelper.string_to_unicode(domain_scan_uuid)
    result = db_session.query(DomainName.uuid)\
        .join(DomainNameScan, DomainNameScan.domain_name_id == DomainName.uuid)\
        .filter(DomainNameScan.uuid == domain_scan_uuid)\
        .one()
    return result[0]


def get_last_completed_domain_name_scan(db_session=None, domain_uuid=None):
    """
    Get the last completed domain name scan associated with the given domain name.
    :param db_session: A SQLAlchemy session.
    :param domain_uuid: The UUID of the domain name to check.
    :return: The last completed domain name scan associated with the given domain name if such a scan
    exists, otherwise None.
    """
    domain_uuid = ConversionHelper.string_to_unicode(domain_uuid)
    return db_session.query(DomainNameScan)\
        .filter(DomainNameScan.ended_at != None)\
        .filter(DomainNameScan.domain_name_id == domain_uuid)\
        .order_by(DomainNameScan.ended_at.desc())\
        .first()


def get_name_from_domain(db_session=None, domain_uuid=None):
    """
    Get the name associated with the given domain name object.
    :param db_session: A SQLAlchemy session.
    :param domain_uuid: The UUID of the domain name to retrieve the name from.
    :return: A string representing the name associated with the given domain name.
    """
    domain_uuid = ConversionHelper.string_to_unicode(domain_uuid)
    result = db_session.query(DomainName.name)\
        .filter(DomainName.uuid == domain_uuid)\
        .one()
    return result[0]


#TESTME
def get_or_create_domain_name_for_organization(
        db_session=None,
        name=None,
        added_by="user",
        org_uuid=None,
        nest_transaction=False,
):
    """
    Get a domain name representing the given input data as owned by the given organization. If a matching
    domain name does not exist, then one is created.
    :param db_session: A SQLAlchemy session.
    :param name: The name to associate with the domain name.
    :param added_by: How the domain was added to the database.
    :param org_uuid: The UUID of the organization to get the domain from.
    :param nest_transaction: Whether or not to nest the SQLAlchemy transaction.
    :return: A DomainName owned by the given organization representing the given data.
    """
    if nest_transaction:
        db_session.begin_nested()
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    name = ConversionHelper.string_to_unicode(name)
    added_by = ConversionHelper.string_to_unicode(added_by)
    new_domain_name = create_domain_for_organization(org_uuid=org_uuid, name=name, added_by=added_by)
    try:
        db_session.add(new_domain_name)
        db_session.commit()
        return new_domain_name
    except sqlalchemy.exc.IntegrityError as e:
        if not is_unique_constraint_exception(e):
            raise e
        db_session.rollback()
        return get_domain_by_name_from_organization(
            db_session=db_session,
            name=name,
            org_uuid=org_uuid,
        )


def get_org_uuid_from_domain_name_scan(db_session=None, domain_scan_uuid=None):
    """
    Get the UUID of the organization that owns the given domain name scan.
    :param db_session: A SQLAlchemy session.
    :param domain_scan_uuid: The UUID of the domain name scan to query.
    :return: The UUID of the organization that owns the given domain name scan.
    """
    domain_scan_uuid = ConversionHelper.string_to_unicode(domain_scan_uuid)
    result = db_session.query(Organization.uuid)\
        .join(DomainName, DomainName.organization_id == Organization.uuid)\
        .join(DomainNameScan, DomainNameScan.domain_name_id == DomainName.uuid)\
        .filter(DomainNameScan.uuid == domain_scan_uuid)\
        .one()
    return result[0]


def update_domain_name(domain_uuid=None, db_session=None, update_dict=None):
    """
    Update the given domain name with the given fields.
    :param domain_uuid: The UUID of the domain name to update.
    :param db_session: A SQLAlchemy session.
    :param update_dict: A dictionary containing key-value pairs to update the domain with.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=DomainName,
        model_uuid=domain_uuid,
        update_dict=update_dict,
    )


def update_domain_name_scan(scan_uuid=None, db_session=None, update_dict=None):
    """
    Update the given domain name scan with the given fields.
    :param scan_uuid: The UUID of the domain name scan to update.
    :param db_session: A SQLAlchemy session.
    :param update_dict: A dictionary of key-value pairs to update the domain name scan with.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=DomainNameScan,
        model_uuid=scan_uuid,
        update_dict=update_dict,
    )


#TESTME
def update_domain_name_scanning_status(db_session=None, scanning_status=None, domain_uuid=None):
    """
    Update the given domain name to reflect whether or not the domain is currently being scanned.
    :param db_session: A SQLAlchemy session.
    :param scanning_status: The status to set on the domain.
    :param domain_uuid: The UUID of the domain name to update.
    :return: None
    """
    update_dict = {
        "scanning_status": scanning_status,
    }
    update_domain_name(db_session=db_session, domain_uuid=domain_uuid, update_dict=update_dict)


#TESTME
def update_domain_name_scan_completed(scan_uuid=None, db_session=None):
    """
    Update the given DomainNameScan to reflect that scanning has concluded.
    :param scan_uuid: The UUID of the domain name scan to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "ended_at": DatetimeHelper.now(),
    }
    update_domain_name_scan(scan_uuid=scan_uuid, db_session=db_session, update_dict=update_dict)
