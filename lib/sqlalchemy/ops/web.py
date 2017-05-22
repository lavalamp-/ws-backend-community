# -*- coding: utf-8 -*-
from __future__ import absolute_import

import sqlalchemy.exc

from lib import ConversionHelper, DatetimeHelper, ConfigManager
from lib.sqlalchemy import WebService, WebServiceScan, NetworkService, IpAddress, WebServiceReport, Organization, \
    Network
from .base import update_model_instance, is_unique_constraint_exception

config = ConfigManager.instance()


def check_web_service_scanning_status(db_session=None, web_service_uuid=None, update_status=True):
    """
    Check to see whether or not the given web service is currently being scanned. If it is not, then modify
    it to show that it is. Return a boolean depicting whether or not scanning code should proceed with
    scanning the given web service.
    :param db_session: A SQLAlchemy session.
    :param web_service_uuid: The UUID of the web service to query.
    :param update_status: Whether or not to update the current scanning state of the web service.
    :return: True if scanning should be performed for the given web service, False otherwise.
    """
    db_session.execute("begin;")
    current_scanning_status = get_web_service_scanning_status(
        db_session=db_session,
        web_service_uuid=web_service_uuid,
        with_for_update=True,
    )
    if current_scanning_status:
        db_session.execute("end;")
        return False
    last_completed_scan = get_last_completed_web_service_scan(
        db_session=db_session,
        web_service_uuid=web_service_uuid,
    )
    if not last_completed_scan or not config.task_enforce_web_service_scan_interval:
        do_scan = True
    else:
        now = DatetimeHelper.now().replace(tzinfo=last_completed_scan.tzinfo)
        elapsed_seconds = (now - last_completed_scan.ended_at).total_seconds()
        if elapsed_seconds > config.task_minimum_web_service_scan_interval:
            do_scan = True
        else:
            do_scan = False
    if do_scan and update_status:
        update_web_service_scanning_status(status=True, web_service_uuid=web_service_uuid, db_session=db_session)
        db_session.commit()
    db_session.execute("end;")
    return do_scan


def create_new_web_service(
        network_service_uuid=None,
        db_session=None,
        host_name=None,
        ip_address=None,
        port=None,
        use_ssl=None,
):
    """
    Create a new WebService, populate it with the necessary fields, and return it.
    :param network_service_uuid: The UUID of the NetworkService that this WebService is a parent of.
    :param db_session: A SQLAlchemy session.
    :param host_name: The hostname to associate with the Web Service.
    :param ip_address: The IP address where the WebService resides.
    :param port: The port where the WebService resides.
    :param use_ssl: Whether or not the web service is accessed over SSL.
    :return: The newly-created WebService.
    """
    network_service_uuid = ConversionHelper.string_to_unicode(network_service_uuid)
    host_name = ConversionHelper.string_to_unicode(host_name)
    new_service = WebService.new(
        host_name=host_name,
        network_service_id=network_service_uuid,
        ip_address=ip_address,
        port=port,
        ssl_enabled=use_ssl,
        scanning_status=False,
    )
    db_session.add(new_service)
    return new_service


def create_new_web_service_report(web_service_uuid=None, db_session=None):
    """
    Create and return a new WebServiceReport object for the given web service.
    :param web_service_uuid: The UUID of the web service to create a WebServiceReport object for.
    :param db_session: A SQLAlchemy session.
    :return: The newly-created WebServiceReport object.
    """
    web_service_uuid = ConversionHelper.string_to_unicode(web_service_uuid)
    new_report = WebServiceReport.new(
        web_service_id=web_service_uuid,
        uses_iis=False,
        uses_wordpress=False,
        uses_apache=False,
        uses_nginx=False,
    )
    return new_report


def create_new_web_service_scan(web_service_uuid=None, db_session=None):
    """
    Create a new WebServiceScan, populate it, and return it.
    :param web_service_uuid: The UUID of the WebService to associate the scan with.
    :param db_session: A SQLAlchemy session.
    :return: The newly-created WebServiceScan.
    """
    web_service_uuid = ConversionHelper.string_to_unicode(web_service_uuid)
    new_scan = WebServiceScan.new(
        web_service_id=web_service_uuid,
        started_at=DatetimeHelper.now(),
    )
    db_session.add(new_scan)
    return new_scan


def get_endpoint_information_for_web_service(web_service_uuid=None, db_session=None):
    """
    Get a tuple containing (1) the IP address, (2) the port, (3) the hostname for the given web
    service, and (4) whether or not to use SSL to connect to the web service.
    :param web_service_uuid: The UUID of the WebService to query.
    :param db_session: A SQLAlchemy session.
    :return: a tuple containing (1) the IP address, (2) the port, (3) the hostname for the given web
    service, and (4) whether or not to use SSL to connect to the web service.
    """
    result = db_session.query(WebService.uuid, IpAddress.address, NetworkService.port, WebService.host_name, WebService.ssl_enabled)\
        .join(NetworkService, WebService.network_service_id == NetworkService.uuid)\
        .join(IpAddress, NetworkService.ip_address_id == IpAddress.uuid)\
        .filter(WebService.uuid == web_service_uuid)\
        .one()
    return tuple(result)[1:]


def get_ip_address_uuid_from_web_service(web_service_uuid=None, db_session=None):
    """
    Get the UUID of the IP address of the host where the given web service resides.
    :param web_service_uuid: The UUID of the web service to query.
    :param db_session: A SQLAlchemy session.
    :return: The UUID of the IP address of the host where the given web service resides.
    """
    web_service_uuid = ConversionHelper.string_to_unicode(web_service_uuid)
    result = db_session.query(IpAddress.uuid)\
        .join(NetworkService, NetworkService.ip_address_id == IpAddress.uuid)\
        .join(WebService, WebService.network_service_id == NetworkService.uuid)\
        .filter(WebService.uuid == web_service_uuid)\
        .one()
    return result[0]


def get_last_completed_web_service_scan(db_session=None, web_service_uuid=None):
    """
    Get the last WebServiceScan that was completed for the given web service, if such a
    scan exists.
    :param db_session: A SQLAlchemy session.
    :param web_service_uuid: The UUID of the web service to retrieve data for.
    :return: The last WebServiceScan that was completed for the given web service if such a
    scan exists, otherwise None.
    """
    web_service_uuid = ConversionHelper.string_to_unicode(web_service_uuid)
    return db_session.query(WebServiceScan)\
        .filter(WebServiceScan.ended_at != None)\
        .filter(WebServiceScan.uuid == web_service_uuid)\
        .order_by(WebServiceScan.ended_at.desc())\
        .first()


def get_latest_web_service_scan_uuid(db_session=None, web_service_uuid=None):
    """
    Get the UUID of the last WebServiceScan to be run for the given web service.
    :param db_session: A SQLAlchemy session.
    :param web_service_uuid: The UUID of the WebService to query.
    :return: The UUID of the last WebServiceScan to be run for the given web service if such a scan
    exists, otherwise None.
    """
    result = db_session.query(WebServiceScan.uuid)\
        .join(WebService, WebServiceScan.web_service_id == WebService.uuid)\
        .order_by(WebServiceScan.ended_at.desc())\
        .filter(WebService.uuid == web_service_uuid)\
        .filter(WebServiceScan.ended_at.isnot(None))\
        .first()
    return result[0] if result is not None else None


def get_open_ports_for_web_service(web_service_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the port number and (2) the the port protocol for all ports that are
    on the same host as the given web service.
    :param web_service_uuid: The UUID of the web service to query.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the port number and (2) the the port protocol for all ports that are
    on the same host as the given web service.
    """
    ip_address_uuid = get_ip_address_uuid_from_web_service(web_service_uuid=web_service_uuid, db_session=db_session)
    results = db_session.query(NetworkService.port, NetworkService.protocol)\
        .join(IpAddress, NetworkService.ip_address_id == IpAddress.uuid)\
        .filter(IpAddress.uuid == ip_address_uuid)\
        .all()
    return [tuple(x) for x in results]


def get_org_uuid_from_web_service_scan(db_session=None, web_scan_uuid=None):
    """
    Get the UUID of the organization that owns the given web service scan.
    :param db_session: A SQLAlchemy session.
    :param web_scan_uuid: The UUID of the web service scan to query against.
    :return: The UUID of the organization that owns the given web service scan.
    """
    web_scan_uuid = ConversionHelper.string_to_unicode(web_scan_uuid)
    result = db_session.query(Organization.uuid)\
        .join(Network, Network.organization_id == Organization.uuid)\
        .join(IpAddress, IpAddress.network_id == Network.uuid)\
        .join(NetworkService, NetworkService.ip_address_id == IpAddress.uuid)\
        .join(WebService, WebService.network_service_id == NetworkService.uuid)\
        .join(WebServiceScan, WebServiceScan.web_service_id == WebService.uuid)\
        .filter(WebServiceScan.uuid == web_scan_uuid)\
        .one()
    return result[0]


def get_or_create_web_service_from_network_service(
        network_service_uuid=None,
        db_session=None,
        host_name=None,
        ip_address=None,
        port=None,
        use_ssl=None,
):
    """
    Get a WebService from the given network service if such a WebService record exists.
    If it does not, create it. This method makes use of a database unique constraint to address race conditions.
    :param network_service_uuid: The UUID of the NetworkService to retrieve the WebService from.
    :param db_session: A SQLAlchemy session.
    :param host_name: The hostname to associate with the WebService.
    :param ip_address: The IP address where the WebService resides.
    :param port: The port where the WebService resides.
    :param use_ssl: Whether or not the web service is accessed over SSL.
    :return: An IpAddress for the given network with the given address and address type.
    """
    new_web_service = create_new_web_service(
        network_service_uuid=network_service_uuid,
        db_session=db_session,
        host_name=host_name,
        ip_address=ip_address,
        port=port,
        use_ssl=use_ssl,
    )
    try:
        db_session.commit()
        return new_web_service
    except sqlalchemy.exc.IntegrityError as e:
        if not is_unique_constraint_exception(e):
            raise e
        db_session.rollback()
        return get_web_service_from_network_service(
            network_service_uuid=network_service_uuid,
            host_name=host_name,
            db_session=db_session,
            use_ssl=use_ssl,
        )


def get_or_create_web_service_report_from_web_service(web_service_uuid=None, db_session=None):
    """
    Get a WebServiceReport from the database that's related to the given web service. If such a report
    object does not exist, then create it and return it. This method makes use of a database unique constraint
    to address race conditions.
    :param web_service_uuid: The UUID of the WebService to get a report object for.
    :param db_session: A SQLAlchemy session.
    :return: A WebServiceReport object related to the given web service.
    """
    new_report = create_new_web_service_report(web_service_uuid=web_service_uuid, db_session=db_session)
    try:
        db_session.add(new_report)
        db_session.commit()
        return new_report
    except sqlalchemy.exc.IntegrityError as e:
        if not is_unique_constraint_exception(e):
            raise e
        db_session.rollback()
        return get_web_service_report_from_web_service(web_service_uuid=web_service_uuid, db_session=db_session)


def get_web_service_from_network_service(network_service_uuid=None, host_name=None, db_session=None, use_ssl=None):
    """
    Get a WebService from the given NetworkService with the given hostname.
    :param network_service_uuid: The UUID of the NetworkService to query against.
    :param host_name: The hostname to look for.
    :param db_session: A SQLAlchemy session.
    :return: A WebService from the given NetworkService with the given hostname.
    """
    network_service_uuid = ConversionHelper.string_to_unicode(network_service_uuid)
    host_name = ConversionHelper.string_to_unicode(host_name)
    return db_session.query(WebService)\
        .filter(WebService.network_service_id == network_service_uuid)\
        .filter(WebService.host_name == host_name)\
        .filter(WebService.ssl_enabled == use_ssl)\
        .one()


def get_web_service_report_from_web_service(web_service_uuid=None, db_session=None):
    """
    Retrieve a WebServiceReport from the database that's related to the given web service.
    :param web_service_uuid: The UUID of the web service to retrieve a WebServiceReport for.
    :param db_session: A SQLAlchemy session.
    :return: A WebServiceReport related to the given web service.
    """
    web_service_uuid = ConversionHelper.string_to_unicode(web_service_uuid)
    return db_session.query(WebServiceReport)\
        .join(WebService, WebServiceReport.web_service_id == WebService.uuid)\
        .filter(WebService.uuid == web_service_uuid)\
        .one()


def get_web_service_scanning_status(db_session=None, web_service_uuid=None, with_for_update=False):
    """
    Get whether or not the given web service is currently being scanned.
    :param db_session: A SQLAlchemy session.
    :param web_service_uuid: The UUID of the WebService in question.
    :param with_for_update: Whether or not to apply a with_for_update clause to the query.
    :return: A boolean depicting whether or not the given web service is currently being
    scanned.
    """
    web_service_uuid = ConversionHelper.string_to_unicode(web_service_uuid)
    query = db_session.query(WebService.scanning_status) \
        .filter(WebService.uuid == web_service_uuid)
    if with_for_update:
        query = query.with_for_update()
    result = query.one()
    return result[0]


def get_web_service_uuid_from_web_service_scan(scan_uuid=None, db_session=None):
    """
    Get the UUID of the web service that is related to the given web service scan.
    :param scan_uuid: The UUID of the web service scan.
    :param db_session: A SQLAlchemy session.
    :return: The UUID of the web service that is related to the given web service scan.
    """
    scan_uuid = ConversionHelper.string_to_unicode(scan_uuid)
    result = db_session.query(WebService.uuid)\
        .join(WebServiceScan, WebServiceScan.web_service_id == WebService.uuid)\
        .filter(WebServiceScan.uuid == scan_uuid)\
        .one()
    return result[0]


def update_web_service(web_service_uuid=None, update_dict=None, db_session=None):
    """
    Update the given web service with the given dictionary.
    :param web_service_uuid: The UUID of the web service to update.
    :param update_dict: A dictionary of key-value pairs to update the network service with.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=WebService,
        model_uuid=web_service_uuid,
        update_dict=update_dict,
    )


def update_web_service_scan(scan_uuid=None, db_session=None, update_dict=None):
    """
    Update the given WebServiceScan with the given fields.
    :param scan_uuid: The UUID of the WebServiceScan to update.
    :param update_dict: A dictionary containing key-value pairs to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_model_instance(
        db_session=db_session,
        model_class=WebServiceScan,
        model_uuid=scan_uuid,
        update_dict=update_dict,
    )


def update_web_service_scan_completed(scan_uuid=None, db_session=None):
    """
    Update the given WebServiceScan to reflect that scanning has concluded.
    :param scan_uuid: The UUID of the WebServiceScan to update.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "ended_at": DatetimeHelper.now()
    }
    update_web_service_scan(scan_uuid=scan_uuid, update_dict=update_dict, db_session=db_session)


def update_web_service_scanning_status(status=None, web_service_uuid=None, db_session=None):
    """
    Update the given web service scan to reflect the given scanning status.
    :param status: A boolean depicting whether or not the web service is being scanned.
    :param web_service_uuid: The UUID of the web service.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    update_dict = {
        "scanning_status": status,
    }
    update_web_service(web_service_uuid=web_service_uuid, update_dict=update_dict, db_session=db_session)
