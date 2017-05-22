# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group, chain
from celery.utils.log import get_task_logger

from lib import FilesystemHelper
from lib.inspection import PortInspector
from lib.sqlalchemy import get_containing_network_uuid_for_organization, \
    get_or_create_ip_address_from_org_network, get_or_create_network_service_from_org_ip, WebService
from ......app import websight_app
from .....base import DatabaseTask

logger = get_task_logger(__name__)


def create_network_service(org_uuid=None, ip_address=None, port=None, db_session=None):
    """
    Create and return a network service associated with the given endpoint and organization.
    :param org_uuid:
    :param ip_address:
    :param port:
    :param db_session:
    :return:
    """
    network_uuid = get_containing_network_uuid_for_organization(
        org_uuid=org_uuid,
        input_ip_address=ip_address,
        db_session=db_session,
    )
    ip_address_model = get_or_create_ip_address_from_org_network(
        network_uuid=network_uuid,
        address=ip_address,
        address_type="ipv4",
        db_session=db_session,
    )
    return get_or_create_network_service_from_org_ip(
        ip_uuid=ip_address_model.uuid,
        port=port,
        protocol="tcp",
        db_session=db_session,
        discovered_by="network scan",
    )


def create_web_application(org_uuid=None, ip_address=None, port=None, domain=None, use_ssl=None, db_session=None):
    """
    Create and return a web application associated with the given endpoint and organization.
    :param org_uuid:
    :param ip_address:
    :param port:
    :param domain:
    :param use_ssl:
    :param db_session:
    :return:
    """
    network_service = create_network_service(org_uuid=org_uuid, ip_address=ip_address, port=port, db_session=db_session)
    to_return = WebService.new(
        ip_address=ip_address,
        port=port,
        host_name=domain,
        ssl_enabled=use_ssl,
        network_service_id=network_service.uuid,
    )
    db_session.add(to_return)
    db_session.commit()
    return to_return


@websight_app.task(bind=True, base=DatabaseTask)
def scan_endpoints_from_bitsquat_file(self, org_uuid=None, file_path=None):
    """
    Perform a custom scan for the web applications found on the endpoints contained within the
    given CSV file.
    :param org_uuid: The UUID of the organization to associate scan results with.
    :param file_path: The local file path to where the file containing the endpoints to scan
    resides.
    :return: None
    """
    contents = FilesystemHelper.get_file_contents(file_path)
    contents = [x.strip() for x in contents.strip().split("\n")]
    task_sigs = []
    for line in contents:
        domain, ip_address = [x.strip() for x in line.split(",")]
        task_sigs.append(scan_endpoint_from_bitsquat_file.si(
            org_uuid=org_uuid,
            domain=domain,
            ip_address=ip_address,
        ))
    group(task_sigs).apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def scan_endpoint_from_bitsquat_file(self, org_uuid=None, domain=None, ip_address=None):
    """
    Perform a custom scan for the web application on the given IP address and with the given
    domain name.
    :param org_uuid: The UUID of the organization to associate scan results with.
    :param domain: The domain name of the web application.
    :param ip_address: The IP address of the web application.
    :return: None
    """
    inspector = PortInspector(address=ip_address, port=80, protocol="tcp")
    http_is_open = inspector.check_if_open()
    inspector = PortInspector(address=ip_address, port=443, protocol="tcp")
    https_is_open = inspector.check_if_open()
    https_uses_ssl = inspector.check_ssl_support()
    if not http_is_open and not https_is_open:
        return
    task_sigs = []
    if http_is_open:
        task_sigs.append(gather_data_on_bitsquat_web_app.si(
            org_uuid=org_uuid,
            ip_address=ip_address,
            domain=domain,
            port=80,
            use_ssl=False,
        ))
    if https_is_open and https_uses_ssl:
        ssl_sigs = []
        ssl_sigs.append(gather_data_on_bitsquat_ssl_cert.si(org_uuid=org_uuid, ip_address=ip_address, port=443))
        ssl_sigs.append(gather_data_on_bitsquat_web_app.si(
            org_uuid=org_uuid,
            ip_address=ip_address,
            port=443,
            domain=domain,
            use_ssl=True,
        ))
        task_sigs.append(chain(ssl_sigs))
    group(task_sigs).apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def gather_data_on_bitsquat_web_app(self, org_uuid=None, ip_address=None, port=None, domain=None, use_ssl=None):
    pass


@websight_app.task(bind=True, base=DatabaseTask)
def gather_data_on_bitsquat_ssl_cert(self, org_uuid=None, ip_address=None, port=None):
    pass
