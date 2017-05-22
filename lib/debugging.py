# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4


def clear_celery_queue():
    """
    Clear out all tasks for the Web Sight Celery application.
    :return: None
    """
    from tasknode import websight_app
    websight_app.control.purge()


def enqueue_database_debugging_task(*args, **kwargs):
    """
    Create and enqueue a Celery task of the debugging_database_task type.
    :param args: Positional arguments to pass to the task.
    :param kwargs: Keyword arguments to pass to the task.
    :return: None
    """
    from tasknode.tasks import debugging_database_task
    sig = debugging_database_task.si(*args, **kwargs)
    sig.apply_async()


def get_debugging_network_service(ip_address=None, port=None, protocol=None):
    """
    Get a OrganizationNetworkService attached to the debugging organization that points to
    the given IP address, port, and protocol.
    :param ip_address: The IP address for the service.
    :param port: The port for the service.
    :param protocol: The protocol for the service.
    :return: A OrganizationNetworkService attached to the debugging organization that points to
    the given IP address, port, and protocol.
    """
    debugging_org = get_debugging_organization()
    network = debugging_org.org_networks[0]
    from .sqlalchemy import get_sa_session, get_or_create_network_service_from_org_ip, \
        get_or_create_ip_address_from_org_network
    db_session = get_sa_session()
    address_model = get_or_create_ip_address_from_org_network(
        network_uuid=network.uuid,
        address=ip_address,
        address_type="ipv4",
        db_session=db_session,
    )
    service = get_or_create_network_service_from_org_ip(
        ip_uuid=address_model.uuid,
        port=port,
        protocol=protocol,
        db_session=db_session,
    )
    return service


def get_debugging_organization(
        org_uuid=u"a9def2a2-54be-40d4-83bf-efc34cc2fbbc",
        user_email=u"chris@websight.io",
):
    """
    Create the default debugging organization for the specified user, or return it if it already
    exists.
    :param org_uuid: The UUID to give the organization.
    :param user_email: The email address for the user to add the organization to.
    :return: The debugging organization owned by the given user.
    """
    from .sqlalchemy import Organization, Network, get_sa_session, get_organization_by_uuid, \
        get_user_uuid_by_username
    db_session = get_sa_session()
    existing_org = get_organization_by_uuid(org_uuid=org_uuid, db_session=db_session)
    if existing_org is not None:
        return existing_org
    user_uuid = get_user_uuid_by_username(username=user_email, db_session=db_session)
    new_org = Organization.new(
        uuid=org_uuid,
        user_id=user_uuid,
        name=u"Debugging Organization",
        description=u"Debugging Organization Description",
        scanning_status=0,
    )
    new_org_network = Network.new(
        name=u"Debugging Network",
        address=u"157.166.255.0",
        mask_length=24,
        scanning_enabled=True,
        organization_id=org_uuid,
        endpoint_count=0,
    )
    db_session.add(new_org)
    db_session.add(new_org_network)
    db_session.commit()
    db_session.close()
    return new_org


def perform_network_service_inspection(
        org_uuid=None,
        scan_uuid=None,
        ip_address=None,
        port=None,
        protocol=None,
):
    """
    Create and enqueue a Celery task of the inspect_network_service_for_organization type.
    :param org_uuid: The UUID for the organization.
    :param scan_uuid: The UUID for the scan.
    :param ip_address: The IP address to check.
    :param port: The port to check.
    :param protocol: The protocol to use to connect to the remote service.
    :return: None
    """
    from tasknode.tasks import perform_network_service_inspection
    from wselasticsearch import bootstrap_index_model_mappings
    org_uuid = org_uuid if org_uuid is not None else str(uuid4())
    scan_uuid = scan_uuid if scan_uuid is not None else str(uuid4())
    bootstrap_index_model_mappings(index=org_uuid, delete_first=True)
    task_sig = perform_network_service_inspection.si(
        org_uuid=org_uuid,
        scan_uuid=scan_uuid,
        port=port,
        protocol=protocol,
        ip_address=ip_address,
    )
    task_sig.apply_async()
