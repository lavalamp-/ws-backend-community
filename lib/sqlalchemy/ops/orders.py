# -*- coding: utf-8 -*-
from __future__ import absolute_import

from sqlalchemy.sql.functions import count

from lib import ConversionHelper
from lib.sqlalchemy import Order, WsUser, OrderDomainName, OrderNetwork, Organization, DomainName, Network


def count_domains_for_order(order_uuid=None, db_session=None):
    """
    Get the number of domains that are associated with the given order.
    :param order_uuid: The UUID of the order to count domains for.
    :param db_session: A SQLAlchemy session.
    :return: The number of domains that are associated with the given order.
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    result = db_session.query(count(OrderDomainName.uuid))\
        .join(Order, Order.uuid == OrderDomainName.order_id)\
        .filter(Order.uuid == order_uuid)\
        .one()
    return result[0]


def count_networks_for_order(order_uuid=None, db_session=None):
    """
    get the number of networks that are associated with the given order.
    :param order_uuid: The UUId of the order to count networks for.
    :param db_session: A SQLAlchemy session.
    :return: The number of networks that are associated with the given order.
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    result = db_session.query(count(OrderNetwork.uuid)) \
        .join(Order, Order.uuid == OrderNetwork.order_id) \
        .filter(Order.uuid == order_uuid) \
        .one()
    return result[0]


def get_monitored_domain_uuids_from_order(order_uuid=None, db_session=None):
    """
    Get all of the DomainName UUIDs from the OrderDomainName objects associated with the
    given order.
    :param order_uuid: The UUID of the order to retrieve domain UUIDs for.
    :param db_session: A SQLAlchemy session.
    :return: A list containing all of the DomainName UUIDs associated with the given order.
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    results = db_session.query(DomainName.uuid)\
        .join(OrderDomainName, OrderDomainName.domain_name_id == DomainName.uuid)\
        .filter(OrderDomainName.order_id == order_uuid)\
        .all()
    return [x[0] for x in results]


def get_monitored_network_ranges_for_order(order_uuid=None, db_session=None):
    """
    Get all of the network ranges for the OrderNetwork objects associated with the given order.
    :param order_uuid: The UUID of the order to retrieve network ranges for.
    :param db_session: A SQLAlchemy session.
    :return: A list containing all of the network ranges associated with the given order.
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    results = db_session.query(OrderNetwork.network_cidr)\
        .filter(OrderNetwork.order_id == order_uuid)\
        .all()
    return [x[0] for x in results]


def get_org_uuid_from_order(order_uuid=None, db_session=None):
    """
    Get the UUID of the organization that is associated with the given order.
    :param order_uuid: The UUID of the order to get the organization UUID for.
    :param db_session: A SQLAlchemy session.
    :return: The UUID of the organization that is related to the given order.
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    result = db_session.query(Organization.uuid)\
        .join(Order, Order.organization_id == Organization.uuid)\
        .filter(Order.uuid == order_uuid)\
        .one()
    return result[0]


def get_user_name_and_email_from_order(order_uuid=None, db_session=None):
    """
    Get the user's name and email address from the given order.
    :param order_uuid: the UUID of the order to retrieve data from.
    :param db_session: A SQLAlchemy session.
    :return: A tuple containing (1) the email address and (2) the name for the user that placed the
    given order.
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    result = db_session.query(WsUser.first_name, WsUser.email)\
        .join(Order, Order.user_id == WsUser.uuid)\
        .filter(Order.uuid == order_uuid)\
        .one()
    return tuple(result)


def update_last_scanning_times_for_order(order_uuid=None, db_session=None, scan_time=None):
    """
    Update all of the last_scanned_time for all of the entities associated with the
    given order to the given time.
    :param order_uuid: The UUID of the order to query for.
    :param db_session: A SQLAlchemy session to use to query a database.
    :param scan_time: The datetime to update the last scanned time to.
    :return: None
    """
    order_uuid = ConversionHelper.string_to_unicode(order_uuid)
    networks = db_session.query(Network)\
        .join(OrderNetwork, OrderNetwork.network_id == Network.uuid)\
        .join(Order, OrderNetwork.order_id == Order.uuid)\
        .filter(Order.uuid == order_uuid)\
        .all()
    for network in networks:
        network.last_scan_time = scan_time
    domains = db_session.query(DomainName)\
        .join(OrderDomainName, OrderDomainName.domain_name_id == DomainName.uuid)\
        .join(Order, OrderDomainName.order_id == Order.uuid)\
        .filter(Order.uuid == order_uuid)\
        .all()
    for domain in domains:
        domain.last_scan_time = scan_time
