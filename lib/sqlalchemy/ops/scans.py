# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib.sqlalchemy import ScanPort, ScanConfig
from lib import ConversionHelper


#TESTME
def get_ports_to_scan_for_scan_config(config_uuid=None, db_session=None):
    """
    Get a list of tuples containing (1) the port number and (2) the protocol to scn for ports
    that should be scanned for the given scan configuration.
    :param config_uuid: The UUID of the scan configuration to retrieve ports for.
    :param db_session: A SQLAlchemy session.
    :return: A list of tuples containing (1) the port number and (2) the protocol to scn for ports
    that should be scanned for the given scan configuration.
    """
    results = db_session.query(ScanPort.port_number, ScanPort.protocol) \
        .join(ScanConfig, ScanPort.scan_config_id == ScanConfig.uuid) \
        .filter(ScanConfig.uuid == config_uuid) \
        .all()
    return [tuple(x) for x in results]


#TESTME
def get_tcp_ports_to_scan_for_scan_config(config_uuid=None, db_session=None):
    """
    Get a list of integers representing the TCP ports configured to be scanned for the given
    scan configuration.
    :param config_uuid: The UUID of the ScanConfig to retrieve ports for.
    :param db_session: A SQLAlchemy session.
    :return: A list of integers representing the TCP ports configured to be scanned for the given
    ScanConfig.
    """
    config_uuid = ConversionHelper.string_to_unicode(config_uuid)
    results = db_session.query(ScanPort.port_number) \
        .filter(ScanPort.protocol == u"tcp") \
        .filter(ScanPort.included == True) \
        .filter(ScanPort.scan_config_id == config_uuid) \
        .all()
    return [x[0] for x in results]


#TESTME
def get_udp_ports_to_scan_for_scan_config(config_uuid=None, db_session=None):
    """
    Get a list of integers representing the UDP ports configured to be scanned for the given
    scan configuration.
    :param config_uuid: The UUID of the ScanConfig to retrieve ports for.
    :param db_session: A SQLAlchemy session.
    :return: A list of integers representing the UDP ports configured to be scanned for the given
    ScanConfig.
    """
    config_uuid = ConversionHelper.string_to_unicode(config_uuid)
    results = db_session.query(ScanPort.port_number) \
        .filter(ScanPort.protocol == u"udp") \
        .filter(ScanPort.included == True) \
        .filter(ScanPort.scan_config_id == config_uuid) \
        .all()
    return [x[0] for x in results]
