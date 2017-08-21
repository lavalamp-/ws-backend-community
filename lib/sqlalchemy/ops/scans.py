# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib.sqlalchemy import ScanPort, ScanConfig


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
