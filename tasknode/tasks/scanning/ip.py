# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import chain
from celery import group
from celery.utils.log import get_task_logger

from lib.inspection import PortInspector, IpAddressScanInspector
from lib.sqlalchemy.ops.exception import NoResultFoundError
from ..base import DatabaseTask, IpAddressTask
from ...app import websight_app
from lib.sqlalchemy import get_ports_to_scan_for_organization, get_containing_network_uuid_for_organization, \
    create_network_for_organization, get_or_create_ip_address_from_org_network, get_address_from_ip_address, \
    get_or_create_network_service_from_org_ip, create_new_network_service_scan, check_ip_address_scanning_status, \
    IpAddress, create_ip_address_scan_for_ip, get_tcp_scan_ports_for_org, get_udp_scan_ports_for_org, \
    update_ip_address_scan_completed as update_ip_address_scan_completed_op, \
    update_ip_address_scanning_status as update_ip_address_scanning_status_op, DefaultFlag, \
    get_all_ip_flags_for_organization
from wselasticsearch.models import DomainServiceLivenessModel, IpReverseHostnameModel, IpPortScanModel, \
    IpDomainHistoryModel
from wselasticsearch.query import BulkElasticsearchQuery
from wselasticsearch.ops import get_open_ports_from_ip_address_scan, update_ip_address_scan_latest_state, \
    update_not_ip_address_scan_latest_state
from lib import DatetimeHelper, enumerate_domains_for_ip_address, ConfigManager
from .services import network_service_inspection_pass, scan_network_service
from .monitoring import initialize_network_service_monitoring
from wselasticsearch.flags import DataFlagger

logger = get_task_logger(__name__)
config = ConfigManager.instance()


@websight_app.task(bind=True, base=DatabaseTask)
def create_ip_address_from_domain_resolution(
        self,
        org_uuid=None,
        ip_address=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        scan_ip=True,
):
    """
    Create a new IpAddress record in the Web Sight database and associate it with a network owned
    by the given organization. Continue on with scanning if scan_ip is True.
    :param org_uuid: The UUID of the organization to add the IpAddress to.
    :param ip_address: The IP address to add.
    :param domain_uuid: The UUID of the domain that was resolved, resulting in the creation of this
    IP address.
    :param domain_scan_uuid: The UUID of the domain name scan that resulted in this task.
    :param scan_ip: Whether or not to continue on and scan for network services on the IP address.
    :return: None
    """
    logger.info(
        "Now ensuring that IP address %s exists in relation to organization %s. Domain scan is %s."
        % (ip_address, org_uuid, domain_scan_uuid)
    )
    try:
        network_uuid = get_containing_network_uuid_for_organization(
            org_uuid=org_uuid,
            input_ip_address=ip_address,
            db_session=self.db_session,
        )
    except NoResultFoundError:
        network = create_network_for_organization(address=ip_address, mask_length=24, org_uuid=org_uuid)
        self.db_session.add(network)
        self.commit_session()
        network_uuid = network.uuid
    ip_address_model = get_or_create_ip_address_from_org_network(
        network_uuid=network_uuid,
        address=ip_address,
        address_type="ipv4",
        db_session=self.db_session,
    )
    logger.info(
        "IP address of %s is associated with network %s and has UUID %s."
        % (ip_address, network_uuid, ip_address_model.uuid)
    )
    if scan_ip:
        logger.info(
            "Now continuing on with scanning IP address at %s for domain scan %s."
            % (ip_address, domain_scan_uuid)
        )
        scan_ip_address_for_services_from_domain.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_model.uuid,
            domain_uuid=domain_uuid,
            domain_scan_uuid=domain_scan_uuid,
        ).apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def scan_ip_address_for_services_from_domain(
        self,
        org_uuid=None,
        ip_address_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
):
    """
    Check to see what network services are exposed by the given endpoint as a result of a
    DNS record lookup.
    :param org_uuid: The organization to scan the endpoint on behalf of.
    :param ip_address_uuid: The UUID of the IP address to scan.
    :param domain_uuid: The UUID of the domain that resulted in this scan.
    :param domain_scan_uuid: The UUID of the domain name scan that resulted in this scan.
    :return: None
    """
    logger.info(
        "Now checking to see what open network services reside on IP %s for domain %s. Organization is "
        "%s, scan is %s."
        % (ip_address_uuid, domain_uuid, org_uuid, domain_scan_uuid)
    )
    scan_ports = get_ports_to_scan_for_organization(org_uuid=org_uuid, db_session=self.db_session)
    task_sigs = []
    for port, protocol in scan_ports:
        task_sigs.append(scan_ip_address_for_service_from_domain.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_uuid,
            port=port,
            protocol=protocol,
            domain_uuid=domain_uuid,
            domain_scan_uuid=domain_scan_uuid,
        ))
    logger.info(
        "Now kicking off %s tasks to check for network services on IP %s for domain %s. Scan is %s."
        % (len(task_sigs), ip_address_uuid, domain_uuid, domain_scan_uuid)
    )
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=DatabaseTask)
def scan_ip_address_for_service_from_domain(
        self,
        org_uuid=None,
        ip_address_uuid=None,
        port=None,
        protocol=None,
        domain_uuid=None,
        domain_scan_uuid=None,
):
    """
    Check to see if the given network service port is currently open and listening at the given IP
    address as a result of resolving IP addresses for the given domain.
    :param org_uuid: The organization to scan the endpoint on behalf of.
    :param ip_address_uuid: The UUID of the IP address to scan.
    :param port: The port number to check.
    :param protocol: The networking protocol to use to connect to the endpoint.
    :param domain_uuid: The UUID of the domain name that resulted in this scan.
    :param domain_scan_uuid: The UUID of the domain name scan that this task is a part of.
    :return: None
    """
    ip_address = get_address_from_ip_address(ip_address_uuid=ip_address_uuid, db_session=self.db_session)
    logger.info(
        "Now checking to see if service at %s:%s (%s) is alive for domain %s, scan %s, organization %s."
        % (ip_address, port, protocol, domain_uuid, domain_scan_uuid, org_uuid)
    )
    inspector = PortInspector(address=ip_address, port=port, protocol=protocol)
    is_open = inspector.check_if_open()
    logger.info(
        "Service at %s:%s (%s) %s open!"
        % (ip_address, port, protocol, "is" if is_open else "is not")
    )
    liveness_model = DomainServiceLivenessModel.from_database_model_uuid(
        uuid=domain_scan_uuid,
        db_session=self.db_session,
        is_alive=is_open,
        checked_at=DatetimeHelper.now(),
    )
    liveness_model.save(org_uuid)
    if not is_open:
        logger.info(
            "Service at %s:%s (%s) was not open, therefore not continuing with inspection."
            % (ip_address, port, protocol)
        )
        return
    logger.info(
        "Service at %s:%s (%s) was open! Setting up a single pass of network service monitoring."
        % (ip_address, port, protocol)
    )
    network_service_model = get_or_create_network_service_from_org_ip(
        ip_uuid=ip_address_uuid,
        port=port,
        protocol=protocol,
        db_session=self.db_session,
        discovered_by="domain scan",
    )
    network_service_inspection_pass.si(
        service_uuid=network_service_model.uuid,
        org_uuid=org_uuid,
        schedule_again=False,
    ).apply_async()


@websight_app.task(bind=True, base=IpAddressTask)
def scan_ip_address(
        self,
        org_uuid=None,
        ip_address_uuid=None,
        scan_network_services=True,
        inspect_network_services=True,
):
    """
    Scan the given IP address for all IP-relevant data supported by Web Sight.
    :param org_uuid: The UUID of the organization to perform the scan on behalf of.
    :param ip_address_uuid: The UUID of the IP address to collect data for.
    :param scan_network_services: Whether or not to scan the IP address for open network services.
    :param inspect_network_services: Whether or not to inspect any network services that are identified
    as open on the IP address.
    :return: None
    """
    logger.info(
        "Now scanning IP address %s for organization %s."
        % (ip_address_uuid, org_uuid)
    )
    should_scan = check_ip_address_scanning_status(
        db_session=self.db_session,
        ip_address_uuid=ip_address_uuid,
        update_status=True,
    )
    if not should_scan:
        logger.info(
            "Should not scan IP address %s. Returning."
            % (ip_address_uuid,)
        )
        return
    ip_scan = create_ip_address_scan_for_ip(ip_address_uuid)
    self.db_session.add(ip_scan)
    self.db_session.commit()
    task_kwargs = {
        "org_uuid": org_uuid,
        "ip_address_uuid": ip_address_uuid,
        "ip_address_scan_uuid": ip_scan.uuid,
    }
    task_sigs = []
    collection_sigs = []
    # collection_sigs.append(geolocate_ip_address.si(**task_kwargs))
    collection_sigs.append(get_reverse_hostnames_for_ip_address.si(**task_kwargs))
    collection_sigs.append(get_historic_dns_data_for_ip_address.si(**task_kwargs))
    # collection_sigs.append(get_as_data_for_ip_address.si(**task_kwargs))
    # collection_sigs.append(get_whois_data_for_ip_address.si(**task_kwargs))
    if scan_network_services:
        network_service_sigs = []
        network_service_sigs.append(scan_ip_address_for_network_services.si(**task_kwargs))
        if inspect_network_services:
            network_service_sigs.append(inspect_network_services_from_ip_address.si(**task_kwargs))
        if len(network_service_sigs) > 1:
            collection_sigs.append(chain(network_service_sigs))
        else:
            collection_sigs.append(network_service_sigs[0])
    task_sigs.append(group(collection_sigs))
    task_sigs.append(create_report_for_ip_address_scan.si(**task_kwargs))
    task_sigs.append(apply_flags_to_ip_address_scan.si(**task_kwargs))
    task_sigs.append(update_ip_address_scan_elasticsearch.si(**task_kwargs))
    task_sigs.append(update_ip_address_scan_completed.si(**task_kwargs))
    scanning_status_signature = update_ip_address_scanning_status.si(
        ip_address_uuid=ip_address_uuid,
        scanning_status=False,
    )
    task_sigs.append(scanning_status_signature)
    logger.info(
        "Now kicking off all necessary tasks to scan IP address %s."
        % (ip_address_uuid,)
    )
    canvas_sig = chain(task_sigs, link_error=scanning_status_signature)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=IpAddressTask)
def geolocate_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Perform geolocation of the given IP address.
    :param org_uuid: The UUID of the organization to perform geolocation on behalf of.
    :param ip_address_uuid: The UUID of the IP address to geolocate.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate geolocation results with.
    :return: None
    """
    logger.info(
        "Now geolocating IP address %s."
        % (ip_address_uuid,)
    )
    geolocations = self.inspector.get_geolocations(use_class_c=True)
    bulk_query = BulkElasticsearchQuery()
    for geolocation in geolocations:
        geolocation_model = geolocation.to_es_model(model=self.ip_address_scan)
        bulk_query.add_model_for_indexing(model=geolocation_model, index=org_uuid)
    bulk_query.save()
    logger.info(
        "All geolocation data collected for IP address %s."
        % (ip_address_uuid,)
    )


@websight_app.task(bind=True, base=IpAddressTask)
def get_reverse_hostnames_for_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Perform a reverse hostname lookup for the given IP address.
    :param org_uuid: The UUID of the organization to perform hostname lookup on behalf of.
    :param ip_address_uuid: The UUID of the IP address to lookup.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate lookup results with.
    :return: None
    """
    logger.info(
        "Now retrieving reverse hostname data for IP address %s."
        % (ip_address_uuid,)
    )
    hostnames = self.inspector.get_hostnames()
    if len(hostnames) == 0:
        logger.info(
            "No hostnames found through reverse DNS lookup for IP address %s."
            % (ip_address_uuid,)
        )
        return
    hostnames_model = IpReverseHostnameModel.from_database_model(
        self.ip_address_scan,
        hostnames=hostnames,
    )
    hostnames_model.save(org_uuid)
    logger.info(
        "All reverse hostnames retrieved and saved for IP address %s."
        % (ip_address_uuid,)
    )


@websight_app.task(bind=True, base=IpAddressTask)
def get_historic_dns_data_for_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Get historic DNS data related to the given IP address.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now getting historic DNS data for IP address %s."
        % (ip_address_uuid,)
    )
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "ip_address_uuid": ip_address_uuid,
        "ip_address_scan_uuid": ip_address_scan_uuid,
    }
    task_sigs.append(get_historic_dns_data_for_ip_address_from_dnsdb.si(**task_kwargs))
    if len(task_sigs) > 1:
        collection_sig = group(task_sigs)
    else:
        collection_sig = task_sigs[0]
    self.finish_after(signature=collection_sig)


@websight_app.task(bind=True, base=IpAddressTask)
def get_historic_dns_data_for_ip_address_from_dnsdb(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Get historic DNS data related to the given IP address from DNS DB.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now getting historic DNS data for IP address %s."
        % (ip_address_uuid,)
    )
    domains = enumerate_domains_for_ip_address(self.ip_address.address, after=config.dns_dnsdb_ip_history_time_in_past)
    if len(domains) == 0:
        logger.info(
            "No historic domains found for IP address %s."
            % (ip_address_uuid,)
        )
        return
    history_model = IpDomainHistoryModel.from_database_model(
        self.ip_address_scan,
        domain_names=domains,
        history_collection_method="dnsdb",
        history_distance=config.dns_dnsdb_ip_history_time_in_past,
    )
    history_model.save(org_uuid)


@websight_app.task(bind=True, base=IpAddressTask)
def get_as_data_for_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Retrieve data about the AS block where the given IP address resides.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now retrieving AS data for IP address %s."
        % (ip_address_uuid,)
    )


@websight_app.task(bind=True, base=IpAddressTask)
def get_whois_data_for_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Retrieve WHOIS data for the given IP address.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now retrieving WHOIS information for IP address %s."
        % (ip_address_uuid,)
    )
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "ip_address_uuid": ip_address_uuid,
        "ip_address_scan_uuid": ip_address_scan_uuid,
    }
    task_sigs.append(get_arin_whois_data_for_ip_address.si(**task_kwargs))
    if len(task_sigs) > 1:
        collection_sig = group(task_sigs)
    else:
        collection_sig = task_sigs[0]
    self.finish_after(signature=collection_sig)


@websight_app.task(bind=True, base=IpAddressTask)
def get_arin_whois_data_for_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Retrieve ARIN WHOIS data for the given IP address.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now retrieving ARIN WHOIS information for IP address %s."
        % (ip_address_uuid,)
    )
    networks = self.inspector.get_arin_related_networks(full_details=True)
    for network in networks:
        whois_model = network.to_es_model(
            model=self.ip_address_scan,
            whois_data_source="arin",
        )
        whois_model.save(org_uuid)
    logger.info(
        "All ARIN WHOIS network data retrieved for IP address %s."
        % (ip_address_uuid,)
    )


@websight_app.task(bind=True, base=IpAddressTask)
def scan_ip_address_for_network_services(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Scan the given IP address to determine what network services are live on the host.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now scanning IP address %s for live network services."
        % (ip_address_uuid,)
    )
    task_sigs = []
    tcp_ports = get_tcp_scan_ports_for_org(org_uuid=org_uuid, db_session=self.db_session)
    if len(tcp_ports) > 0:
        task_sigs.append(scan_ip_address_for_tcp_network_services.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_uuid,
            ip_address_scan_uuid=ip_address_scan_uuid,
            ports=tcp_ports,
        ))
    udp_ports = get_udp_scan_ports_for_org(org_uuid=org_uuid, db_session=self.db_session)
    if len(udp_ports) > 0:
        task_sigs.append(scan_ip_address_for_udp_network_services.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_uuid,
            ip_address_scan_uuid=ip_address_scan_uuid,
            ports=udp_ports,
        ))
    if len(task_sigs) == 0:
        logger.info(
            "No ports were included to scan for the organization (%s)."
            % (org_uuid,)
        )
        return
    if len(task_sigs) > 1:
        scanning_sig = group(task_sigs)
    else:
        scanning_sig = task_sigs[0]
    self.finish_after(signature=scanning_sig)


@websight_app.task(bind=True, base=IpAddressTask)
def scan_ip_address_for_tcp_network_services(
        self,
        org_uuid=None,
        ip_address_uuid=None,
        ip_address_scan_uuid=None,
        ports=None,
):
    """
    Scan the given IP address for TCP network services.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :param ports: A list of integers representing the ports to scan.
    :return: None
    """
    logger.info(
        "Now scanning IP address %s for TCP ports (%s total)."
        % (ip_address_uuid, len(ports))
    )
    start_time = DatetimeHelper.now()
    open_tcp_ports = self.inspector.scan_for_open_tcp_ports(ports=ports, db_session=self.db_session)
    end_time = DatetimeHelper.now()
    port_statuses = []
    for open_port in open_tcp_ports:
        port_statuses.append({
            "port_number": open_port,
            "port_status": "open",
            "port_protocol": "tcp",
        })
    scan_model = IpPortScanModel.from_database_model(
        self.ip_address_scan,
        port_results=port_statuses,
        port_scan_method="nmap",
        scan_start_time=start_time,
        scan_end_time=end_time,
    )
    scan_model.save(org_uuid)
    logger.info(
        "IP address %s scanned for %s TCP ports (%s were open)."
        % (ip_address_uuid, len(ports), len(open_tcp_ports))
    )


@websight_app.task(bind=True, base=IpAddressTask)
def scan_ip_address_for_udp_network_services(
        self,
        org_uuid=None,
        ip_address_uuid=None,
        ip_address_scan_uuid=None,
        ports=None,
):
    """
    Scan the given IP address for UDP network services.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :param ports: A list of integers representing the ports to scan.
    :return: None
    """
    logger.info(
        "Now scanning IP address %s for UDP ports (%s total)."
        % (ip_address_uuid, len(ports))
    )
    start_time = DatetimeHelper.now()
    open_udp_ports = self.inspector.scan_for_open_udp_ports(ports=ports, db_session=self.db_session)
    end_time = DatetimeHelper.now()
    port_statuses = []
    for open_port in open_udp_ports:
        port_statuses.append({
            "port_number": open_port,
            "port_status": "open",
            "port_protocol": "udp",
        })
    scan_model = IpPortScanModel.from_database_model(
        self.ip_address_scan,
        port_results=port_statuses,
        port_scan_method="nmap",
        scan_start_time=start_time,
        scan_end_time=end_time,
    )
    scan_model.save(org_uuid)
    logger.info(
        "IP address %s scanned for %s UDP ports (%s were open)."
        % (ip_address_uuid, len(ports), len(open_udp_ports))
    )


@websight_app.task(bind=True, base=IpAddressTask)
def inspect_network_services_from_ip_address(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Kick off all of the necessary tasks to inspect the live network services associated with the given IP
    address.
    :param org_uuid: The UUID of the organization to perform data retrieval on behalf of.
    :param ip_address_uuid: The UUID of the IP address to retrieve data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate retrieved data with.
    :return: None
    """
    logger.info(
        "Now kicking off all tasks to inspect network services on IP address %s."
        % (ip_address_uuid,)
    )
    self.wait_for_es()
    open_ports = get_open_ports_from_ip_address_scan(ip_address_scan_uuid=ip_address_scan_uuid, org_uuid=org_uuid)
    task_sigs = []
    for port_number, port_protocol in open_ports:
        network_service = get_or_create_network_service_from_org_ip(
            ip_uuid=ip_address_uuid,
            port=port_number,
            protocol=port_protocol,
            db_session=self.db_session,
            discovered_by="ip address scan",
        )
        task_sigs.append(scan_network_service.si(
            org_uuid=org_uuid,
            network_service_uuid=network_service.uuid,
            check_liveness=False,
            liveness_cause="ip address scan",
        ))
    if len(task_sigs) == 0:
        logger.info(
            "No network services were found to be open for IP address %s."
            % (ip_address_uuid,)
        )
        return
    group(task_sigs).apply_async()


@websight_app.task(bind=True, base=IpAddressTask)
def create_report_for_ip_address_scan(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Create an Elasticsearch report for the data gathered during the given IP address scan.
    :param org_uuid: The UUID of the organization to create the report on behalf of.
    :param ip_address_uuid: The UUID of the IP address to create the report for.
    :param ip_address_scan_uuid: The UUID of the IP address scan to associate the report with.
    :return: None
    """
    logger.info(
        "Now creating report for IP address scan %s."
        % (ip_address_scan_uuid,)
    )
    self.wait_for_es()
    inspector = IpAddressScanInspector(ip_address_scan_uuid=ip_address_scan_uuid, db_session=self.db_session)
    report = inspector.to_es_model(model=self.ip_address_scan)
    report.save(org_uuid)


@websight_app.task(bind=True, base=IpAddressTask)
def update_ip_address_scan_elasticsearch(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Update Elasticsearch to reflect that all of the data associated with the given IP address scan is the
    most recent data collected for the given IP address.
    :param org_uuid: The UUID of the organization that owns the IP address.
    :param ip_address_uuid: The UUID of the IP address to update data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to update data about.
    :return: None
    """
    logger.info(
        "Now updating Elasticsearch to reflect that IP address scan %s is most recent for IP address %s."
        % (ip_address_scan_uuid, ip_address_uuid)
    )
    self.wait_for_es()
    update_ip_address_scan_latest_state(scan_uuid=ip_address_scan_uuid, latest_state=True, org_uuid=org_uuid)
    self.wait_for_es()
    update_not_ip_address_scan_latest_state(
        scan_uuid=ip_address_scan_uuid,
        latest_state=False,
        org_uuid=org_uuid,
        ip_address_uuid=ip_address_uuid,
    )
    logger.info(
        "Elasticsearch updated to reflect IP address scan %s is latest for IP address %s."
        % (ip_address_scan_uuid, ip_address_uuid)
    )


@websight_app.task(bind=True, base=IpAddressTask)
def update_ip_address_scan_completed(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Update the given IP address scan to indicate that the scan has completed.
    :param org_uuid: The UUID of the organization that owns the IP address scan.
    :param ip_address_uuid: The UUID of the IP address to update data about.
    :param ip_address_scan_uuid: The UUID of the IP address scan to update data about.
    :return: None
    """
    logger.info(
        "Now updating IP address scan %s to mark as completed."
        % (ip_address_scan_uuid,)
    )
    update_ip_address_scan_completed_op(scan_uuid=ip_address_scan_uuid, db_session=self.db_session)
    self.db_session.commit()
    logger.info(
        "IP address scan %s updated to show it has completed."
        % (ip_address_scan_uuid,)
    )


@websight_app.task(bind=True, base=IpAddressTask)
def update_ip_address_scanning_status(self, ip_address_uuid=None, scanning_status=None):
    """
    Update the given IP address to set its current scanning status to the given value.
    :param ip_address_uuid: The UUID of the IP address to update.
    :param scanning_status: The value to set scanning_status to on the given IP address.
    :return: None
    """
    logger.info(
        "Now updating IP address %s to have scanning status of %s."
        % (ip_address_uuid, scanning_status)
    )
    update_ip_address_scanning_status_op(
        db_session=self.db_session,
        ip_address_uuid=ip_address_uuid,
        scanning_status=scanning_status,
    )
    self.db_session.commit()


@websight_app.task(bind=True, base=IpAddressTask)
def apply_flags_to_ip_address_scan(self, org_uuid=None, ip_address_uuid=None, ip_address_scan_uuid=None):
    """
    Apply all of the relevant flags to the data collected during the given IP address scan.
    :param org_uuid: The UUID of the organization that flags are being applied for.
    :param ip_address_uuid: The UUID of the IP address that was scanned.
    :param ip_address_scan_uuid: The UUID of the IP address scan.
    :return: None
    """
    logger.info(
        "Now applying flags to IP address scan %s."
        % (ip_address_scan_uuid,)
    )
    flags = get_all_ip_flags_for_organization(org_uuid=org_uuid, db_session=self.db_session)
    if len(flags) == 0:
        logger.info(
            "No IP address flags found for organization %s."
            % (org_uuid,)
        )
        return
    task_sigs = []
    for flag in flags:
        flag_type = "default" if isinstance(flag, DefaultFlag) else "organization"
        task_sigs.append(apply_flag_to_ip_address_scan.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_uuid,
            ip_address_scan_uuid=ip_address_scan_uuid,
            flag_uuid=flag.uuid,
            flag_type=flag_type,
        ))
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=IpAddressTask)
def apply_flag_to_ip_address_scan(
        self,
        org_uuid=None,
        ip_address_uuid=None,
        ip_address_scan_uuid=None,
        flag_uuid=None,
        flag_type=None,
):
    """
    Apply the given flag to data collected during the given IP address scan.
    :param org_uuid: The UUID of the organization that flags are being applied for.
    :param ip_address_uuid: The UUID of the IP address that was scanned.
    :param ip_address_scan_uuid: The UUID of the IP address scan.
    :param flag_uuid: The UUID of the flag to apply.
    :param flag_type: The type of the flag being applied.
    :return: None
    """
    logger.info(
        "Now applying flag %s to IP address scan %s."
        % (flag_uuid, ip_address_scan_uuid)
    )
    flagger = DataFlagger.from_flag_uuid(flag_uuid=flag_uuid, flag_type=flag_type, db_session=self.db_session)
    flagger.filter_by_ip_address_scan(ip_address_scan_uuid)
    self.wait_for_es()
    flagger.apply_flag_to_organization(org_uuid=org_uuid)
    logger.info(
        "Flag %s successfully applied to IP address scan %s."
        % (flag_uuid, ip_address_scan_uuid)
    )
