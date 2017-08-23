# -*- coding: utf-8 -*-
from __future__ import absolute_import

from collections import Counter
from celery import group, chain
from celery.utils.log import get_task_logger
from requests.exceptions import SSLError, ReadTimeout

from wselasticsearch.ops import get_fingerprint_data_for_network_service_scan
from wselasticsearch.models import VirtualHostModel
from ......app import websight_app
from .....base import NetworkServiceTask
from lib.sqlalchemy import get_all_domains_for_organization
from lib.inspection import WebServiceInspector
from lib import ConfigManager

logger = get_task_logger(__name__)
config = ConfigManager.instance()


def pick_baseline(results):
    """
    Iterate over the tuples in results (should be returned by get_fingerprint_data_for_network_service_scan)
    and pick a tuple that best represents a baseline truth for use in virtual host fingerprint matching.
    :param results: A list of tuples returned by get_fingerprint_data_for_network_service_scan.
    :return: A tuple from results to use as a baseline for analysis of virtual hosts.
    """
    hashes = [primary_hash for _, _, _, primary_hash, _, _, _ in results]
    most_common_hash = Counter(hashes).most_common(1)[0][0]
    for result in results:
        if result[3] == most_common_hash:
            return result


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def discover_virtual_hosts_for_web_service(
        self,
        org_uuid=None,
        network_service_scan_uuid=None,
        network_service_uuid=None,
        use_ssl=None,
        order_uuid=None,
):
    """
    Discover all of the virtual hosts for the given web service.
    :param org_uuid: The organization to discover virtual hosts on behalf of.
    :param network_service_scan_uuid: The UUID of the network service scan that this virtual host discovery is
    a part of.
    :param network_service_uuid: The UUID of the network service where the web service resides.
    :param use_ssl: Whether or not to use SSL to interact with the remote web service.
    :return: None
    """
    logger.info(
        "Now discovering virtual hosts for network service %s. Organization is %s, scan is %s."
        % (network_service_uuid, org_uuid, network_service_scan_uuid)
    )
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "network_service_uuid": network_service_uuid,
        "network_service_scan_uuid": network_service_scan_uuid,
        "use_ssl": use_ssl,
        "order_uuid": order_uuid,
    }
    task_sigs.append(fingerprint_virtual_hosts.si(**task_kwargs))
    task_sigs.append(assess_virtual_host_fingerprints.si(**task_kwargs))
    logger.info(
        "Now kicking off virtual host fingerprinting and assessment tasks for scan %s, organization %s."
        % (network_service_scan_uuid, org_uuid)
    )
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def assess_virtual_host_fingerprints(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        use_ssl=None,
        order_uuid=None,
):
    """
    Evaluate the contents of the virtual host fingerprints gathered during the given network scan
    and create virtual host models for all of the virtual hosts that were discovered.
    :param org_uuid: The UUID of the organization to assess virtual hosts for.
    :param network_service_uuid: The UUID of the network service that virtual hosts were checked for.
    :param network_service_scan_uuid: The UUID of the network service scan to assess virtual host fingerprints
    for.
    :param use_ssl: Whether or not to use SSL to connect to the remote endpoint.
    :return: None
    """
    logger.info(
        "Now assessing the results of virtual host fingerprinting for service %s, scan %s. Organization is %s."
        % (network_service_uuid, network_service_scan_uuid, org_uuid)
    )
    self.wait_for_es()
    fingerprint_results = get_fingerprint_data_for_network_service_scan(
        org_uuid=org_uuid,
        scan_uuid=network_service_scan_uuid,
        over_ssl=use_ssl,
    )
    try:
        ip_address, port, protocol = self.get_endpoint_information()
        inspector = WebServiceInspector(ip_address=ip_address, port=port, use_ssl=use_ssl)
        response = inspector.get()
        base_fingerprint = response.to_es_model(model_uuid=network_service_scan_uuid, db_session=self.db_session)
        base_response_code = base_fingerprint.response_code
        base_response_has_content = base_fingerprint.response_has_content
        base_response_mime_type = base_fingerprint.response_mime_type
        base_response_secondary_hash = base_fingerprint.response_secondary_hash
        base_hostname = base_fingerprint.hostname
    except SSLError as e:
        ip_address, port, protocol = self.get_endpoint_information()
        logger.warning(
            "SSLError thrown when retrieving baseline for endpoint %s (%s:%s): %s."
            % (network_service_uuid, ip_address, port, e.message)
        )
        baseline = pick_baseline(fingerprint_results)
        base_response_code = baseline[0]
        base_response_has_content = baseline[1]
        base_response_mime_type = baseline[2]
        base_response_secondary_hash = baseline[4]
        base_hostname = baseline[6]
    vhost_domains = []
    for code, has_content, mime_type, p_hash, s_hash, over_ssl, hostname in fingerprint_results:
        if base_response_code != code:
            vhost_domains.append((hostname, "status-code"))
        elif base_response_has_content and not has_content:
            vhost_domains.append((hostname, "has-content"))
        elif base_response_mime_type != mime_type:
            vhost_domains.append((hostname, "mime-type"))
        elif base_response_secondary_hash != s_hash:
            vhost_domains.append((hostname, "content-hash"))
    logger.info(
        "Out of %s fingerprints, %s appear to indicate different virtual hosts for service %s."
        % (len(fingerprint_results), len(vhost_domains), network_service_uuid)
    )
    network_service_scan = self.network_service_scan
    for hostname, discovery_method in vhost_domains:
        vhost_model = VirtualHostModel.from_database_model(
            database_model=network_service_scan,
            hostname=hostname,
            discovery_method=discovery_method,
        )
        vhost_model.save(org_uuid)
    base_model = VirtualHostModel.from_database_model(
        database_model=network_service_scan,
        hostname=base_hostname,
        discovery_method="baseline",
    )
    base_model.save(org_uuid)
    logger.info(
        "Elasticsearch updated to reflect results of processing virtual host fingerprints for service %s, "
        "scan %s, organization %s."
        % (network_service_uuid, network_service_scan_uuid, org_uuid)
    )


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def fingerprint_virtual_hosts(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        use_ssl=None,
        order_uuid=None,
):
    """
    Perform fingerprinting for virtual hosts for the given network service.
    :param org_uuid: The UUID of the organization to perform fingerprinting on behalf of.
    :param network_service_uuid: The UUID of the network service to fingerprint.
    :param network_service_scan_uuid: The UUID of the network service scan that this fingerprinting is a part
    of.
    :param use_ssl: Whether or not to use SSL to connect to the remote endpoint.
    :return: None
    """
    logger.info(
        "Now starting to fingerprint virtual hosts for service %s. Organization is %s."
        % (network_service_uuid, org_uuid)
    )
    domain_names = get_all_domains_for_organization(org_uuid=org_uuid, db_session=self.db_session)
    task_sigs = []
    for domain_name in domain_names:
        task_sigs.append(fingerprint_virtual_host.si(
            org_uuid=org_uuid,
            network_service_uuid=network_service_uuid,
            network_service_scan_uuid=network_service_scan_uuid,
            use_ssl=use_ssl,
            hostname=domain_name,
        ))
    logger.info(
        "Now kicking off a total of %s tasks to fingerprint service %s."
        % (len(task_sigs), network_service_uuid)
    )
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def fingerprint_virtual_host(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        use_ssl=None,
        hostname=None,
        order_uuid=None,
):
    """
    Get a virtual host fingerprint from the web service running at the given network service for
    the given hostname.
    :param org_uuid: The UUID of the organization to retrieve a fingerprint for.
    :param network_service_uuid: The UUID of the network service where the web service resides.
    :param network_service_scan_uuid: The UUID of the network service scan that this fingerprinting is a part
    of.
    :param use_ssl: Whether or not to use SSL to connect to the remote endpoint.
    :param hostname: The hostname to submit a request for.
    :return: None
    """
    logger.info(
        "Now retrieving virtual host fingerprint for service %s with hostname %s. Organization is %s."
        % (network_service_uuid, hostname, org_uuid)
    )
    ip_address, port, protocol = self.get_endpoint_information()
    inspector = WebServiceInspector(ip_address=ip_address, port=port, use_ssl=use_ssl, hostname=hostname)
    try:
        response = inspector.get()
    except (SSLError, ReadTimeout) as e:
        logger.error(
            "Error thrown when retrieving fingerprint: %s %s."
            % (e.__class__.__name__, e.message)
        )
        return
    logger.info(
        "Fingerprint retrieved for virtual host %s on service %s."
        % (hostname, network_service_uuid)
    )
    fingerprint_model = response.to_es_model(model_uuid=network_service_scan_uuid, db_session=self.db_session)
    fingerprint_model.save(org_uuid)
    logger.info("Fingerprint pushed to Elasticsearch successfully.")
