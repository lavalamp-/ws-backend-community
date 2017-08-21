# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time
from celery import group, chain
from celery.utils.log import get_task_logger
import socket

from nassl._nassl import OpenSSLError

from wselasticsearch.query import BulkElasticsearchQuery
from ....app import websight_app
from ...base import ServiceTask, NetworkServiceTask
from lib import ConfigManager, FilesystemHelper, ValidationHelper, get_storage_helper
from wselasticsearch.models import SslSupportModel, SslCertificateModel, \
    SslVulnerabilityModel
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, Tlsv11ScanCommand, \
    Tlsv12ScanCommand, Sslv20ScanCommand, Sslv30ScanCommand
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.plugins.session_resumption_plugin import SessionResumptionSupportScanCommand
from lib.sqlalchemy import get_related_uuids_from_network_service_scan, \
    get_latest_network_service_scan_uuids_for_organization, get_all_ssl_flags_for_organization, DefaultFlag
from wselasticsearch.ops import delete_ssl_inspection_documents_for_network_service_scan
from .analysis import create_ssl_support_report_for_network_service_scan
from wselasticsearch.flags import DataFlagger

logger = get_task_logger(__name__)
config = ConfigManager.instance()


def get_ssl_cipher_suite_commands():
    """
    Get a list of tuples containing (1) the SSL protocol string and (2) the Sslyze command to test
    for connectivity for the given SSL protocol.
    :return: A list of tuples containing (1) the SSL protocol string and (2) the Sslyze command to test
    for connectivity for the given SSL protocol.
    """
    return [
        ("sslv2", Sslv20ScanCommand),
        ("sslv3", Sslv30ScanCommand),
        ("tlsv1", Tlsv10ScanCommand),
        ("tlsv1.1", Tlsv11ScanCommand),
        ("tlsv1.2", Tlsv12ScanCommand),
    ]


def get_ssl_vulnerabilities_command_map():
    """
    Get a dictionary that maps strings to commands supported by Sslyze for enumerating SSL-based
    vulnerabilities.
    :return: A dictionary that maps strings to commands supported by Sslyze for enumerating SSL-based
    vulnerabilities.
    """
    return {
        "fallback_scsv": {
            "command": FallbackScsvScanCommand,
            "fields": ["supports_fallback_scsv"],
        },
        "heartbleed": {
            "command": HeartbleedScanCommand,
            "fields": ["is_vulnerable_to_heartbleed"],
        },
        "ccs_injection": {
            "command": OpenSslCcsInjectionScanCommand,
            "fields": ["is_vulnerable_to_ccs_injection"],
        },
        "session_renegotiation": {
            "command": SessionRenegotiationScanCommand,
            "fields": ["accepts_client_renegotiation", "supports_secure_renegotiation"],
        },
        "session_resumption": {
            "command": SessionResumptionSupportScanCommand,
            "fields": ["is_ticket_resumption_supported"],
        },
    }


#TESTME
def upload_certificate_to_s3(org_uuid=None, cert_string=None, local_file_path=None):
    """
    Upload the given SSL certificate to AWS S3 and return a tuple describing where it was uploaded
    to.
    :param org_uuid: The UUID of the organization that this SSL certificate is being uploaded on behalf
    of.
    :param cert_string: A string containing the SSL certificate.
    :param local_file_path: A local file path that can be used to write data to.
    :return: A tuple containing (1) the bucket where the file was uploaded to and (2) the key it
    was uploaded under.
    """
    FilesystemHelper.write_to_file(file_path=local_file_path, data=cert_string)
    storage_helper = get_storage_helper()
    response, key = storage_helper.upload_ssl_certificate(
        org_uuid=org_uuid,
        local_file_path=local_file_path,
        bucket=config.storage_bucket,
    )
    return config.storage_bucket, key


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def inspect_tcp_service_for_ssl_support(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Collect all possible information about SSL support found on the referenced network service.
    :param org_uuid: The UUID of the organization to collect information on behalf of.
    :param network_service_uuid: The UUID of the network service to check for SSL support.
    :param network_service_scan_uuid: The UUID of the network service scan that this SSL support check is associated
    with.
    :return: None
    """
    ip_address = self.network_service.ip_address.address
    port = self.network_service.port
    logger.info(
        "Now inspecting TCP service at %s:%s for SSL data for organization %s. Scan is %s."
        % (ip_address, port, org_uuid, network_service_scan_uuid)
    )
    initial_check = self.inspector.check_ssl_support()
    if not initial_check:
        logger.info(
            "Service at %s:%s does not support any version of SSL."
            % (ip_address, port)
        )
        return
    logger.info(
        "Service at %s:%s supports SSL. Now kicking off subtasks to check for various version support."
        % (ip_address, port)
    )
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "network_service_uuid": network_service_uuid,
        "network_service_scan_uuid": network_service_scan_uuid,
        "order_uuid": order_uuid,
    }
    collection_sigs = []
    scan_config = self.order.scan_config
    if scan_config.ssl_enumerate_vulns:
        collection_sigs.append(enumerate_vulnerabilities_for_ssl_service.si(**task_kwargs))
    if scan_config.ssl_enumerate_cipher_suites:
        collection_sigs.append(enumerate_cipher_suites_for_ssl_service.si(**task_kwargs))
    if scan_config.ssl_retrieve_cert:
        collection_sigs.append(retrieve_ssl_certificate_for_tcp_service.si(**task_kwargs))
    task_sigs.append(group(collection_sigs))
    task_sigs.append(create_ssl_support_report_for_network_service_scan.si(**task_kwargs))
    task_sigs.append(apply_flags_to_ssl_support_scan.si(**task_kwargs))
    canvas_sig = chain(task_sigs)
    logger.info(
        "Now kicking off %s tasks to inspect SSL support for network service %s."
        % (len(collection_sigs) + 1, network_service_uuid)
    )
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def enumerate_vulnerabilities_for_ssl_service(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Enumerate all of the SSL-based vulnerabilities for the given SSL/TLS service.
    :param org_uuid: The UUID of the organization to enumerate SSL vulnerabilities on behalf of.
    :param network_service_uuid: The UUID of the network service that is being scanned.
    :param network_service_scan_uuid: The UUID of the network service scan that this enumeration is
    a part of.
    :return: None
    """
    logger.info(
        "Now enumerating SSL vulnerabilities for network service %s."
        % (network_service_uuid,)
    )
    task_sigs = []
    command_map = get_ssl_vulnerabilities_command_map()
    for command_name in command_map.keys():
        task_sigs.append(test_ssl_service_for_ssl_vulnerability.si(
            org_uuid=org_uuid,
            network_service_uuid=network_service_uuid,
            network_service_scan_uuid=network_service_scan_uuid,
            vulnerability_name=command_name,
            order_uuid=order_uuid,
        ))
    canvas_sig = group(task_sigs)
    logger.info(
        "Now kicking off %s tasks to inspect network service %s for SSL vulnerabilities."
        % (len(task_sigs), network_service_uuid)
    )
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def test_ssl_service_for_ssl_vulnerability(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        vulnerability_name=None,
        order_uuid=None,
):
    """
    Test the given network service for the specified SSL vulnerability.
    :param org_uuid: The UUID of the organization to enumerate SSL vulnerabilities on behalf of.
    :param network_service_uuid: The UUID of the network service that is being scanned.
    :param network_service_scan_uuid: The UUID of the network service scan that this enumeration is
    a part of.
    :param vulnerability_name: A string representing the vulnerability to test for.
    :return: None
    """
    logger.info(
        "Now testing network service %s for SSL vulnerability %s."
        % (network_service_uuid, vulnerability_name)
    )
    command_map = get_ssl_vulnerabilities_command_map()
    ValidationHelper.validate_in(to_check=vulnerability_name, contained_by=command_map.keys())
    command = command_map[vulnerability_name]["command"]
    ip_address = self.network_service.ip_address.address
    port = self.network_service.port
    scanner = SynchronousScanner()
    server_info = ServerConnectivityInfo(hostname=ip_address, ip_address=ip_address, port=port)
    try:
        server_info.test_connectivity_to_server()
    except ServerConnectivityError as e:
        logger.warning(
            "ServerConnectivityError thrown when attempting to test SSL at %s:%s for %s vulnerability: %s"
            % (ip_address, port, vulnerability_name, e.message)
        )
        return
    try:
        result = scanner.run_scan_command(server_info, command())
        vuln_model = SslVulnerabilityModel.from_database_model(
            self.network_service_scan,
            test_errored=False,
            vuln_test_name=vulnerability_name,
        )
        vuln_model.test_results = []
        for field in command_map[vulnerability_name]["fields"]:
            vuln_model.test_results.append({
                "key": field,
                "value": getattr(result, field),
            })
        vuln_model.save(org_uuid)
    except (socket.error, OpenSSLError):
        vuln_model = SslVulnerabilityModel.from_database_model(
            self.network_service_scan,
            test_errored=True,
        )
        vuln_model.save(org_uuid)
    logger.info(
        "Network service %s successfully tested for SSL vulnerability %s."
        % (network_service_uuid, vulnerability_name)
    )


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def enumerate_cipher_suites_for_ssl_service(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Enumerate all of the cipher suites that the given SSL/TLS service supports.
    :param org_uuid: The UUID of the organization to enumerate cipher suites on behalf of.
    :param network_service_uuid: The UUID of the network service that is being scanned.
    :param network_service_scan_uuid: The UUID of the network service scan that this enumeration is
    a part of.
    :return: None
    """
    logger.info(
        "Now enumerating supported cipher suites for network service %s."
        % (network_service_uuid,)
    )
    ip_address = self.network_service.ip_address.address
    port = self.network_service.port
    server_info = ServerConnectivityInfo(hostname=ip_address, ip_address=ip_address, port=port)
    try:
        server_info.test_connectivity_to_server()
    except ServerConnectivityError as e:
        logger.warning(
            "ServerConnectivityError thrown when attempting to inspect SSL at %s:%s: %s"
            % (ip_address, port, e.message)
        )
        return
    scanner = SynchronousScanner()
    bulk_query = BulkElasticsearchQuery()
    network_service_scan = self.network_service_scan
    for ssl_protocol, command in get_ssl_cipher_suite_commands():
        result = scanner.run_scan_command(server_info, command())
        ssl_support_record = SslSupportModel.from_database_model(
            network_service_scan,
            ssl_version=ssl_protocol,
            supported=len(result.accepted_cipher_list) > 0,
        )
        ssl_support_record.accepted_ciphers = [cipher.name for cipher in result.accepted_cipher_list]
        ssl_support_record.rejected_ciphers = [cipher.name for cipher in result.rejected_cipher_list]
        ssl_support_record.errored_ciphers = [cipher.name for cipher in result.errored_cipher_list]
        ssl_support_record.preferred_cipher = result.preferred_cipher.name if result.preferred_cipher else None
        bulk_query.add_model_for_indexing(model=ssl_support_record, index=org_uuid)
    logger.info("All cipher suite information converted to Elasticsearch data. Now updating via bulk query.")
    bulk_query.save()
    logger.info(
        "Bulk query completed. SSL cipher suites enumerated for network service %s."
        % (network_service_uuid,)
    )


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def retrieve_ssl_certificate_for_tcp_service(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Retrieve the SSL certificate associated with the given TCP service.
    :param org_uuid: The UUID of the organization to collect information on behalf of.
    :param network_service_uuid: The UUID of the network service to retrieve the SSL certificate for.
    :param network_service_scan_uuid: The UUID of the network service scan that this SSL certificate retrieval is associated
    with.
    :return: None
    """
    cert_string, pem_cert = self.inspector.get_ssl_certificate()
    cert_model = SslCertificateModel.from_database_model(self.network_service_scan)
    cert_model = SslCertificateModel.populate_from_x509_certificate(certificate=pem_cert, to_populate=cert_model)
    bucket, key = upload_certificate_to_s3(
        org_uuid=org_uuid,
        local_file_path=self.get_temporary_file_path(),
        cert_string=cert_string,
    )
    cert_model.set_s3_attributes(bucket=bucket, key=key, file_type="ssl certificate")
    cert_model.save(org_uuid)
    logger.info(
        "Successfully retrieved and saved SSL certificate for TCP service %s. Organization was %s, scan was %s."
        % (network_service_uuid, org_uuid, network_service_scan_uuid)
    )


@websight_app.task(bind=True, base=ServiceTask)
def redo_ssl_support_inspection_for_organization(self, org_uuid=None):
    """
    Perform SSL support inspection for all of the network services associated with the given organization
    again.
    :param org_uuid: The UUID of the organization to re-do SSL support inspection for.
    :return: None
    """
    logger.info(
        "Now redo'ing SSL support inspection for organization %s."
        % (org_uuid,)
    )
    network_service_scan_uuids = get_latest_network_service_scan_uuids_for_organization(
        org_uuid=org_uuid,
        db_session=self.db_session,
    )
    task_sigs = []
    for network_service_scan_uuid in network_service_scan_uuids:
        task_sigs.append(redo_ssl_support_inspection_for_network_service_scan.si(
            network_service_scan_uuid=network_service_scan_uuid,
        ))
    canvas_sig = group(task_sigs)
    logger.info(
        "Now kicking off %s tasks to redo SSL inspection for organization %s."
        % (len(task_sigs), org_uuid)
    )
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=ServiceTask)
def redo_ssl_support_inspection_for_network_service_scan(self, network_service_scan_uuid=None):
    """
    Perform SSL support inspection for the given network service scan again.
    :param network_service_scan_uuid: The UUID of the network service scan to perform SSL support inspection
    for.
    :return: None
    """
    from .base import update_network_service_scan_elasticsearch
    logger.info(
        "Now redo'ing SSL support inspection for network service scan %s."
        % (network_service_scan_uuid,)
    )
    org_uuid, network_service_uuid = get_related_uuids_from_network_service_scan(
        network_service_scan_uuid=network_service_scan_uuid,
        db_session=self.db_session,
    )
    delete_ssl_inspection_documents_for_network_service_scan(
        org_uuid=org_uuid,
        network_service_scan_uuid=network_service_scan_uuid,
    )
    task_sigs = []
    task_sigs.append(inspect_tcp_service_for_ssl_support.si(
        org_uuid=org_uuid,
        network_service_uuid=network_service_uuid,
        network_service_scan_uuid=network_service_scan_uuid,
    ))
    task_sigs.append(update_network_service_scan_elasticsearch.si(
        network_service_scan_uuid=network_service_scan_uuid,
        org_uuid=org_uuid,
        network_service_uuid=network_service_uuid,
    ))
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def apply_flags_to_ssl_support_scan(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Apply all of the necessary flags to the results of data gathered during the given SSL support scan.
    :param org_uuid: The UUID of the organization that owns the network service.
    :param network_service_uuid: The UUID of the network service that was scanned.
    :param network_service_scan_uuid: The UUID of the network service scan that this task is a part of.
    :return: None
    """
    logger.info(
        "Now applying flags to SSL support scan %s."
        % (network_service_uuid,)
    )
    flags = get_all_ssl_flags_for_organization(org_uuid=org_uuid, db_session=self.db_session)
    if len(flags) == 0:
        logger.info(
            "No SSL flags found for organization %s."
            % (org_uuid,)
        )
        return
    task_sigs = []
    for flag in flags:
        flag_type = "default" if isinstance(flag, DefaultFlag) else "organization"
        task_sigs.append(apply_flag_to_ssl_support_scan.si(
            org_uuid=org_uuid,
            network_service_uuid=network_service_uuid,
            network_service_scan_uuid=network_service_scan_uuid,
            flag_uuid=flag.uuid,
            flag_type=flag_type,
            order_uuid=order_uuid,
        ))
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def apply_flag_to_ssl_support_scan(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        flag_uuid=None,
        flag_type=None,
        order_uuid=None,
):
    """
    Apply the given flag to the given SSL support scan.
    :param org_uuid: The UUID of the organization that owns the network service.
    :param network_service_uuid: The UUID of the network service that was scanned.
    :param network_service_scan_uuid: The UUID of the network service scan that this task is a part of.
    :param flag_uuid: The UUID of the flag to apply.
    :param flag_type: The type of flag to apply.
    :return: None
    """
    logger.info(
        "Now applying flag %s to ssl support scan %s."
        % (flag_uuid, network_service_scan_uuid)
    )
    flagger = DataFlagger.from_flag_uuid(flag_uuid=flag_uuid, flag_type=flag_type, db_session=self.db_session)
    flagger.filter_by_network_service_scan(network_service_scan_uuid)
    self.wait_for_es()
    flagger.apply_flag_to_organization(org_uuid=org_uuid)
    logger.info(
        "Flag %s successfully applied to SSL support scan %s."
        % (flag_uuid, network_service_scan_uuid)
    )
