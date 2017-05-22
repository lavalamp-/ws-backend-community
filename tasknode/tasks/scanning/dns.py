# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group, chain
from celery.utils.log import get_task_logger

from wselasticsearch.models import DnsRecordModel, SubdomainEnumerationModel
from wselasticsearch.query import SubdomainEnumerationQuery
from wselasticsearch.ops import get_ip_addresses_from_domain_name_scan, get_all_subdomains_from_domain_scan_enumeration
from wselasticsearch.ops import update_domain_name_scan_latest_state, update_not_domain_name_scan_latest_state
from ..base import DatabaseTask
from ...app import websight_app
from lib.sqlalchemy import get_all_included_domain_uuids_for_organization, create_domain_scan_for_domain, get_name_from_domain, \
    DomainNameScan, get_ip_address_for_organization, DomainName, get_all_domains_for_organization, \
    check_domain_name_scanning_status, get_or_create_domain_name_for_organization
from lib import ConfigManager, FilesystemHelper, RegexLib, BaseWsException, \
    enumerate_subdomains_for_domain as enumerate_subdomains_for_domain_dnsdb
from lib.inspection import DomainInspector
from .ip import scan_ip_address_for_services_from_domain, scan_ip_address
from lib.sqlalchemy import update_domain_name_scan_completed as update_domain_name_scan_completed_op, \
    update_domain_name_scanning_status as update_domain_name_scanning_status_op

config = ConfigManager.instance()
logger = get_task_logger(__name__)


class UnsupportedTldException(BaseWsException):
    """
    This is an exception for denoting that a given TLD is not supported.
    """

    _message = "Unsupported TLD"


def get_dns_record_types_for_scan():
    """
    Get a list of tuples containing (1) the DNS record type and (2) whether or not resolved IPs
    associated with the record type should be scanned from the DNS record types file.
    :return: A list of tuples containing (1) the DNS record type and (2) whether or not resolved IPs
    associated with the record type should be scanned from the DNS record types file.
    """
    file_contents = FilesystemHelper.get_file_contents(path=config.files_dns_record_types_path)
    file_contents = [x.strip() for x in file_contents.strip().split("\n")]
    to_return = []
    for line in file_contents:
        line_split = line.split(",")
        if line_split[1] == "True":
            to_return.append((
                line_split[0],
                True if line_split[2] == "True" else False,
            ))
    return to_return


def get_supported_tlds():
    """
    Get a list of strings representing the TLDs that are supported for subdomain discovery.
    :return: A list of strings representing the TLDs that are supported for subdomain discovery.
    """
    file_contents = FilesystemHelper.get_file_contents(path=config.files_tlds_path)
    return [x.strip() for x in file_contents.strip().split("\n")]


def get_parent_domain_for_subdomain_discovery(parent_domain):
    """
    Get the domain that should be queried for subdomain discovery based on the given parent domain.
    :param parent_domain: The parent domain to check.
    :return: The domain that should be queried for subdomain discovery based on the given parent domain.
    """
    supported_tlds = get_supported_tlds()
    for supported_tld in supported_tlds:
        if parent_domain.lower().endswith(supported_tld):
            without_tld = parent_domain[: -1 * len(supported_tld)]
            if "." in without_tld:
                return "%s%s" % (without_tld[without_tld.rfind(".") + 1:], supported_tld)
            else:
                return "%s%s" % (without_tld, supported_tld)
    raise UnsupportedTldException(
        "The domain TLD in the domain %s is not supported."
        % (parent_domain,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def enumerate_subdomains_for_domain(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_name=None,
        domain_scan_uuid=None,
        scan_endpoints=True,
):
    """
    Enumerate subdomains for the given domain name and associate the results with the given domain UUID.
    :param org_uuid: The UUID of the organization to perform the task for.
    :param domain_uuid: The UUID of the parent domain that this subdomain scan is invoked on behalf of.
    :param domain_name: The domain name to enumerate subdomains for.
    :param scan_endpoints: Whether or not to scan any endpoints found during resolution of discovered
    subdomains.
    :return: None
    """
    logger.info(
        "Now enumerating subdomains for domain name %s (parent domain %s)."
        % (domain_name, domain_uuid)
    )
    try:
        parent_domain = get_parent_domain_for_subdomain_discovery(domain_name)
    except UnsupportedTldException:
        logger.warning(
            "The domain %s contains a TLD that we do not support."
            % (domain_name,)
        )
        return
    task_sigs = []
    discovery_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "domain_uuid": domain_uuid,
        "domain_scan_uuid": domain_scan_uuid,
        "parent_domain": parent_domain,
    }
    discovery_sigs.append(enumerate_subdomains_by_dnsdb.si(**task_kwargs))
    task_sigs.append(group(discovery_sigs))
    task_kwargs["scan_endpoints"] = scan_endpoints
    task_sigs.append(create_and_inspect_domains_from_subdomain_enumeration.si(**task_kwargs))
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=DatabaseTask)
def create_and_inspect_domains_from_subdomain_enumeration(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        parent_domain=None,
        scan_endpoints=True,
):
    """
    Process the contents of all subdomain enumerations for the given domain name scan, create new domains
    for those subdomains that are new, and invoke scans for the domains as necessary.
    :param org_uuid: The UUID of the organization that subdomains were enumerated for.
    :param domain_uuid: The UUID of the domain name related to this inspection.
    :param domain_scan_uuid: The UUID of the domain name scan that this enumeration is a part of.
    :param parent_domain: The parent domain that was queried.
    :param scan_endpoints: Whether or not to scan IP addresses associated with resolved IP addresses of
    the domains.
    :return: None
    """
    logger.info(
        "Now creating an inspecting domains from subdomain enumeration of parent domain %s."
        % (parent_domain,)
    )
    self.wait_for_es()
    subdomains = get_all_subdomains_from_domain_scan_enumeration(
        org_uuid=org_uuid,
        parent_domain=parent_domain,
        domain_scan_uuid=domain_scan_uuid,
    )
    task_sigs = []
    for subdomain in subdomains:
        domain_name = get_or_create_domain_name_for_organization(
            db_session=self.db_session,
            name=subdomain,
            added_by="subdomain_enum",
            org_uuid=org_uuid,
        )
        self.db_session.add(domain_name)
        do_scan = check_domain_name_scanning_status(
            db_session=self.db_session,
            domain_uuid=domain_name.uuid,
            update_status=False,
        )
        if do_scan:
            task_sigs.append(scan_domain_name.si(
                org_uuid=org_uuid,
                domain_uuid=domain_name.uuid,
                enumerate_subdomains=False,
                scan_ip_addresses=scan_endpoints,
            ))
    self.db_session.commit()
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=DatabaseTask)
def enumerate_subdomains_by_dnsdb(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        parent_domain=None,
):
    """
    Enumerate subdomains for the given parent domain by using DNSDB.
    :param org_uuid: The UUID of the organization to enumerate subdomains on behalf of.
    :param domain_uuid: The UUID of the domain name that enumeration was started on behalf of.
    :param domain_scan_uuid: The UUID of the domain name scan that enumeration was started on behalf of.
    :param parent_domain: The parent domain name to discover subdomains for.
    :return: None
    """
    logger.info(
        "Now enumerating subdomains for parent domain of %s through DNSDB."
        % (parent_domain,)
    )
    query = SubdomainEnumerationQuery(max_size=True)
    query.filter_by_parent_domain(parent_domain)
    query.filter_by_enumeration_method("dnsdb")
    result = query.search(org_uuid)
    if result.results_count > 0:
        logger.info(
            "Parent domain of %s has already been queried via DNSDB."
            % (parent_domain,)
        )
        return
    subdomains = enumerate_subdomains_for_domain_dnsdb(parent_domain)
    es_model = SubdomainEnumerationModel.from_database_model_uuid(
        uuid=domain_scan_uuid,
        db_session=self.db_session,
        enumeration_method="dnsdb",
        child_domains=subdomains,
        parent_domain=parent_domain,
    )
    es_model.save(org_uuid)


@websight_app.task(bind=True, base=DatabaseTask)
def scan_domain_name(
        self,
        org_uuid=None,
        domain_uuid=None,
        enumerate_subdomains=False,
        scan_ip_addresses=True,
        scan_network_services=True,
        inspect_network_services=True,
):
    """
    Initiate a domain name scan for the given organization and domain.
    :param org_uuid: The UUID of the organization to initiate the domain name scan for.
    :param enumerate_subdomains: Whether or not to enumerate subdomains of the give domain.
    :param domain_uuid: The UUID of the domain to scan.
    :param scan_ip_addresses: Whether or not to perform scanning of the IP addresses associated with the
    domain name.
    :param scan_network_services: Whether or not to scan network services on associated IP addresses.
    :param inspect_network_services: Whether or not to perform inspection of live network services on
    associated IP addresses.
    :return: None
    """
    logger.info(
        "Now scanning domain name %s."
        % (domain_uuid,)
    )
    should_scan = check_domain_name_scanning_status(
        db_session=self.db_session,
        domain_uuid=domain_uuid,
        update_status=True,
    )
    if not should_scan:
        logger.info(
            "Should not scan domain name %s. Returning."
            % (domain_uuid,)
        )
    domain_name = DomainName.by_uuid(uuid=domain_uuid, db_session=self.db_session)
    domain_scan = create_domain_scan_for_domain(domain_uuid)
    self.db_session.add(domain_scan)
    self.db_session.commit()
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "domain_uuid": domain_uuid,
        "domain_scan_uuid": str(domain_scan.uuid),
        "domain_name": domain_name.name,
    }
    initial_group = []
    if enumerate_subdomains:
        initial_group.append(enumerate_subdomains_for_domain.si(**task_kwargs))
    initial_group.append(gather_data_for_domain_name.si(**task_kwargs))
    task_sigs.append(group(initial_group))
    task_kwargs.pop("domain_name")
    task_sigs.append(create_report_for_domain_name_scan.si(**task_kwargs))
    task_sigs.append(update_domain_name_scan_elasticsearch.si(**task_kwargs))
    task_sigs.append(update_domain_name_scan_completed.si(**task_kwargs))
    task_kwargs["scan_network_services"] = scan_network_services
    task_kwargs["inspect_network_services"] = inspect_network_services
    if scan_ip_addresses:
        task_sigs.append(scan_ip_addresses_for_domain_name_scan.si(**task_kwargs))
    scanning_status_signature = update_domain_name_scanning_status.si(
        domain_uuid=domain_uuid,
        scanning_status=False,
    )
    task_sigs.append(scanning_status_signature)
    logger.info(
        "Now kicking off all necessary tasks to scan domain name %s."
        % (domain_uuid,)
    )
    canvas_sig = chain(task_sigs, link_error=scanning_status_signature)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=DatabaseTask)
def scan_ip_addresses_for_domain_name_scan(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        scan_network_services=True,
        inspect_network_services=True,
):
    """
    Kick off tasks for scanning all of the IP addresses discovered during the given domain name scan.
    :param org_uuid: The UUID of the organization to scan endpoints for.
    :param domain_uuid: The UUID of the domain name that was scanned.
    :param domain_scan_uuid: The UUID of the domain name scan to kick off endpoint scanning tasks
    for.
    :param scan_network_services: Whether or not to scan network services on associated IP addresses.
    :param inspect_network_services: Whether or not to perform inspection of live network services on
    associated IP addresses.
    :return: None
    """
    logger.info(
        "Now kicking off all tasks for scanning IP addresses associated with domain %s."
        % (domain_uuid,)
    )
    ip_addresses = get_ip_addresses_from_domain_name_scan(domain_scan_uuid=domain_scan_uuid, org_uuid=org_uuid)
    if len(ip_addresses) == 0:
        logger.info(
            "No IP addresses discovered for domain %s during scan %s."
            % (domain_uuid, domain_scan_uuid)
        )
        return
    domain = DomainName.by_uuid(db_session=self.db_session, uuid=domain_uuid)
    task_sigs = []
    for ip_address in ip_addresses:
        ip_address_model = get_ip_address_for_organization(
            db_session=self.db_session,
            org_uuid=org_uuid,
            ip_address=ip_address,
        )
        domain.ip_addresses.append(ip_address_model)
        task_sigs.append(scan_ip_address.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_model.uuid,
            scan_network_services=scan_network_services,
            inspect_network_services=inspect_network_services,
        ))
    group(task_sigs).apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def update_domain_name_scanning_status(self, domain_uuid=None, scanning_status=None):
    """
    Update the scanning status found on the given domain name to the given value.
    :param domain_uuid: The UUID of the domain name to update.
    :param scanning_status: The value to set scanning status to.
    :return: None
    """
    logger.info(
        "Now updating scanning status of domain name %s to %s."
        % (domain_uuid, scanning_status)
    )
    update_domain_name_scanning_status_op(
        db_session=self.db_session,
        domain_uuid=domain_uuid,
        scanning_status=scanning_status,
    )
    self.db_session.commit()


@websight_app.task(bind=True, base=DatabaseTask)
def gather_data_for_domain_name(self, org_uuid=None, domain_uuid=None, domain_scan_uuid=None, domain_name=None):
    """
    Perform all data gathering for the given domain name.
    :param org_uuid: The UUID of the organization to retrieve data for.
    :param domain_uuid: The UUID of the parent domain name that is being investigated.
    :param domain_scan_uuid: The UUID of the domain name scan that this task is a part of.
    :param domain_name: The domain name to collect data for.
    :return: None
    """
    logger.info(
        "Now gathering information for domain name %s (parent domain %s)."
        % (domain_name, domain_uuid)
    )
    record_types = get_dns_record_types_for_scan()
    task_sigs = []
    for record_type, do_scanning in record_types:
        task_sigs.append(resolve_domain_name_for_organization.si(
            org_uuid=org_uuid,
            domain_uuid=domain_uuid,
            domain_scan_uuid=domain_scan_uuid,
            record_type=record_type,
        ))
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=DatabaseTask)
def create_report_for_domain_name_scan(self, org_uuid=None, domain_uuid=None, domain_scan_uuid=None):
    """
    Create the domain name report containing the results of the given domain name scan.
    :param org_uuid: The UUID of the organization to create the report for.
    :param domain_uuid: The UUID of the domain name that was scanned.
    :param domain_scan_uuid: The UUID of the domain name scan to create the report for.
    :return: None
    """
    logger.info(
        "Now creating report for domain name scan %s."
        % (domain_scan_uuid,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def initiate_dns_scans_for_organization(self, org_uuid=None, scan_endpoints=True):
    """
    Kick off all of the necessary tasks for inspecting attributes of DNS records for all of
    the domains associated with the given organization.
    :param org_uuid: The UUID of the organization to kick off tasks for.
    :param scan_endpoints: Whether or not to do application-layer scanning for hosts associated with
    the domain names owned by the given organization.
    :return: None
    """
    logger.info(
        "Now initiating DNS scans for organization %s."
        % (org_uuid,)
    )
    domain_uuids = get_all_included_domain_uuids_for_organization(
        db_session=self.db_session,
        org_uuid=org_uuid,
    )
    logger.info(
        "There are a total of %s domains associated with organization %s."
        % (len(domain_uuids), org_uuid)
    )
    task_sigs = []
    for domain_uuid in domain_uuids:
        task_sigs.append(initiate_dns_scan_for_organization.si(
            org_uuid=org_uuid,
            domain_uuid=domain_uuid,
            scan_endpoints=scan_endpoints,
        ))
    logger.info(
        "Now kicking off %s tasks as a group to scan domains for organization %s."
        % (len(task_sigs), org_uuid)
    )
    canvas_sig = group(task_sigs)
    canvas_sig.apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def scan_endpoints_from_domain_inspection(self, org_uuid=None, domain_uuid=None, domain_scan_uuid=None):
    """
    Create the necessary database objects to scan all endpoints associated with the given domain scan
    and kick off tasks to perform the scanning.
    :param org_uuid: The UUID of the organization to scan endpoints for.
    :param domain_uuid: The UUID of the domain name that was scanned.
    :param domain_scan_uuid: The UUID of the domain name scan to kick off endpoint scanning tasks
    for.
    :return: None
    """
    logger.info(
        "Now kicking off scans for endpoints discovered during domain name %s and scan %s. Organization is %s."
        % (domain_uuid, domain_scan_uuid, org_uuid)
    )
    ip_addresses = get_ip_addresses_from_domain_name_scan(domain_scan_uuid=domain_scan_uuid, org_uuid=org_uuid)
    logger.info(
        "A total of %s IP addresses were discovered during domain name scan %s."
        % (len(ip_addresses), domain_scan_uuid)
    )
    if len(ip_addresses) == 0:
        return
    domain = DomainName.by_uuid(db_session=self.db_session, uuid=domain_uuid)
    task_sigs = []
    for ip_address in ip_addresses:
        ip_address_model = get_ip_address_for_organization(
            db_session=self.db_session,
            org_uuid=org_uuid,
            ip_address=ip_address,
        )
        domain.ip_addresses.append(ip_address_model)
        task_sigs.append(scan_ip_address_for_services_from_domain.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_model.uuid,
            domain_uuid=domain_uuid,
            domain_scan_uuid=domain_scan_uuid,
        ))
    logger.info(
        "Now kicking off %s tasks to perform scanning of endpoints associated with domain %s. Organization is %s."
        % (len(task_sigs), domain_uuid, org_uuid)
    )
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=DatabaseTask)
def initiate_dns_scan_for_organization(
        self,
        org_uuid=None,
        domain_uuid=None,
        scan_endpoints=True,
):
    """
    Kick off all of the necessary tasks for inspecting the domain name referenced by domain_uuid.
    :param org_uuid: The UUID of the organization to kick the scan off for.
    :param domain_uuid: The UUID of the domain name to inspect.
    :param scan_endpoints: Whether or not to do application-layer scanning for hosts associated with
    the referenced domain.
    :return: None
    """
    logger.info(
        "Now initiating DNS scan for domain %s and organization %s."
        % (domain_uuid, org_uuid)
    )
    domain_scan = create_domain_scan_for_domain(domain_uuid)
    self.db_session.add(domain_scan)
    self.commit_session()
    logger.info(
        "Domain scan for domain %s will be %s."
        % (domain_uuid, domain_scan.uuid)
    )
    record_types = get_dns_record_types_for_scan()
    task_sigs = []
    resolution_sigs = []
    for record_type, do_scanning in record_types:
        resolution_sigs.append(resolve_domain_name_for_organization.si(
            org_uuid=org_uuid,
            domain_uuid=domain_uuid,
            domain_scan_uuid=domain_scan.uuid,
            record_type=record_type,
        ))
    task_sigs.append(group(resolution_sigs))
    if scan_endpoints:
        task_sigs.append(scan_endpoints_from_domain_inspection.si(
            org_uuid=org_uuid,
            domain_uuid=domain_uuid,
            domain_scan_uuid=domain_scan.uuid,
        ))
    task_sigs.append(update_domain_name_scan_elasticsearch.si(
        org_uuid=org_uuid,
        domain_scan_uuid=domain_scan.uuid,
        domain_uuid=domain_uuid,
    ))
    task_sigs.append(update_domain_name_scan_completed.si(
        org_uuid=org_uuid,
        domain_scan_uuid=domain_scan.uuid,
    ))
    logger.info(
        "Now kicking off %s tasks as a group to scan the domain %s on behalf of organization %s. Scan UUID is %s."
        % (len(resolution_sigs) + 2, domain_uuid, org_uuid, domain_scan.uuid)
    )
    canvas_sig = chain(task_sigs)
    canvas_sig.apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def update_domain_name_scan_elasticsearch(self, org_uuid=None, domain_scan_uuid=None, domain_uuid=None):
    """
    Update Elasticsearch so that all of the data gathered during the given domain name scan is marked
    as being part of the latest scan, and that all other data collected during other scans is marked
    as not being part of the latest scan.
    :param org_uuid: The UUID of the organization to perform the task for.
    :param domain_scan_uuid: The UUID of the domain name scan.
    :param domain_uuid: The UUID of the domain name.
    :return: None
    """
    logger.info(
        "Now updating domain name scan %s in Elasticsearch. Organization is %s."
        % (domain_scan_uuid, org_uuid)
    )
    self.wait_for_es()
    update_domain_name_scan_latest_state(scan_uuid=domain_scan_uuid, latest_state=True, org_uuid=org_uuid)
    self.wait_for_es()
    update_not_domain_name_scan_latest_state(
        scan_uuid=domain_scan_uuid,
        latest_state=False,
        org_uuid=org_uuid,
        domain_uuid=domain_uuid,
    )
    logger.info(
        "Elasticsearch updated to reflect that domain name scan %s is the latest domain name scan for "
        "domain %s and organization %s."
        % (domain_scan_uuid, domain_uuid, org_uuid)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def update_domain_name_scan_completed(self, org_uuid=None, domain_scan_uuid=None, domain_uuid=None):
    """
    Update the referenced domain name scan to reflect that the scan has completed.
    :param org_uuid: The UUID of the organization that owns the domain name.
    :param domain_scan_uuid: The UUID of the domain name scan to update.
    :param domain_uuid: The UUID of the domain name that was scanned.
    :return: None
    """
    logger.info(
        "Now updating domain name scan %s to show that scan has completed. Organization is %s."
        % (domain_scan_uuid, org_uuid)
    )
    update_domain_name_scan_completed_op(scan_uuid=domain_scan_uuid, db_session=self.db_session)
    self.commit_session()
    logger.info(
        "Domain name scan %s updated to show it has completed."
        % (domain_scan_uuid,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def resolve_domain_name_for_organization(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        record_type=None,
):
    """
    Resolve all of the IP addresses associated with the given domain on behalf of
    the given organization.
    :param org_uuid: The UUID of the organization to resolve the domain name on behalf of.
    :param domain_uuid: The UUID of the domain name to resolve.
    :param domain_scan_uuid: The UUID of the domain name scan that this resolution is part of.
    :param record_type: The DNS record type to query.
    :return: None
    """
    domain_name = DomainName.by_uuid(db_session=self.db_session, uuid=domain_uuid)
    logger.info(
        "Now resolving domain %s (%s) on behalf of organization %s. Domain scan is %s."
        % (domain_uuid, domain_name.name, org_uuid, domain_scan_uuid)
    )
    inspector = DomainInspector(domain_name.name)
    record_set = inspector.get_record(record_type)
    if len(record_set) == 0:
        logger.info(
            "No records found for domain name %s and record type %s."
            % (domain_name.name, record_type)
        )
        return
    logger.info(
        "A total of %s records were returned for record type of %s for domain %s."
        % (len(record_set), record_type, domain_name.name)
    )
    domain_name_scan = DomainNameScan.by_uuid(db_session=self.db_session, uuid=domain_scan_uuid)
    for record in record_set:
        contains_ip = RegexLib.ipv4_address_regex.match(record)
        if contains_ip:
            logger.info(
                "Record of type %s contains IP address (%s)."
                % (record_type, record)
            )
        record_model = DnsRecordModel.from_database_model(
            database_model=domain_name_scan,
            record_type=record_type,
            record_content=str(record),
            contains_ip_address=bool(contains_ip),
        )
        record_model.save(org_uuid)

