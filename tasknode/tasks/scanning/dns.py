# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group, chain
from celery.utils.log import get_task_logger

from wselasticsearch.models import DnsRecordModel, SubdomainEnumerationModel
from wselasticsearch.query import SubdomainEnumerationQuery
from wselasticsearch.ops import get_ip_addresses_from_domain_name_scan, get_all_subdomains_from_domain_scan_enumeration
from wselasticsearch.ops import update_domain_name_scan_latest_state, update_not_domain_name_scan_latest_state
from ..base import DomainNameTask
from ...app import websight_app
from lib.sqlalchemy import create_domain_scan_for_domain, \
    get_ip_address_for_organization, \
    check_domain_name_scanning_status, get_or_create_domain_name_for_organization
from lib import ConfigManager, FilesystemHelper, RegexLib, BaseWsException, \
    enumerate_subdomains_for_domain as enumerate_subdomains_for_domain_dnsdb
from lib.inspection import DomainNameScanInspector
from .ip import scan_ip_address
from lib.sqlalchemy import update_domain_name_scan_completed as update_domain_name_scan_completed_op, \
    update_domain_name_scanning_status as update_domain_name_scanning_status_op

config = ConfigManager.instance()
logger = get_task_logger(__name__)


class UnsupportedTldException(BaseWsException):
    """
    This is an exception for denoting that a given TLD is not supported.
    """

    _message = "Unsupported TLD"


#TESTME
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


#TESTME
def get_supported_tlds():
    """
    Get a list of strings representing the TLDs that are supported for subdomain discovery.
    :return: A list of strings representing the TLDs that are supported for subdomain discovery.
    """
    file_contents = FilesystemHelper.get_file_contents(path=config.files_tlds_path)
    return [x.strip() for x in file_contents.strip().split("\n")]


#TESTME
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


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def enumerate_subdomains_for_domain(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_name=None,
        domain_scan_uuid=None,
        order_uuid=None,
):
    """
    Enumerate subdomains for the given domain name and associate the results with the given domain UUID.
    :param org_uuid: The UUID of the organization to perform the task for.
    :param domain_uuid: The UUID of the parent domain that this subdomain scan is invoked on behalf of.
    :param domain_name: The domain name to enumerate subdomains for.
    :param order_uuid: The UUID of the order that this enumeration is associated with.
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
        "order_uuid": order_uuid,
    }
    discovery_sigs.append(enumerate_subdomains_by_dnsdb.si(**task_kwargs))
    task_sigs.append(group(discovery_sigs))
    task_sigs.append(create_and_inspect_domains_from_subdomain_enumeration.si(**task_kwargs))
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def create_and_inspect_domains_from_subdomain_enumeration(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        parent_domain=None,
        order_uuid=None,
):
    """
    Process the contents of all subdomain enumerations for the given domain name scan, create new domains
    for those subdomains that are new, and invoke scans for the domains as necessary.
    :param org_uuid: The UUID of the organization that subdomains were enumerated for.
    :param domain_uuid: The UUID of the domain name related to this inspection.
    :param domain_scan_uuid: The UUID of the domain name scan that this enumeration is a part of.
    :param parent_domain: The parent domain that was queried.
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
            ))
    self.db_session.commit()
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def enumerate_subdomains_by_dnsdb(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        parent_domain=None,
        order_uuid=None,
):
    """
    Enumerate subdomains for the given parent domain by using DNSDB.
    :param org_uuid: The UUID of the organization to enumerate subdomains on behalf of.
    :param domain_uuid: The UUID of the domain name that enumeration was started on behalf of.
    :param domain_scan_uuid: The UUID of the domain name scan that enumeration was started on behalf of.
    :param parent_domain: The parent domain name to discover subdomains for.
    :param order_uuid: The UUID of the order that this domain name scan is associated
    with.
    :return: None
    """
    logger.info(
        "Now enumerating subdomains for parent domain of %s through DNSDB."
        % (parent_domain,)
    )
    #TODO roll this into an elasticsearch op
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
    es_model = SubdomainEnumerationModel.from_database_model(
        self.domain_scan,
        enumeration_method="dnsdb",
        child_domains=subdomains,
        parent_domain=parent_domain,
    )
    es_model.save(org_uuid)


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def scan_domain_name(self, org_uuid=None, domain_uuid=None, order_uuid=None):
    """
    Initiate a domain name scan for the given organization and domain.
    :param org_uuid: The UUID of the organization to initiate the domain name scan for.
    :param domain_uuid: The UUID of the domain to scan.
    :param order_uuid: The UUID of the order that this domain name scan is associated
    with.
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
    domain_scan = create_domain_scan_for_domain(self.domain_uuid)
    self.db_session.add(domain_scan)
    self.db_session.commit()
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "domain_uuid": domain_uuid,
        "domain_scan_uuid": str(domain_scan.uuid),
        "domain_name": self.domain.name,
        "order_uuid": order_uuid,
    }
    initial_group = []
    scan_config = self.order.scan_config
    if scan_config.dns_enumerate_subdomains:
        initial_group.append(enumerate_subdomains_for_domain.si(**task_kwargs))
    initial_group.append(gather_data_for_domain_name.si(**task_kwargs))
    task_sigs.append(group(initial_group))
    task_kwargs.pop("domain_name")
    task_sigs.append(create_report_for_domain_name_scan.si(**task_kwargs))
    task_sigs.append(update_domain_name_scan_elasticsearch.si(**task_kwargs))
    task_sigs.append(update_domain_name_scan_completed.si(**task_kwargs))
    if scan_config.dns_scan_resolutions:
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


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def scan_ip_addresses_for_domain_name_scan(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        order_uuid=None,
):
    """
    Kick off tasks for scanning all of the IP addresses discovered during the given domain name scan.
    :param org_uuid: The UUID of the organization to scan endpoints for.
    :param domain_uuid: The UUID of the domain name that was scanned.
    :param domain_scan_uuid: The UUID of the domain name scan to kick off endpoint scanning tasks
    for.
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
    task_sigs = []
    for ip_address in ip_addresses:
        ip_address_model = get_ip_address_for_organization(
            db_session=self.db_session,
            org_uuid=org_uuid,
            ip_address=ip_address,
        )
        self.domain.ip_addresses.append(ip_address_model)
        task_sigs.append(scan_ip_address.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_model.uuid,
            order_uuid=order_uuid,
        ))
    group(task_sigs).apply_async()


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def update_domain_name_scanning_status(
        self,
        domain_uuid=None,
        scanning_status=None,
        order_uuid=None,
):
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


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def gather_data_for_domain_name(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        domain_name=None,
        order_uuid=None,
):
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
            order_uuid=order_uuid,
        ))
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def create_report_for_domain_name_scan(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        order_uuid=None,
):
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
    self.wait_for_es()
    inspector = DomainNameScanInspector(domain_scan_uuid=domain_scan_uuid, db_session=self.db_session)
    report = inspector.to_es_model(model_uuid=domain_scan_uuid, db_session=self.db_session)
    report.save(org_uuid)
    logger.info(
        "Successfully generated domain name scan report for domain name scan %s."
        % (domain_scan_uuid,)
    )


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def update_domain_name_scan_elasticsearch(
        self,
        org_uuid=None,
        domain_scan_uuid=None,
        domain_uuid=None,
        order_uuid=None,
):
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


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def update_domain_name_scan_completed(
        self,
        org_uuid=None,
        domain_scan_uuid=None,
        domain_uuid=None,
        order_uuid=None,
):
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


#USED
@websight_app.task(bind=True, base=DomainNameTask)
def resolve_domain_name_for_organization(
        self,
        org_uuid=None,
        domain_uuid=None,
        domain_scan_uuid=None,
        record_type=None,
        order_uuid=None,
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
    domain_name = self.domain
    logger.info(
        "Now resolving domain %s (%s) on behalf of organization %s. Domain scan is %s."
        % (domain_uuid, self.domain_name.name, org_uuid, domain_scan_uuid)
    )
    record_set = self.inspector.get_record(record_type)
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
    for record in record_set:
        contains_ip = RegexLib.ipv4_address_regex.match(record)
        if contains_ip:
            logger.info(
                "Record of type %s contains IP address (%s)."
                % (record_type, record)
            )
        record_model = DnsRecordModel.from_database_model(
            database_model=self.domain_scan,
            record_type=record_type,
            record_content=str(record),
            contains_ip_address=bool(contains_ip),
        )
        record_model.save(org_uuid)
