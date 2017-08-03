# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseInspector
from ...mixin import ElasticsearchableMixin
from lib.sqlalchemy import DomainName, get_domain_uuid_from_domain_scan, get_org_uuid_from_domain_name_scan
from wselasticsearch.query import DnsRecordQuery


class DomainNameScanInspector(BaseInspector, ElasticsearchableMixin):
    """
    This is an inspector class that is responsible for analyzing the results of a single domain name
    scan for the purpose of creating a single DomainNameReport.
    """

    # Class Members

    # Instantiation

    def __init__(self, domain_scan_uuid=None, db_session=None):
        super(DomainNameScanInspector, self).__init__()
        self._domain_scan_uuid = domain_scan_uuid
        self._org_uuid = None
        self._domain_uuid = None
        self._domain_name = None
        self._dns_record_models = None
        self._domain_resolutions = None
        self._subdomain_dns_record_models = None
        self._subdomains = None
        self._related_ips = None
        self.db_session = db_session

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import DomainNameReportModel
        return DomainNameReportModel

    # Public Methods

    # Protected Methods

    def _to_es_model(self):
        from wselasticsearch.models import DomainNameReportModel
        return DomainNameReportModel(
            domain_name=self.domain_name.name,
            resolutions=self.domain_resolutions,
            has_resolutions=self.has_resolutions,
            subdomains=self.subdomains,
            related_ips=self.related_ips,
        )

    # Private Methods

    def __get_dns_record_models(self):
        """
        Get an Elasticsearch response containing all of the DNS records that were retrieved
        during the domain name scan.
        :return: an Elasticsearch response containing all of the DNS records that were retrieved
        during the domain name scan.
        """
        query = DnsRecordQuery(max_size=True)
        query.filter_by_domain_name_scan(self.domain_scan_uuid)
        return query.search(self.org_uuid)

    def __get_subdomain_dns_record_models(self):
        """
        Get an Elasticsearch response containing all of the subdomain DNS record models that exist for
        subdomains of the inspected domain.
        :return: an Elasticsearch response containing all of the subdomain DNS record models that
        exist for subdomains of the inspected domain.
        """
        query = DnsRecordQuery(max_size=True)
        query.filter_by_subdomain(self.domain_name.name)
        return query.search(self.org_uuid)

    # Properties

    @property
    def dns_record_models(self):
        """
        Get an Elasticsearch response containing all of the DNS records that were retrieved
        during the domain name scan.
        :return: an Elasticsearch response containing all of the DNS records that were retrieved
        during the domain name scan.
        """
        if self._dns_record_models is None:
            self._dns_record_models = self.__get_dns_record_models()
        return self._dns_record_models

    @property
    def domain_name(self):
        """
        Get the domain name that was scanned during the given domain name scan.
        :return: the domain name that was scanned during the given domain name scan.
        """
        if self._domain_name is None:
            self._domain_name = DomainName.by_uuid(uuid=self.domain_uuid, db_session=self.db_session)
        return self._domain_name

    @property
    def domain_resolutions(self):
        """
        Get a list of dictionaries containing the resolutions that were performed during this
        domain name scan.
        :return: a list of dictionaries containing the resolutions that were performed during
        this domain name scan.
        """
        if self._domain_resolutions is None:
            resolutions = {}
            for result in self.dns_record_models.results:
                if result["_source"]["record_type"] not in resolutions:
                    resolutions[result["_source"]["record_type"]] = []
                resolutions[result["_source"]["record_type"]].append(result["_source"]["record_content"])
            self._domain_resolutions = [{"record_type": k, "record_contents": v} for k, v in resolutions.iteritems()]
        return self._domain_resolutions

    @property
    def domain_scan_uuid(self):
        """
        Get the UUID of the domain name scan that this inspector is responsible for inspecting.
        :return: the UUID of the domain name scan that this inspector is responsible for inspecting.
        """
        return self._domain_scan_uuid

    @property
    def domain_uuid(self):
        """
        Get the UUID of the domain name that is related to this domain name scan.
        :return: the UUID of the domain name that is related to this domain name scan.
        """
        if self._domain_uuid is None:
            self._domain_uuid = get_domain_uuid_from_domain_scan(
                db_session=self.db_session,
                domain_scan_uuid=self.domain_scan_uuid,
            )
        return self._domain_uuid

    @property
    def has_resolutions(self):
        """
        Get whether or not this domain name resolved to any records.
        :return: whether or not this domain name resolved to any records.
        """
        return self.dns_record_models.results_count > 0

    @property
    def inspection_target(self):
        return "Domain Name Scan %s" % (self.domain_scan_uuid,)

    @property
    def org_uuid(self):
        """
        Get the UUID of the organization that owns the inspected domain name.
        :return: the UUID of the organization that owns the inspected domain name.
        """
        if self._org_uuid is None:
            self._org_uuid = get_org_uuid_from_domain_name_scan(
                db_session=self.db_session,
                domain_scan_uuid=self.domain_scan_uuid,
            )
        return self._org_uuid

    @property
    def related_ips(self):
        """
        Get a list of dictionaries containing the IP addresses that this domain resolves to.
        :return: a list of dictionaries containing the IP addresses that this domain resolves to.
        """
        if self._related_ips is None:
            related_ips = []
            for result in self.dns_record_models.results:
                if result["_source"]["contains_ip_address"]:
                    related_ips.append({
                        "ip_address": result["_source"]["record_content"],
                        "ip_address_uuid": result["_source"]["ip_address_uuid"],
                    })
            self._related_ips = related_ips
        return self._related_ips

    @property
    def subdomains(self):
        """
        Get a list of dictionaries describing the subdomains found for this parent domain.
        :return: a list of dictionaries describing the subdomains found for this parent domain.
        """
        if self._subdomains is None:
            subdomains = []
            for result in self.subdomain_dns_record_models.results:
                if result["_source"]["domain_name"].lower().endswith(self.domain_name.name.lower()):
                    subdomains.append({
                        "subdomain": result["_source"]["domain_name"],
                        "domain_uuid": result["_source"]["domain_uuid"],
                    })
            self._subdomains = subdomains
        return self._subdomains

    @property
    def subdomain_dns_record_models(self):
        """
        Get an Elasticsearch response containing all of the subdomain DNS record models that exist for
        subdomains of the inspected domain.
        :return: an Elasticsearch response containing all of the subdomain DNS record models that
        exist for subdomains of the inspected domain.
        """
        if self._subdomain_dns_record_models is None:
            self._subdomain_dns_record_models = self.__get_subdomain_dns_record_models()
        return self._subdomain_dns_record_models

    # Representation and Comparison
