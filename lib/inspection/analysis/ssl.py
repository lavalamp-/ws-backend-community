# -*- coding: utf-8 -*-
from __future__ import absolute_import

import OpenSSL
import certifi
from datetime import datetime
import requests
from cryptography.hazmat.primitives import serialization
import logging

from ..base import BaseInspector
from lib import ElasticsearchableMixin, BaseWsException, FilesystemHelper, RegexLib, DatetimeHelper, \
    ConfigManager, get_storage_helper
from lib.sqlalchemy import get_org_uuid_from_network_service_scan
from wselasticsearch.query import SslCertificateQuery, SslVulnerabilitiesQuery, SslSupportQuery, SslVulnerabilityQuery

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class InvalidCertificateTimeError(BaseWsException):
    """
    This is an exception for denoting that a timestamp found in an SSL certificate does not follow
    expected format.
    """

    _message = "Unknown SSL certificate timestamp."


class UnknownKeyTypeError(BaseWsException):
    """
    This is an exception for denoting that the inspector found a key type that it does not recognize.
    """

    _message = "Unknown key type found."


class ExtensionNotFoundError(BaseWsException):
    """
    This is an exception for denoting that the inspector was passed an extension name that was not
    contained within the referenced SSL certificate.
    """

    _message = "Extension not found."


#1d3556ed-7092-4365-8e88-d4fb2e4d77c7
class SslSupportInspector(BaseInspector, ElasticsearchableMixin):
    """
    This is an inspector class that is responsible for analyzing the results of SSL analysis performed
    during the course of a network scan.
    """

    # Class Members

    # Instantiation

    def __init__(self, network_service_scan_uuid=None, db_session=None):
        super(SslSupportInspector, self).__init__()
        self._network_scan_uuid = network_service_scan_uuid
        self.db_session = db_session
        self._ssl_certificate = None
        self._ssl_certificate_model = None
        self._ssl_vulnerabilities_model = None
        self._org_uuid = None
        self._cert_start_time = None
        self._cert_invalid_time = None
        self._cert_key_type = None
        self._cert_public_key = None
        self._cert_content = None
        self._cert_extension_names = None
        self._cert_authority_key_id = None
        self._cert_subject_key_id = None
        self._cert_extended_key_usage = None
        self._cert_certificate_policies = None
        self._cert_crl_distribution_points = None
        self._cert_subject_alt_name = None
        self._cert_authority_info_access = None
        self._cert_validation_chain = None
        self._ssl_store_context = None
        self._cert_is_valid = None
        self._ssl_support_records = None
        self._cert_extensions = None
        self._ssl_vulnerability_models = None
        self._cert_policy_oids = None
        self._env_oids = None

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import SslSupportReportModel
        return SslSupportReportModel

    # Public Methods

    # Protected Methods

    def _to_es_model(self):
        from wselasticsearch.models import SslSupportReportModel
        return SslSupportReportModel(
            cert_serial_number=self.cert_serial_number,
            cert_version=self.cert_version,
            cert_has_start_time=self.cert_has_start_time,
            cert_start_time=self.cert_start_time,
            cert_has_invalid_time=self.cert_has_invalid_time,
            cert_invalid_time=self.cert_invalid_time,
            cert_expired=self.cert_expired,
            cert_md5_digest=self.cert_md5_digest,
            cert_sha1_digest=self.cert_sha1_digest,
            cert_sha256_digest=self.cert_sha256_digest,
            cert_sha512_digest=self.cert_sha512_digest,
            cert_key_bits=self.cert_key_bits,
            cert_key_type=self.cert_key_type,
            cert_public_key=self.cert_public_key,
            cert_content=self.cert_content,
            cert_issuer_common_name=self.cert_issuer_common_name,
            cert_issuer_country=self.cert_issuer_country,
            cert_issuer_email=self.cert_issuer_email,
            cert_issuer_hash=self.cert_issuer_hash,
            cert_issuer_locality=self.cert_issuer_locality,
            cert_issuer_organization=self.cert_issuer_organization,
            cert_issuer_organizational_unit=self.cert_issuer_organizational_unit,
            cert_issuer_state=self.cert_issuer_state,
            cert_subject_common_name=self.cert_subject_common_name,
            cert_subject_country=self.cert_subject_country,
            cert_subject_email=self.cert_subject_email,
            cert_subject_hash=self.cert_subject_hash,
            cert_subject_locality=self.cert_subject_locality,
            cert_subject_organization=self.cert_subject_organization,
            cert_subject_organizational_unit=self.cert_subject_organizational_unit,
            cert_subject_state=self.cert_subject_state,
            cert_extension_names=self.cert_extension_names,
            cert_has_authority_key_id=self.cert_has_authority_key_id,
            cert_authority_key_id=self.cert_authority_key_id,
            cert_has_subject_key_id=self.cert_has_subject_key_id,
            cert_subject_key_id=self.cert_subject_key_id,
            cert_has_extended_key_usage=self.cert_has_extended_key_usage,
            cert_extended_key_usage=self.cert_extended_key_usage,
            cert_has_certificate_policies=self.cert_has_certificate_policies,
            cert_certificate_policies=self.cert_certificate_policies,
            cert_certificate_policy_oids=self.cert_certificate_policy_oids,
            cert_has_crl_distribution_points=self.cert_has_crl_distribution_points,
            cert_crl_distribution_points=self.cert_crl_distribution_points,
            cert_has_subject_alt_name=self.cert_has_subject_alt_name,
            cert_subject_alt_name=self.cert_subject_alt_name,
            cert_has_authority_info_access=self.cert_has_authority_info_access,
            cert_authority_info_access=self.cert_authority_info_access,
            cert_is_valid=self.cert_is_valid,
            cert_is_extended_validation=self.cert_is_extended_validation,
            supports_fallback_scsv=self.supports_fallback_scsv,
            is_vulnerable_to_heartbleed=self.is_vulnerable_to_heartbleed,
            is_vulnerable_to_ccs_injection=self.is_vulnerable_to_ccs_injection,
            accepts_client_renegotiation=self.accepts_client_renegotiation,
            supports_secure_renegotiation=self.supports_secure_renegotiation,
            is_ticket_resumption_supported=self.is_ticket_resumption_supported,
            supports_sslv2=self.supports_sslv2,
            supports_sslv3=self.supports_sslv3,
            supports_tlsv1=self.supports_tlsv1,
            supports_tlsv1_1=self.supports_tlsv1_1,
            supports_tlsv1_2=self.supports_tlsv1_2,
            sslv2_preferred_cipher=self.sslv2_preferred_cipher,
            sslv3_preferred_cipher=self.sslv3_preferred_cipher,
            tlsv1_preferred_cipher=self.tlsv1_preferred_cipher,
            tlsv1_1_preferred_cipher=self.tlsv1_1_preferred_cipher,
            tlsv1_2_preferred_cipher=self.tlsv1_2_preferred_cipher,
            sslv2_supported_ciphers=self.sslv2_supported_ciphers,
            sslv3_supported_ciphers=self.sslv3_supported_ciphers,
            tlsv1_supported_ciphers=self.tlsv1_supported_ciphers,
            tlsv1_1_supported_ciphers=self.tlsv1_1_supported_ciphers,
            tlsv1_2_supported_ciphers=self.tlsv1_2_supported_ciphers,
            is_vulnerable=self.is_vulnerable,
            cert_is_trusted=self.cert_is_trusted,
            scan_completed_at=DatetimeHelper.now(),
            cert_extensions=self.cert_extensions,
            heartbleed_test_errored=self.heartbleed_test_errored,
            fallback_scsv_test_errored=self.fallback_scsv_test_errored,
            ccs_injection_test_errored=self.ccs_injection_test_errored,
            session_renegotiation_test_errored=self.session_renegotiation_test_errored,
            session_resumption_test_errored=self.session_renegotiation_test_errored,
        )

    # Private Methods

    def __get_certificate_timestamp(self, to_process):
        """
        Get a Python datetime corresponding to the given certificate timestamp.
        :param to_process: A string containing the value to process as a timestamp.
        :return: A Python datetime.
        """
        if "Z" in to_process:
            return datetime.strptime(to_process, "%Y%m%d%H%M%SZ")
        elif "-" in to_process:
            return datetime.strptime(to_process, "%Y%m%d%H%M%S%z")
        elif "+" in to_process:
            return datetime.strptime(to_process, "%Y%m%d%H%M%S%z")
        else:
            raise InvalidCertificateTimeError(
                "Unsure how to process timestamp of %s."
                % (to_process,)
            )

    def __get_cert_chain(self):
        """
        Get a list of the X509 certificates in the verification chain for the referenced SSL
        certificate.
        :return: A list of the X509 certificates in the verification chain for the referenced SSL
        certificate.
        """
        if not self.cert_has_authority_info_access:
            return []
        to_return = []
        from lib.parsing import SslCertificateWrapper
        cert_wrapper = SslCertificateWrapper(self.cert_content)
        parent_cert_url = cert_wrapper.preferred_parent_cert_url
        while True:
            cert_response = requests.get(parent_cert_url)
            to_return.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_response.content))
            cert_wrapper = SslCertificateWrapper(cert_response.content, cert_type=OpenSSL.crypto.FILETYPE_ASN1)
            if cert_wrapper.has_parent_cert_url:
                parent_cert_url = cert_wrapper.preferred_parent_cert_url
            else:
                break
        return to_return

    def __get_cert_content(self):
        """
        Get a string representing the contents of the referenced SSL certificate.
        :return: A string representing the contents of the referenced SSL certificate.
        """
        storage_helper = get_storage_helper()
        return storage_helper.get_file(
            file_key=self.ssl_certificate_model["s3_key"],
            bucket=self.ssl_certificate_model["s3_bucket"],
        ).strip()

    def __get_cert_key_type(self):
        """
        Get a string representing the key type associated with the SSL certificate.
        :return: A string representing the key type associated with the SSL certificate.
        """
        key_type = self.ssl_certificate.get_pubkey().type()
        if key_type == OpenSSL.crypto.TYPE_RSA:
            return "RSA"
        elif key_type == OpenSSL.crypto.TYPE_DSA:
            return "DSA"
        elif key_type == 408:
            return "EC"
        else:
            raise UnknownKeyTypeError(
                "Unknown key type of %s."
                % (key_type,)
            )

    def __get_certifi_ssl_certificates(self):
        """
        Get a list of strings representing the certificates found within the certifi root CAs file.
        :return: A list of strings representing the certificates found within the certifi root CAs file.
        """
        file_contents = FilesystemHelper.get_file_contents(path=certifi.where())
        return RegexLib.ssl_certificate_regex.findall(file_contents)

    def __get_extended_validation_oids(self):
        """
        Get a list of tuples containing (1) the certificate issuer name and (2) the OID for all certificate
        policy OIDs that represent extended certificate validation.
        :return: A list of tuples containing (1) the certificate issuer name and (2) the OID for all certificate
        policy OIDs that represent extended certificate validation.
        """
        file_contents = FilesystemHelper.get_file_contents(config.files_extended_validation_oids_path)
        return [x.strip().split(",") for x in file_contents.strip().split("\n")]

    def __get_extension_content(self, extension_name):
        """
        Get a string representing the content of the given extension.
        :param extension_name: The name of the extension to retrieve content for.
        :return: A string representing the content of the given extension.
        """
        for i in range(self.ssl_certificate.get_extension_count()):
            extension = self.ssl_certificate.get_extension(i)
            if extension.get_short_name() == extension_name:
                return str(extension)
        raise ExtensionNotFoundError(
            "Extension with name %s was not found in SSL certificate."
            % (extension_name,)
        )

    def __get_ssl_certificate_model(self):
        """
        Get the SSL certificate model that was retrieved during the referenced network scan.
        :return: The SSL certificate model that was retrieved during the referenced network scan.
        """
        query = SslCertificateQuery()
        query.filter_by_network_service_scan(self.network_scan_uuid)
        response = query.search(self.org_uuid)
        return response.results[0]["_source"]

    def __get_ssl_vulnerability_models(self):
        """
        Get an Elasticsearch response containing all of the SslVulnerabilityModel objects collected
        during the referenced network service scan.
        :return: An Elasticsearch response containing all of the SslVulnerabilityModel objects collected
        during the referenced network service scan.
        """
        query = SslVulnerabilityQuery()
        query.filter_by_network_service_scan(self.network_scan_uuid)
        return query.search(self.org_uuid)

    def __get_ssl_certificate_store_context(self):
        """
        Get an OpenSSL X509StoreContext object used for validating the referenced SSL certificate.
        :return: An OpenSSL X509StoreContext object used for validating the referenced SSL certificate.
        """
        certifi_certs = self.__get_certifi_ssl_certificates()
        x509_store = OpenSSL.crypto.X509Store()
        for certifi_cert in certifi_certs:
            cur_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certifi_cert)
            x509_store.add_cert(cur_cert)
        for chain_cert in self.cert_validation_chain:
            x509_store.add_cert(chain_cert)
        x509_context = OpenSSL.crypto.X509StoreContext(x509_store, self.ssl_certificate)
        return x509_context

    def __get_ssl_support_records(self):
        """
        Get an Elasticsearch response that contains all of the SSL support records collected during the
        referenced scan.
        :return: An Elasticsearch response that contains all of the SSL support records collected during the
        referenced scan.
        """
        query = SslSupportQuery()
        query.filter_by_network_service_scan(self.network_scan_uuid)
        return query.search(self.org_uuid)

    # Properties

    @property
    def accepts_client_renegotiation(self):
        """
        Returns wether or not this tcp service accepts client renegotiation
        :return: True or False
        """
        if self.session_renegotiation_result:
            for entry in self.session_renegotiation_result["_source"]["test_results"]:
                if entry["key"] == "accepts_client_renegotiation":
                    return entry["value"]
            return False
        else:
            return False

    @property
    def ccs_injection_result(self):
        """
        Get the result of the CCS injection vulnerability check, if such a result is available.
        :return: the result of the CCS injection vulnerability check, if such a result is available.
        """
        to_return = filter(lambda x: x["_source"]["vuln_test_name"] == "ccs_injection",
                           self.ssl_vulnerability_models.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def ccs_injection_test_errored(self):
        """
        Get whether or not the CCS injection test threw an error.
        :return: whether or not the CCS injection test threw an error.
        """
        return self.ccs_injection_result["_source"]["test_errored"] if self.ccs_injection_result else True

    @property
    def cert_authority_info_access(self):
        """
        Get the authority info access from the certificate extensions of the extensions contain it.
        :return: the authority info access from the certificate extensions of the extensions contain it.
        """
        if self._cert_authority_info_access is None and self.cert_has_authority_info_access:
            self._cert_authority_info_access = self.__get_extension_content("authorityInfoAccess")
        return self._cert_authority_info_access

    @property
    def cert_authority_key_id(self):
        """
        Get the authority key ID from the certificate extensions if extensions contain one.
        :return: the authority key ID from the certificate extensions if extensions contain one.
        """
        if self._cert_authority_key_id is None and self.cert_has_authority_key_id:
            self._cert_authority_key_id = self.__get_extension_content("authorityKeyIdentifier")
        return self._cert_authority_key_id

    @property
    def cert_certificate_policies(self):
        """
        Get the certificate policies from the certificate extensions if extensions contain one.
        :return: the certificate policies from the certificate extensions if extensions contain one.
        """
        if self._cert_certificate_policies is None and self.cert_has_certificate_policies:
            self._cert_certificate_policies = self.__get_extension_content("certificatePolicies")
        return self._cert_certificate_policies

    @property
    def cert_crl_distribution_points(self):
        """
        Get the CRL distribution points from the certificate extensions if the extensions contain them.
        :return: the CRL distribution points from the certificate extensions if the extensions contain them.
        """
        if self._cert_crl_distribution_points is None and self.cert_has_crl_distribution_points:
            self._cert_crl_distribution_points = self.__get_extension_content("crlDistributionPoints")
        return self._cert_crl_distribution_points

    @property
    def cert_extended_key_usage(self):
        """
        Get the extended key usage from the certificate extensions of extensions contain one.
        :return: the extended key usage from the certificate extensions of extensions contain one.
        """
        if self._cert_extended_key_usage is None and self.cert_has_extended_key_usage:
            self._cert_extended_key_usage = self.__get_extension_content("extendedKeyUsage")
        return self._cert_extended_key_usage

    @property
    def cert_subject_key_id(self):
        """
        Get the subject key ID from the certificate extensions of extensions contain one.
        :return: the subject key ID from the certificate extensions of extensions contain one.
        """
        if self._cert_subject_key_id is None and self.cert_has_subject_key_id:
            self._cert_subject_key_id = self.__get_extension_content("subjectKeyIdentifier")
        return self._cert_subject_key_id

    @property
    def cert_content(self):
        """
        Get a string representing the content of the referenced SSL certificate.
        :return: a string representing the content of the referenced SSL certificate.
        """
        if self._cert_content is None:
            self._cert_content = self.__get_cert_content()
        return self._cert_content

    @property
    def cert_expired(self):
        """
        Get whether or not the certificate has expired.
        :return: whether or not the certificate has expired.
        """
        return self.ssl_certificate.has_expired()

    @property
    def cert_extension_names(self):
        """
        Get a list of names representing the extensions found within the SSL certificate.
        :return: a list of names representing the extensions found within the SSL certificate.
        """
        if self._cert_extension_names is None:
            names = []
            for i in range(self.ssl_certificate.get_extension_count()):
                names.append(self.ssl_certificate.get_extension(i).get_short_name())
            self._cert_extension_names = names
        return self._cert_extension_names

    @property
    def cert_extensions(self):
        """
        Get a list of dictionaries describing the extensions associated with the analyzed SSL
        certificate.
        :return: A list of dictionaries describing the extensions associated with the analyzed SSL
        certificate.
        """
        if self._cert_extensions is None:
            cert_extensions = []
            for i in range(self.ssl_certificate.get_extension_count()):
                try:
                    extension = self.ssl_certificate.get_extension(i)
                    cert_extensions.append({
                        "extension_name": extension.get_short_name().strip(),
                        "extension_content": str(extension).strip(),
                    })
                except Exception as e:
                    logger.warning(
                        "%s exception thrown when attempting to get extension data for SSL certificate."
                        % (e.__class__.__name__,)
                    )
            self._cert_extensions = cert_extensions
        return self._cert_extensions

    @property
    def cert_has_authority_info_access(self):
        """
        Get whether or not the certificate has the authorityInfoAccess extension.
        :return: whether or not the certificate has the authorityInfoAccess extension.
        """
        return "authorityInfoAccess" in self.cert_extension_names

    @property
    def cert_has_authority_key_id(self):
        """
        Get whether or not the certificate as the authorityKeyIdentifier extension.
        :return: whether or not the certificate as the authorityKeyIdentifier extension.
        """
        return "authorityKeyIdentifier" in self.cert_extension_names

    @property
    def cert_has_certificate_policies(self):
        """
        Get whether or not the certificate has the certificatePolicies extension.
        :return: whether or not the certificate has the certificatePolicies extension.
        """
        return "certificatePolicies" in self.cert_extension_names

    @property
    def cert_has_crl_distribution_points(self):
        """
        Get whether or not the certificate has the crlDistributionPoints extension.
        :return: whether or not the certificate has the crlDistributionPoints extension.
        """
        return "crlDistributionPoints" in self.cert_extension_names

    @property
    def cert_has_extended_key_usage(self):
        """
        Get whether or not the certificate has the extendedKeyUsage extension.
        :return: whether or not the certificate has the extendedKeyUsage extension.
        """
        return "extendedKeyUsage" in self.cert_extension_names

    @property
    def cert_has_subject_alt_name(self):
        """
        Get whether or not the certificate has the subjectAltName extension.
        :return: whether or not the certificate has the subjectAltName extension.
        """
        return "subjectAltName" in self.cert_extension_names

    @property
    def cert_has_subject_key_id(self):
        """
        Get whether or not the certificate has the subjectKeyIdentifier extension.
        :return: whether or not the certificate has the subjectKeyIdentifier extension.
        """
        return "subjectKeyIdentifier" in self.cert_extension_names

    @property
    def cert_has_invalid_time(self):
        """
        Get whether or not the referenced SSL certificate contains a validity end time.
        :return: whether or not the referenced SSL certificate contains a validity end time.
        """
        return self.ssl_certificate.get_notAfter() is not None

    @property
    def cert_has_start_time(self):
        """
        Get whether or not the referenced SSL certificate contains a validity start time.
        :return: whether or not the referenced SSL certificate contains a validity start time.
        """
        return self.ssl_certificate.get_notBefore() is not None

    @property
    def cert_invalid_time(self):
        """
        Get a datetime depicting when the certificate will no longer be valid.
        :return: a datetime depicting when the certificate will no longer be valid.
        """
        if self._cert_invalid_time is None and self.cert_has_invalid_time:
            self._cert_invalid_time = self.__get_certificate_timestamp(self.ssl_certificate.get_notAfter())
        return self._cert_invalid_time

    @property
    def cert_is_extended_validation(self):
        """
        Get whether or not the referenced certificate is an extended validation certificate.
        :return: whether or not the referenced certificate is an extended validation certificate.
        """
        env_oids = [x[1] for x in self.env_oids]
        return any([env_oid in self.cert_certificate_policy_oids for env_oid in env_oids])

    @property
    def cert_issuer_common_name(self):
        """
        Get the common name for where the certificate is issued from.
        :return: the common name for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().commonName

    @property
    def cert_issuer_country(self):
        """
        Get the country code for where the certificate is issued from.
        :return: the country code for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().countryName

    @property
    def cert_issuer_email(self):
        """
        Get the email address for where the certificate is issued from.
        :return: the email address for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().emailAddress

    @property
    def cert_issuer_hash(self):
        """
        Get a hash of the issuer of the certificate.
        :return: a hash of the issuer of the certificate.
        """
        return self.ssl_certificate.get_issuer().hash()

    @property
    def cert_issuer_locality(self):
        """
        Get the locality for where the certificate is issued from.
        :return: the locality for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().localityName

    @property
    def cert_issuer_organization(self):
        """
        Get the organization for where the certificate is issued from.
        :return: the organization for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().organizationName

    @property
    def cert_issuer_organizational_unit(self):
        """
        Get the organizational unit for where the certificate is issued from.
        :return: the organizational unit for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().organizationalUnitName

    @property
    def cert_issuer_state(self):
        """
        Get the state for where the certificate is issued from.
        :return: the state for where the certificate is issued from.
        """
        return self.ssl_certificate.get_issuer().stateOrProvinceName

    @property
    def cert_is_trusted(self):
        """
        Get whether or not the certificate is trusted.
        :return: whether or not the certificate is trusted.
        """
        if self.cert_expired:
            # TODO this may not be accurate, as cert_is_valid may be false due to expiration
            return self.cert_is_valid
        else:
            return self.cert_is_valid

    @property
    def cert_is_valid(self):
        """
        Get whether or not the certificate is valid.
        :return: whether or not the certificate is valid.
        """
        if self._cert_is_valid is None:
            try:
                self.ssl_store_context.verify_certificate()
                self._cert_is_valid = True
            except OpenSSL.crypto.X509StoreContextError:
                self._cert_is_valid = False
        return self._cert_is_valid

    @property
    def cert_key_bits(self):
        """
        Get the number of bits used in the certificate's key.
        :return: the number of bits used in the certificate's key.
        """
        return self.ssl_certificate.get_pubkey().bits()

    @property
    def cert_key_type(self):
        """
        Get the type of key associated with the SSL certificate.
        :return: the type of key associated with the SSL certificate.
        """
        if self._cert_key_type is None:
            self._cert_key_type = self.__get_cert_key_type()
        return self._cert_key_type

    @property
    def cert_md5_digest(self):
        """
        Get an MD5 digest of the SSL certificate.
        :return: an MD5 digest of the SSL certificate.
        """
        return self.ssl_certificate.digest("md5")

    @property
    def cert_certificate_policy_oids(self):
        """
        Get a list of strings representing the OIDs that are associated with this certificate's certificate
        policies extension.
        :return: A list of strings representing the OIDs that are associated with this certificate's certificate
        policies extension.
        """
        if self._cert_policy_oids is None:
            oids = []
            if self.cert_has_certificate_policies:
                policy_lines = [x.strip() for x in self.cert_certificate_policies.strip().split("\n")]
                for policy_line in policy_lines:
                    if "policy:" in policy_line.lower():
                        oids.append(policy_line.split()[-1].strip())
            self._cert_policy_oids = oids
        return self._cert_policy_oids

    @property
    def cert_public_key(self):
        """
        Get a string containing the public key associated with the SSL certificate.
        :return: a string containing the public key associated with the SSL certificate.
        """
        if self._cert_public_key is None:
            self._cert_public_key = self.ssl_certificate.get_pubkey().to_cryptography_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).strip()
        return self._cert_public_key

    @property
    def cert_sha1_digest(self):
        """
        Get a SHA1 digest of the SSL certificate.
        :return: a SHA1 digest of the SSL certificate.
        """
        return self.ssl_certificate.digest("sha1")

    @property
    def cert_sha256_digest(self):
        """
        Get a SHA256 digest of the SSL certificate.
        :return: a SHA256 digest of the SSL certificate.
        """
        return self.ssl_certificate.digest("sha256")

    @property
    def cert_sha512_digest(self):
        """
        Get a SHA512 digest of the SSL certificate.
        :return: a SHA512 digest of the SSL certificate.
        """
        return self.ssl_certificate.digest("sha512")

    @property
    def cert_serial_number(self):
        """
        Get the serial number associated with the retrieved SSL certificate.
        :return: the serial number associated with the retrieved SSL certificate.
        """
        return self.ssl_certificate.get_serial_number()

    @property
    def cert_start_time(self):
        """
        Get a datetime depicting when the certificate started being valid.
        :return: a datetime depicting when the certificate started being valid.
        """
        if self._cert_start_time is None and self.cert_has_start_time:
            self._cert_start_time = self.__get_certificate_timestamp(self.ssl_certificate.get_notBefore())
        return self._cert_start_time

    @property
    def cert_subject_alt_name(self):
        """
        Get the subject alternative name from the certificate extensions if the extensions has one.
        :return: the subject alternative name from the certificate extensions if the extensions has one.
        """
        if self._cert_subject_alt_name is None and self.cert_has_subject_alt_name:
            self._cert_subject_alt_name = self.__get_extension_content("subjectAltName")
        return self._cert_subject_alt_name

    @property
    def cert_subject_common_name(self):
        """
        Get the common name for the certificate subject.
        :return: the common name for the certificate subject.
        """
        return self.ssl_certificate.get_subject().commonName

    @property
    def cert_subject_country(self):
        """
        Get the country code for the certificate subject.
        :return: the country code for the certificate subject.
        """
        return self.ssl_certificate.get_subject().countryName

    @property
    def cert_subject_email(self):
        """
        Get the email address for the certificate subject.
        :return: the email address for the certificate subject.
        """
        return self.ssl_certificate.get_subject().emailAddress

    @property
    def cert_subject_hash(self):
        """
        Get a hash of the issuer of the certificate.
        :return: a hash of the issuer of the certificate.
        """
        return self.ssl_certificate.get_subject().hash()

    @property
    def cert_subject_locality(self):
        """
        Get the locality for the certificate subject.
        :return: the locality for the certificate subject.
        """
        return self.ssl_certificate.get_subject().localityName

    @property
    def cert_subject_organization(self):
        """
        Get the organization for the certificate subject.
        :return: the organization for the certificate subject.
        """
        return self.ssl_certificate.get_subject().organizationName

    @property
    def cert_subject_organizational_unit(self):
        """
        Get the organizational unit for the certificate subject.
        :return: the organizational unit for the certificate subject.
        """
        return self.ssl_certificate.get_subject().organizationalUnitName

    @property
    def cert_subject_state(self):
        """
        Get the state for the certificate subject.
        :return: the state for the certificate subject.
        """
        return self.ssl_certificate.get_subject().stateOrProvinceName

    @property
    def cert_validation_chain(self):
        """
        Get a list of certificates to be used for certificate validation.
        :return: a list of certificates to be used for certificate validation.
        """
        if self._cert_validation_chain is None:
            self._cert_validation_chain = self.__get_cert_chain()
        return self._cert_validation_chain

    @property
    def cert_version(self):
        """
        Get the SSL certificate version.
        :return: the SSL certificate version.
        """
        return self.ssl_certificate.get_version()

    @property
    def env_oids(self):
        """
        Get a list of tuples containing (1) the certificate issuer and (2) the OID for all OIDs that
        represent extended validation certificates.
        :return: a list of tuples containing (1) the certificate issuer and (2) the OID for all OIDs
        that represent extended validation certificates.
        """
        if self._env_oids is None:
            self._env_oids = self.__get_extended_validation_oids()
        return self._env_oids

    @property
    def fallback_scsv_result(self):
        """
        Get the result of the fallback SCSV vulnerability check, if such a result is available.
        :return: the result of the fallback SCSV vulnerability check, if such a result is available.
        """
        to_return = filter(lambda x: x["_source"]["vuln_test_name"] == "fallback_scsv",
                           self.ssl_vulnerability_models.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def fallback_scsv_test_errored(self):
        """
        Get whether or not the fallback SCSV test threw an error.
        :return: whether or not the fallback SCSV test threw an error.
        """
        return self.fallback_scsv_result["_source"]["test_errored"] if self.fallback_scsv_result else True

    @property
    def heartbleed_result(self):
        """
        Get the result of the heartbleed vulnerability check, if such a result is available.
        :return: the result of the heartbleed vulnerability check, if such a result is available.
        """
        to_return = filter(lambda x: x["_source"]["vuln_test_name"] == "heartbleed", self.ssl_vulnerability_models.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def heartbleed_test_errored(self):
        """
        Get whether or not the heartbleed test threw an error.
        :return: whether or not the heartbleed test threw an error.
        """
        return self.heartbleed_result["_source"]["test_errored"] if self.heartbleed_result else True

    @property
    def inspection_target(self):
        return self.network_scan_uuid

    @property
    def is_ticket_resumption_supported(self):
        """
        Returns wether or not this tcp service supports ticket resumption
        :return: True or False
        """
        if self.session_resumption_result:
            for entry in self.session_resumption_result["_source"]["test_results"]:
                if entry["key"] == "is_ticket_resumption_supported":
                    return entry["value"]
            return False
        else:
            return False

    @property
    def is_vulnerable(self):
        """
        Get whether or not the current configuration for the network service contains vulnerabilities.
        :return: whether or not the current configuration for the network service contains vulnerabilities.
        """
        return self.is_vulnerable_to_ccs_injection \
            or self.is_vulnerable_to_heartbleed

    @property
    def is_vulnerable_to_ccs_injection(self):
        """
        Returns wether or not this tcp service is vulnerable to css injection
        :return: True or False
        """
        if self.ccs_injection_result:
            for entry in self.ccs_injection_result["_source"]["test_results"]:
                if entry["key"] == "is_vulnerable_to_ccs_injection":
                    return entry["value"]
            return False
        else:
            return False

    @property
    def is_vulnerable_to_heartbleed(self):
        """
        Returns wether or not this tcp service is vulnerable to heartbleed
        :return: True or False
        """
        if self.heartbleed_result:
            for entry in self.heartbleed_result["_source"]["test_results"]:
                if entry["key"] == "is_vulnerable_to_heartbleed":
                    return entry["value"]
            return False
        else:
            return False

    @property
    def network_scan_uuid(self):
        """
        Get the UUID of the network service scan that this inspector class is responsible for analyzing.
        :return: the UUID of the network service scan that this inspector class is responsible for
        analyzing.
        """
        return self._network_scan_uuid

    @property
    def org_uuid(self):
        """
        Get the UUID of the organization that owns the referenced network service scan.
        :return: the UUID of the organization that owns the referenced network service scan.
        """
        if self._org_uuid is None:
            self._org_uuid = get_org_uuid_from_network_service_scan(
                db_session=self.db_session,
                scan_uuid=self.network_scan_uuid,
            )
        return self._org_uuid

    @property
    def session_renegotiation_result(self):
        """
        Get the result of the session renegotiation vulnerability check, if such a result is available.
        :return: the result of the session renegotiation vulnerability check, if such a result is available.
        """
        to_return = filter(lambda x: x["_source"]["vuln_test_name"] == "session_renegotiation",
                           self.ssl_vulnerability_models.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def session_renegotiation_test_errored(self):
        """
        Get whether or not the session renegotiation test threw an error.
        :return: whether or not the session renegotiation test threw an error.
        """
        return self.session_renegotiation_result["_source"]["test_errored"] \
            if self.session_renegotiation_result \
            else True

    @property
    def session_resumption_result(self):
        """
        Get the result of the session resumption vulnerability check, if such a result is available.
        :return: the result of the session resumption vulnerability check, if such a result is available.
        """
        to_return = filter(lambda x: x["_source"]["vuln_test_name"] == "session_resumption",
                           self.ssl_vulnerability_models.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def session_resumption_test_errored(self):
        """
        Get whether or not the session resumption test threw an error.
        :return: whether or not the session resumption test threw an error.
        """
        return self.session_resumption_result["_source"]["test_errored"] \
            if self.session_resumption_result \
            else True

    @property
    def sslv2_support_record(self):
        """
        Get the SSL support record from the given scan for SSLv2 if such a record exists.
        :return: the SSL support record from the given scan for SSLv2 if such a record exists.
        """
        to_return = filter(lambda x: x["_source"]["ssl_version"] == "sslv2", self.ssl_support_records.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def sslv2_preferred_cipher(self):
        """
        Get the cipher that is preferred by the remote server when using SSLv2.
        :return: the cipher that is preferred by the remote server when using SSLv2.
        """
        return self.sslv2_support_record["_source"]["preferred_cipher"] if self.supports_sslv2 else None

    @property
    def sslv2_rejected_ciphers(self):
        """
        Get a list containing the ciphers rejected by the network service when using SSLv2.
        :return: a list containing the ciphers rejected by the network service when using SSLv2.
        """
        return self.sslv2_support_record["_source"]["rejected_ciphers"] if self.supports_sslv2 else []

    @property
    def sslv2_supported_ciphers(self):
        """
        Get a list containing the ciphers supported by the network service when using SSLv2.
        :return: a list containing the ciphers supported by the network service when using SSLv2.
        """
        return self.sslv2_support_record["_source"]["accepted_ciphers"] if self.supports_sslv2 else []

    @property
    def sslv3_support_record(self):
        """
        Get the SSL support record from the given scan for SSLv3 if such a record exists.
        :return: the SSL support record from the given scan for SSLv3 if such a record exists.
        """
        to_return = filter(lambda x: x["_source"]["ssl_version"] == "sslv3", self.ssl_support_records.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def sslv3_preferred_cipher(self):
        """
        Get the cipher that is preferred by the remote server when using SSLv3.
        :return: the cipher that is preferred by the remote server when using SSLv3.
        """
        return self.sslv3_support_record["_source"]["preferred_cipher"] if self.supports_sslv3 else None

    @property
    def sslv3_rejected_ciphers(self):
        """
        Get a list containing the ciphers rejected by the network service when using SSLv3.
        :return: a list containing the ciphers rejected by the network service when using SSLv3.
        """
        return self.sslv3_support_record["_source"]["rejected_ciphers"] if self.supports_sslv3 else []

    @property
    def sslv3_supported_ciphers(self):
        """
        Get a list containing the ciphers supported by the network service when using SSLv3.
        :return: a list containing the ciphers supported by the network service when using SSLv3.
        """
        return self.sslv3_support_record["_source"]["accepted_ciphers"] if self.supports_sslv3 else []

    @property
    def ssl_certificate(self):
        """
        Get a PyOpenSSL x509 object wrapping the contents of the SSL certificate retrieved from the
        referenced network service.
        :return: a PyOpenSSL x509 object wrapping the contents of the SSL certificate retrieved from the
        referenced network service.
        """
        if self._ssl_certificate is None:
            self._ssl_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_content)
        return self._ssl_certificate

    @property
    def ssl_certificate_model(self):
        """
        Get the Elasticsearch model associated with the SSL certificate retrieved during the referenced
        network scan.
        :return: the Elasticsearch model associated with the SSL certificate retrieved during the
        referenced network scan.
        """
        if self._ssl_certificate_model is None:
            self._ssl_certificate_model = self.__get_ssl_certificate_model()
        return self._ssl_certificate_model

    @property
    def ssl_support_records(self):
        """
        Get an Elasticsearch response that contains all of the SSL support models collected during the given scan.
        :return: an Elasticsearch response that contains all of the SSL support models collected during the given scan.
        """
        if self._ssl_support_records is None:
            self._ssl_support_records = self.__get_ssl_support_records()
        return self._ssl_support_records

    @property
    def ssl_store_context(self):
        """
        Get the SSL store context to use to validate the referenced certificate.
        :return: the SSL store context to use to validate the referenced certificate.
        """
        if self._ssl_store_context is None:
            self._ssl_store_context = self.__get_ssl_certificate_store_context()
        return self._ssl_store_context

    @property
    def ssl_vulnerability_models(self):
        """
        Get an Elasticsearch response containing all of the vulnerability reports collected during the
        referenced network service scan.
        :return: an Elasticsearch response containing all of the vulnerability reports collected during
        the referenced network service scan.
        """
        if self._ssl_vulnerability_models is None:
            self._ssl_vulnerability_models = self.__get_ssl_vulnerability_models()
        return self._ssl_vulnerability_models

    @property
    def supports_fallback_scsv(self):
        """
        Returns wether or not this tcp service supports TLS_FALLBACK_SCSV
        :return: True or False
        """
        if self.fallback_scsv_result:
            for entry in self.fallback_scsv_result["_source"]["test_results"]:
                if entry["key"] == "supports_fallback_scsv":
                    return entry["value"]
            return False
        else:
            return False

    @property
    def supports_secure_renegotiation(self):
        """
        Returns wether or not this tcp service supports secure renegotiation
        :return: True or False
        """
        if self.session_renegotiation_result:
            for entry in self.session_renegotiation_result["_source"]["test_results"]:
                if entry["key"] == "supports_secure_renegotiation":
                    return entry["value"]
            return False
        else:
            return False

    @property
    def supports_sslv2(self):
        """
        Get whether or not the network service supports SSLv2.
        :return: whether or not the network service supports SSLv2.
        """
        return self.sslv2_support_record["_source"]["supported"] if self.sslv2_support_record is not None else False

    @property
    def supports_sslv3(self):
        """
        Get whether or not the network service supports SSLv3.
        :return: whether or not the network service supports SSLv3.
        """
        return self.sslv3_support_record["_source"]["supported"] if self.sslv3_support_record is not None else False

    @property
    def supports_tlsv1(self):
        """
        Get whether or not the network service supports TLSv1.
        :return: whether or not the network service supports TLSv1.
        """
        return self.tlsv1_support_record["_source"]["supported"] if self.tlsv1_support_record is not None else False

    @property
    def supports_tlsv1_1(self):
        """
        Get whether or not the network service supports TLSv1_1.
        :return: whether or not the network service supports TLSv1_1.
        """
        return self.tlsv1_1_support_record["_source"]["supported"] if self.tlsv1_1_support_record is not None else False

    @property
    def supports_tlsv1_2(self):
        """
        Get whether or not the network service supports TLSv1_2.
        :return: whether or not the network service supports TLSv1_2.
        """
        return self.tlsv1_2_support_record["_source"]["supported"] if self.tlsv1_2_support_record is not None else False

    @property
    def tlsv1_support_record(self):
        """
        Get the SSL support record from the given scan for TLSv1 if such a record exists.
        :return: the SSL support record from the given scan for TLSv1 if such a record exists.
        """
        to_return = filter(lambda x: x["_source"]["ssl_version"] == "tlsv1",
                           self.ssl_support_records.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def tlsv1_preferred_cipher(self):
        """
        Get the cipher that is preferred by the remote server when using tlsv1.
        :return: the cipher that is preferred by the remote server when using tlsv1.
        """
        return self.tlsv1_support_record["_source"]["preferred_cipher"] if self.supports_tlsv1 else None

    @property
    def tlsv1_rejected_ciphers(self):
        """
        Get a list containing the ciphers rejected by the network service when using tlsv1.
        :return: a list containing the ciphers rejected by the network service when using tlsv1.
        """
        return self.tlsv1_support_record["_source"]["rejected_ciphers"] if self.supports_tlsv1 else []

    @property
    def tlsv1_supported_ciphers(self):
        """
        Get a list containing the ciphers supported by the network service when using tlsv1.
        :return: a list containing the ciphers supported by the network service when using tlsv1.
        """
        return self.tlsv1_support_record["_source"]["accepted_ciphers"] if self.supports_tlsv1 else []

    @property
    def tlsv1_1_support_record(self):
        """
        Get the SSL support record from the given scan for TLSv1_1 if such a record exists.
        :return: the SSL support record from the given scan for TLSv1_1 if such a record exists.
        """
        to_return = filter(lambda x: x["_source"]["ssl_version"] == "tlsv1.1",
                           self.ssl_support_records.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def tlsv1_1_preferred_cipher(self):
        """
        Get the cipher that is preferred by the remote server when using tlsv1_1.
        :return: the cipher that is preferred by the remote server when using tlsv1_1.
        """
        return self.tlsv1_1_support_record["_source"]["preferred_cipher"] if self.supports_tlsv1_1 else None

    @property
    def tlsv1_1_rejected_ciphers(self):
        """
        Get a list containing the ciphers rejected by the network service when using tlsv1_1.
        :return: a list containing the ciphers rejected by the network service when using tlsv1_1.
        """
        return self.tlsv1_1_support_record["_source"]["rejected_ciphers"] if self.supports_tlsv1_1 else []

    @property
    def tlsv1_1_supported_ciphers(self):
        """
        Get a list containing the ciphers supported by the network service when using tlsv1_1.
        :return: a list containing the ciphers supported by the network service when using tlsv1_1.
        """
        return self.tlsv1_1_support_record["_source"]["accepted_ciphers"] if self.supports_tlsv1_1 else []

    @property
    def tlsv1_2_support_record(self):
        """
        Get the SSL support record from the given scan for TLSv1_2 if such a record exists.
        :return: the SSL support record from the given scan for TLSv1_2 if such a record exists.
        """
        to_return = filter(lambda x: x["_source"]["ssl_version"] == "tlsv1.2",
                           self.ssl_support_records.results)
        return to_return[0] if len(to_return) > 0 else None

    @property
    def tlsv1_2_preferred_cipher(self):
        """
        Get the cipher that is preferred by the remote server when using tlsv1_2.
        :return: the cipher that is preferred by the remote server when using tlsv1_2.
        """
        return self.tlsv1_2_support_record["_source"]["preferred_cipher"] if self.supports_tlsv1_2 else None

    @property
    def tlsv1_2_rejected_ciphers(self):
        """
        Get a list containing the ciphers rejected by the network service when using tlsv1_2.
        :return: a list containing the ciphers rejected by the network service when using tlsv1_2.
        """
        return self.tlsv1_2_support_record["_source"]["rejected_ciphers"] if self.supports_tlsv1_2 else []

    @property
    def tlsv1_2_supported_ciphers(self):
        """
        Get a list containing the ciphers supported by the network service when using tlsv1_2.
        :return: a list containing the ciphers supported by the network service when using tlsv1_2.
        """
        return self.tlsv1_2_support_record["_source"]["accepted_ciphers"] if self.supports_tlsv1_2 else []

    # Representation and Comparison
