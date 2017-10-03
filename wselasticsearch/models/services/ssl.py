# -*- coding: utf-8 -*-
from __future__ import absolute_import

from OpenSSL import crypto

from .base import BaseNetworkServiceScanModel
from ..types import *
from ..mixin import DomainNameMixin, S3Mixin
from lib import ConversionHelper


class SslSupportModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model for representing the results of an SSL support check.
    """

    # Class Members

    ssl_version = KeywordElasticsearchType(
        help_text="The SSL/TLS version that the SSL support was checked against.",
    )
    supported = BooleanElasticsearchType(
        help_text="Whether or not the referenced SSL/TLS version was supported.",
    )
    accepted_ciphers = KeywordElasticsearchType(
        help_text="The ciphers that were supported for the referenced SSL/TLS version.",
    )
    rejected_ciphers = KeywordElasticsearchType(
        help_text="The ciphers that were rejected for the referenced SSL/TLS version.",
    )
    errored_ciphers = KeywordElasticsearchType(
        help_text="The ciphers that threw errors for the referenced SSL/TLS version.",
    )
    preferred_cipher = KeywordElasticsearchType(
        help_text="The preferred cipher for the referenced SSL/TLS version.",
    )
    pyopenssl_protocol = KeywordElasticsearchType(
        help_text="A string depicting the pyopenssl protocol that was used for testing.",
    )

    # Instantiation

    def __init__(
            self,
            ssl_version=None,
            supported=None,
            accepted_ciphers=None,
            rejected_ciphers=None,
            errored_ciphers=None,
            preferred_cipher=None,
            **kwargs
    ):
        super(SslSupportModel, self).__init__(**kwargs)
        self.ssl_version = ssl_version
        self.supported = supported
        self.accepted_ciphers = accepted_ciphers
        self.rejected_ciphers = rejected_ciphers
        self.errored_ciphers = errored_ciphers
        self.preferred_cipher = preferred_cipher
        if ssl_version is not None:
            self.pyopenssl_protocol = ConversionHelper.pyopenssl_protocol_name_from_ssl_version(ssl_version)
        else:
            self.pyopenssl_protocol = None

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.ssl_version = WsFaker.get_ssl_version_name()
        to_populate.pyopenssl_protocol = ConversionHelper.pyopenssl_protocol_name_from_ssl_version(
            to_populate.ssl_version
        )
        to_populate.supported = RandomHelper.flip_coin()
        to_populate.accepted_ciphers = WsFaker.get_words()
        to_populate.rejected_ciphers = WsFaker.get_words()
        to_populate.errored_ciphers = WsFaker.get_words()
        to_populate.preferred_cipher = WsFaker.get_words(1)[0]
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslVulnerabilityModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model for representing the results of a single check for a single
    SSL vulnerability.
    """

    # Class Members

    vuln_test_name = KeywordElasticsearchType(
        help_text="A string depicting the name of the vulnerability test that was conducted.",
    )
    test_errored = BooleanElasticsearchType(
        help_text="Whether or not the vulnerability test threw an exception.",
    )
    test_results = KeywordBooleanKeyValueElasticsearchType(
        help_text="The results of the SSL/TLS vulnerability check.",
    )

    # Instantiation

    def __init__(self, vuln_test_name=None, test_errored=None, test_results=None, **kwargs):
        super(SslVulnerabilityModel, self).__init__(**kwargs)
        self.vuln_test_name = vuln_test_name
        self.test_errored = test_errored
        self.test_results = test_results

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.vuln_test_name = WsFaker.get_word()
        to_populate.test_errored = RandomHelper.flip_coin()
        to_populate.test_results = WsFaker.get_ssl_vuln_test_results()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslCertificateModel(BaseNetworkServiceScanModel, DomainNameMixin, S3Mixin):
    """
    This is an Elasticsearch model for representing an SSL certificate.
    """

    # Class Members

    ssl_version = KeywordElasticsearchType(
        help_text="The SSL/TLS version that was used to retrieve the certificate.",
    )
    certificate_hash = KeywordElasticsearchType(
        help_text="The hash of the SSL/TLS certificate.",
    )
    country = KeywordElasticsearchType(
        help_text="The country code for where the SSL/TLS certificate is registered.",
    )
    state = KeywordElasticsearchType(
        help_text="The state code for where the SSL/TLS certificate is registered.",
    )
    locality = KeywordElasticsearchType(
        help_text="The locality code for where the SSL/TLS certificate is registered.",
    )
    organization = KeywordElasticsearchType(
        help_text="The name of the organization that the SSL certificate was registered for.",
    )
    organizational_unit = KeywordElasticsearchType(
        help_text="The organizational unit code for where the SSL/TLS certificate is registered.",
    )
    common_name = KeywordElasticsearchType(
        help_text="The contents of the CNAME field within the SSL certificate.",
    )

    # Instantiation

    def __init__(
            self,
            ssl_version=None,
            certificate_hash=None,
            country=None,
            state=None,
            locality=None,
            organization=None,
            organizational_unit=None,
            common_name=None,
            **kwargs
    ):
        super(SslCertificateModel, self).__init__(**kwargs)
        self.ssl_version = ssl_version
        self.certificate_hash = certificate_hash
        self.country = country
        self.state = state
        self.locality = locality
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.common_name = common_name
        if common_name is not None and not common_name.startswith("*"):
            self.domain_names = [common_name]
        else:
            self.domain_names = []

    # Static Methods

    # Class Methods

    @classmethod
    def from_x509_certificate(
            cls,
            certificate=None,
            cert_output_type=crypto.FILETYPE_PEM,
            **kwargs
    ):
        """
        Create and return an SslCertificateModel based on the contents of the given SSL certificate
        and other arguments.
        :param certificate: An OpenSSL certificate.
        :param cert_output_type: The certificate output type to calculate a hash over.
        :return: The newly-create SslCertificateModel.
        """
        to_return = cls(**kwargs)
        to_return = cls.populate_from_x509_certificate(
            certificate=certificate,
            cert_output_type=cert_output_type,
            to_populate=to_return,
        )
        return to_return

    @classmethod
    def populate_from_x509_certificate(cls, certificate=None, cert_output_type=crypto.FILETYPE_PEM, to_populate=None):
        """
        Populate the contents of to_populate based on the contents of the given SSL certificate.
        :param certificate: The SSL certificate to process.
        :param cert_output_type: The SSL certificate type.
        :param to_populate: The Elasticsearch model to populate.
        :return: The updated model.
        """
        cert_subject = certificate.get_subject()
        certificate_contents = {
            "country": cert_subject.C,
            "state": cert_subject.ST,
            "locality": cert_subject.L,
            "organization": cert_subject.O,
            "organizational_unit": cert_subject.OU,
            "common_name": cert_subject.CN,
            "certificate_hash": ConversionHelper.ssl_certificate_to_hash(
                certificate=certificate,
                output_type=cert_output_type,
            )
        }
        for k, v in certificate_contents.iteritems():
            setattr(to_populate, k, v)
        return to_populate

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        cert_model = SslCertificateModel.from_x509_certificate(certificate=WsFaker.get_ssl_certificate(as_string=False))
        for mapped_attribute in cert_model.all_mapping_fields:
            cert_model_value = getattr(cert_model, mapped_attribute)
            if cert_model_value is not None:
                setattr(to_populate, mapped_attribute, cert_model_value)
        to_populate.ssl_version = WsFaker.get_ssl_version_name()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslSupportReportModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model class for containing aggregated and analyzed data about a network service's
    support of SSL.
    """

    # Class Members

    cert_serial_number = KeywordElasticsearchType(
        help_text="The serial number of the service's SSL certificate.",
    )
    cert_version = IntElasticsearchType(
        help_text="The version number of the service's SSL certificate.",
    )
    cert_has_start_time = BooleanElasticsearchType(
        help_text="Whether or not the referenced certificate has a valid_after field.",
    )
    cert_start_time = DateElasticsearchType(
        help_text="The contents of the certificate's valid_after field.",
    )
    cert_has_invalid_time = BooleanElasticsearchType(
        help_text="Whether or not the referenced certificate has a valid_before field.",
    )
    cert_invalid_time = DateElasticsearchType(
        help_text="The contents of the certificate's valid_before field.",
    )
    cert_expired = BooleanElasticsearchType(
        help_text="Whether or not the certificate was expired at the time of collection.",
    )
    cert_md5_digest = KeywordElasticsearchType(
        help_text="The MD5 digest for the certificate.",
    )
    cert_sha1_digest = KeywordElasticsearchType(
        help_text="The SHA1 digest for the certificate.",
    )
    cert_sha256_digest = KeywordElasticsearchType(
        help_text="The SHA256 digest for the certificate.",
    )
    cert_sha512_digest = KeywordElasticsearchType(
        help_text="The SHA512 digest for the certificate.",
    )
    cert_key_bits = IntElasticsearchType(
        help_text="The number of bits for the key associated with the certificate.",
    )
    cert_key_type = KeywordElasticsearchType(
        help_text="The type of the key found within the certificate.",
    )
    cert_public_key = KeywordElasticsearchType(
        help_text="The contents of the public key found within the referenced certificate.",
    )
    cert_content = KeywordElasticsearchType(
        help_text="The contents of the certificate.",
    )
    cert_issuer_common_name = KeywordElasticsearchType(
        help_text="The common name associated with the certificate's issuer.",
    )
    cert_issuer_country = KeywordElasticsearchType(
        help_text="The country code associated with the certificate's issuer.",
    )
    cert_issuer_email = KeywordElasticsearchType(
        help_text="The email address associated with the certificate's issuer.",
    )
    cert_issuer_hash = KeywordElasticsearchType(
        help_text="The hash associated with the certificate's issuer.",
    )
    cert_issuer_locality = KeywordElasticsearchType(
        help_text="The locality code associated with the certificate's issuer.",
    )
    cert_issuer_organization = KeywordElasticsearchType(
        help_text="The name of the organization associated with the certificate's issuer.",
    )
    cert_issuer_organizational_unit = KeywordElasticsearchType(
        help_text="The unit of the organization associated with the certificate's issuer.",
    )
    cert_issuer_state = KeywordElasticsearchType(
        help_text="The state code associated with the certificate's issuer.",
    )
    cert_subject_common_name = KeywordElasticsearchType(
        help_text="The common name associated with the certificate's subject.",
    )
    cert_subject_country = KeywordElasticsearchType(
        help_text="The country code associated with the certificate's subject.",
    )
    cert_subject_email = KeywordElasticsearchType(
        help_text="The email address associated with the certificate's subject.",
    )
    cert_subject_hash = KeywordElasticsearchType(
        help_text="The hash associated with the certificate's subject.",
    )
    cert_subject_locality = KeywordElasticsearchType(
        help_text="The locality code associated with the certificate's subject.",
    )
    cert_subject_organization = KeywordElasticsearchType(
        help_text="The organization associated with the certificate's subject.",
    )
    cert_subject_organizational_unit = KeywordElasticsearchType(
        help_text="The unit of the organization associated with the certificate's subject.",
    )
    cert_subject_state = KeywordElasticsearchType(
        help_text="The state code associated with the certificate's subject.",
    )
    cert_extension_names = KeywordElasticsearchType(
        help_text="The names of the recognized certificate extensions found within the "
                  "certificate.",
    )
    cert_has_authority_key_id = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the authority_key_id extension.",
    )
    cert_authority_key_id = KeywordElasticsearchType(
        help_text="The contents of the certificate's authority_key_id extension.",
    )
    cert_has_subject_key_id = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the subject_key_id extension.",
    )
    cert_subject_key_id = KeywordElasticsearchType(
        help_text="The contents of the certificate's subject_key_id extension.",
    )
    cert_has_extended_key_usage = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the extended_key_usage extension.",
    )
    cert_extended_key_usage = KeywordElasticsearchType(
        help_text="The contents of the certificate's extended_key_usage extension.",
    )
    cert_has_certificate_policies = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the certificate_policies extension.",
    )
    cert_certificate_policies = KeywordElasticsearchType(
        help_text="The content of the certificate's certificate_policies extension.",
    )
    cert_has_crl_distribution_points = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the crl_distribution_points extension.",
    )
    cert_crl_distribution_points = KeywordElasticsearchType(
        help_text="The content of the certificate's crl_distribution_points extension.",
    )
    cert_has_subject_alt_name = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the subject_alt_name extension.",
    )
    cert_subject_alt_name = KeywordElasticsearchType(
        help_text="The content of the certificate's subject_alt_name extension.",
    )
    cert_has_authority_info_access = BooleanElasticsearchType(
        help_text="Whether or not the certificate has the authority_info_access extension.",
    )
    cert_authority_info_access = KeywordElasticsearchType(
        help_text="The content of the certificate's authority_info_access extension.",
    )
    cert_is_valid = BooleanElasticsearchType(
        help_text="Whether or not the certificate was found to be valid.",
    )
    supports_fallback_scsv = BooleanElasticsearchType(
        help_text="Whether or not the network service supports the fallback SCSV.",
    )
    is_vulnerable_to_heartbleed = BooleanElasticsearchType(
        help_text="Whether or not the network service is vulnerable to heartbleed.",
    )
    is_vulnerable_to_ccs_injection = BooleanElasticsearchType(
        help_text="Whether or not the network service is vulnerable to CCS injection.",
    )
    accepts_client_renegotiation = BooleanElasticsearchType(
        help_text="Whether or not the network service accepts client renegotiation.",
    )
    supports_secure_renegotiation = BooleanElasticsearchType(
        help_text="Whether or not the network service supports secure renegotiation.",
    )
    is_ticket_resumption_supported = BooleanElasticsearchType(
        help_text="Whether or not the network service supports ticket resumption.",
    )
    supports_sslv3 = BooleanElasticsearchType(
        help_text="Whether or not the network service supports SSLv3.",
    )
    supports_tlsv1 = BooleanElasticsearchType(
        help_text="Whether or not the network service supports TLSv1.0.",
    )
    supports_tlsv1_1 = BooleanElasticsearchType(
        help_text="Whether or not the network service supports TLSv1.1.",
    )
    supports_tlsv1_2 = BooleanElasticsearchType(
        help_text="Whether or not the network service supports TLSv1.2.",
    )
    sslv3_preferred_cipher = KeywordElasticsearchType(
        help_text="The preferred SSLv3 cipher for the network service.",
    )
    tlsv1_preferred_cipher = KeywordElasticsearchType(
        help_text="The preferred TLSv1.0 cipher for the network service.",
    )
    tlsv1_1_preferred_cipher = KeywordElasticsearchType(
        help_text="The preferred TLSv1.1 cipher for the network service.",
    )
    tlsv1_2_preferred_cipher = KeywordElasticsearchType(
        help_text="The preferred TLSv1.2 cipher for the network service.",
    )
    sslv3_supported_ciphers = KeywordElasticsearchType(
        help_text="The supported SSLV3 ciphers for the network service.",
    )
    tlsv1_supported_ciphers = KeywordElasticsearchType(
        help_text="The supported TLSv1.0 ciphers for the network service.",
    )
    tlsv1_1_supported_ciphers = KeywordElasticsearchType(
        help_text="The supported TLSv1.1 ciphers for the network service.",
    )
    tlsv1_2_supported_ciphers = KeywordElasticsearchType(
        help_text="The supported TLSv1.2 ciphers for the network service.",
    )
    is_vulnerable = BooleanElasticsearchType(
        help_text="Whether or not the network service suffers from any SSL/TLS-related "
                  "vulnerabilities.",
    )
    cert_is_trusted = BooleanElasticsearchType(
        help_text="Whether or not the certificate is trusted.",
    )
    scan_completed_at = DateElasticsearchType(
        help_text="The time at which the investigation of the referenced SSL/TLS network service "
                  "completed.",
    )
    cert_extensions = KeywordTextKeyValueElasticsearchType(
        key_name="extension_name",
        value_name="extension_content",
        help_text="The certificate extensions found within the certificate.",
    )
    supports_sslv2 = BooleanElasticsearchType(
        help_text="Whether or not the network service supports SSLv2.",
    )
    sslv2_preferred_cipher = KeywordElasticsearchType(
        help_text="The preferred SSLv2 cipher for the network service.",
    )
    sslv2_supported_ciphers = KeywordElasticsearchType(
        help_text="The supported SSLV3 ciphers for the network service.",
    )
    heartbleed_test_errored = BooleanElasticsearchType(
        help_text="Whether or not the heartbleed test threw an exception.",
    )
    fallback_scsv_test_errored = BooleanElasticsearchType(
        help_text="Whether or not the fallback SCSV test threw an exception.",
    )
    ccs_injection_test_errored = BooleanElasticsearchType(
        help_text="Whether or not the CCS injection test threw an exception.",
    )
    session_renegotiation_test_errored = BooleanElasticsearchType(
        help_text="Whether or not the session renegotiation test threw an exception.",
    )
    session_resumption_test_errored = BooleanElasticsearchType(
        help_text="Whether or not the session resumption test threw an exception.",
    )
    cert_certificate_policy_oids = KeywordElasticsearchType(
        help_text="The OIDs associated with the policies found within the certificate.",
    )
    cert_is_extended_validation = BooleanElasticsearchType(
        help_text="Whether or not the certificate is an extended validation certificate.",
    )

    # Instantiation

    def __init__(
            self,
            cert_serial_number=None,
            cert_version=None,
            cert_has_start_time=None,
            cert_start_time=None,
            cert_has_invalid_time=None,
            cert_invalid_time=None,
            cert_expired=None,
            cert_md5_digest=None,
            cert_sha1_digest=None,
            cert_sha256_digest=None,
            cert_sha512_digest=None,
            cert_key_bits=None,
            cert_key_type=None,
            cert_public_key=None,
            cert_content=None,
            cert_issuer_common_name=None,
            cert_issuer_country=None,
            cert_issuer_email=None,
            cert_issuer_hash=None,
            cert_issuer_locality=None,
            cert_issuer_organization=None,
            cert_issuer_organizational_unit=None,
            cert_issuer_state=None,
            cert_subject_common_name=None,
            cert_subject_country=None,
            cert_subject_email=None,
            cert_subject_hash=None,
            cert_subject_locality=None,
            cert_subject_organization=None,
            cert_subject_organizational_unit=None,
            cert_subject_state=None,
            cert_extension_names=None,
            cert_has_authority_key_id=None,
            cert_authority_key_id=None,
            cert_has_subject_key_id=None,
            cert_subject_key_id=None,
            cert_has_extended_key_usage=None,
            cert_extended_key_usage=None,
            cert_has_certificate_policies=None,
            cert_certificate_policies=None,
            cert_has_crl_distribution_points=None,
            cert_crl_distribution_points=None,
            cert_has_subject_alt_name=None,
            cert_subject_alt_name=None,
            cert_has_authority_info_access=None,
            cert_authority_info_access=None,
            cert_is_valid=None,
            supports_fallback_scsv=None,
            is_vulnerable_to_heartbleed=None,
            is_vulnerable_to_ccs_injection=None,
            accepts_client_renegotiation=None,
            supports_secure_renegotiation=None,
            is_ticket_resumption_supported=None,
            supports_sslv3=None,
            supports_tlsv1=None,
            supports_tlsv1_1=None,
            supports_tlsv1_2=None,
            sslv3_preferred_cipher=None,
            tlsv1_preferred_cipher=None,
            tlsv1_1_preferred_cipher=None,
            tlsv1_2_preferred_cipher=None,
            sslv3_supported_ciphers=None,
            tlsv1_supported_ciphers=None,
            tlsv1_1_supported_ciphers=None,
            tlsv1_2_supported_ciphers=None,
            is_vulnerable=None,
            cert_is_trusted=None,
            scan_completed_at=None,
            cert_extensions=None,
            supports_sslv2=None,
            sslv2_preferred_cipher=None,
            sslv2_supported_ciphers=None,
            heartbleed_test_errored=None,
            fallback_scsv_test_errored=None,
            ccs_injection_test_errored=None,
            session_renegotiation_test_errored=None,
            session_resumption_test_errored=None,
            cert_certificate_policy_oids=None,
            cert_is_extended_validation=None,
            **kwargs
    ):
        super(SslSupportReportModel, self).__init__(**kwargs)
        self.cert_serial_number = cert_serial_number
        self.cert_version = cert_version
        self.cert_has_start_time = cert_has_start_time
        self.cert_start_time = cert_start_time
        self.cert_has_invalid_time = cert_has_invalid_time
        self.cert_invalid_time = cert_invalid_time
        self.cert_expired = cert_expired
        self.cert_md5_digest = cert_md5_digest
        self.cert_sha1_digest = cert_sha1_digest
        self.cert_sha256_digest = cert_sha256_digest
        self.cert_sha512_digest = cert_sha512_digest
        self.cert_key_bits = cert_key_bits
        self.cert_key_type = cert_key_type
        self.cert_public_key = cert_public_key
        self.cert_content = cert_content
        self.cert_issuer_common_name = cert_issuer_common_name
        self.cert_issuer_country = cert_issuer_country
        self.cert_issuer_email = cert_issuer_email
        self.cert_issuer_hash = cert_issuer_hash
        self.cert_issuer_locality = cert_issuer_locality
        self.cert_issuer_organization = cert_issuer_organization
        self.cert_issuer_organizational_unit = cert_issuer_organizational_unit
        self.cert_issuer_state = cert_issuer_state
        self.cert_subject_common_name = cert_subject_common_name
        self.cert_subject_country = cert_subject_country
        self.cert_subject_email = cert_subject_email
        self.cert_subject_hash = cert_subject_hash
        self.cert_subject_locality = cert_subject_locality
        self.cert_subject_organization = cert_subject_organization
        self.cert_subject_organizational_unit = cert_subject_organizational_unit
        self.cert_subject_state = cert_subject_state
        self.cert_extension_names = cert_extension_names
        self.cert_has_authority_key_id = cert_has_authority_key_id
        self.cert_authority_key_id = cert_authority_key_id
        self.cert_has_subject_key_id = cert_has_subject_key_id
        self.cert_subject_key_id = cert_subject_key_id
        self.cert_has_extended_key_usage = cert_has_extended_key_usage
        self.cert_extended_key_usage = cert_extended_key_usage
        self.cert_has_certificate_policies = cert_has_certificate_policies
        self.cert_certificate_policies = cert_certificate_policies
        self.cert_has_crl_distribution_points = cert_has_crl_distribution_points
        self.cert_crl_distribution_points = cert_crl_distribution_points
        self.cert_has_subject_alt_name = cert_has_subject_alt_name
        self.cert_subject_alt_name = cert_subject_alt_name
        self.cert_has_authority_info_access = cert_has_authority_info_access
        self.cert_authority_info_access = cert_authority_info_access
        self.cert_is_valid = cert_is_valid
        self.supports_fallback_scsv = supports_fallback_scsv
        self.is_vulnerable_to_heartbleed = is_vulnerable_to_heartbleed
        self.is_vulnerable_to_ccs_injection = is_vulnerable_to_ccs_injection
        self.accepts_client_renegotiation = accepts_client_renegotiation
        self.supports_secure_renegotiation = supports_secure_renegotiation
        self.is_ticket_resumption_supported = is_ticket_resumption_supported
        self.supports_sslv3 = supports_sslv3
        self.supports_tlsv1 = supports_tlsv1
        self.supports_tlsv1_1 = supports_tlsv1_1
        self.supports_tlsv1_2 = supports_tlsv1_2
        self.sslv3_preferred_cipher = sslv3_preferred_cipher
        self.tlsv1_preferred_cipher = tlsv1_preferred_cipher
        self.tlsv1_1_preferred_cipher = tlsv1_1_preferred_cipher
        self.tlsv1_2_preferred_cipher = tlsv1_2_preferred_cipher
        self.sslv3_supported_ciphers = sslv3_supported_ciphers
        self.tlsv1_supported_ciphers = tlsv1_supported_ciphers
        self.tlsv1_1_supported_ciphers = tlsv1_1_supported_ciphers
        self.tlsv1_2_supported_ciphers = tlsv1_2_supported_ciphers
        self.is_vulnerable = is_vulnerable
        self.cert_is_trusted = cert_is_trusted
        self.scan_completed_at = scan_completed_at
        self.cert_extensions = cert_extensions
        self.supports_sslv2 = supports_sslv2
        self.sslv2_preferred_cipher = sslv2_preferred_cipher
        self.sslv2_supported_ciphers = sslv2_supported_ciphers
        self.heartbleed_test_errored = heartbleed_test_errored
        self.fallback_scsv_test_errored = fallback_scsv_test_errored
        self.ccs_injection_test_errored = ccs_injection_test_errored
        self.session_renegotiation_test_errored = session_renegotiation_test_errored
        self.session_resumption_test_errored = session_resumption_test_errored
        self.cert_certificate_policy_oids = cert_certificate_policy_oids
        self.cert_is_extended_validation = cert_is_extended_validation

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.cert_serial_number = ":".join(WsFaker.get_words())
        to_populate.cert_version = WsFaker.get_random_int()
        to_populate.cert_has_start_time = RandomHelper.flip_coin()
        to_populate.cert_start_time = WsFaker.get_time_in_past()
        to_populate.cert_has_invalid_time = RandomHelper.flip_coin()
        to_populate.cert_invalid_time = WsFaker.get_time_in_future()
        to_populate.cert_expired = RandomHelper.flip_coin()
        to_populate.cert_md5_digest = WsFaker.get_sha256_string()
        to_populate.cert_sha1_digest = WsFaker.get_sha256_string()
        to_populate.cert_sha256_digest = WsFaker.get_sha256_string()
        to_populate.cert_sha512_digest = WsFaker.get_sha256_string()
        to_populate.cert_key_bits = WsFaker.get_random_int()
        to_populate.cert_key_type = "RSA"
        to_populate.cert_public_key = ".".join(WsFaker.get_words(200))
        to_populate.cert_content = ".".join(WsFaker.get_words(200))
        to_populate.cert_issuer_common_name = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_country = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_email = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_hash = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_locality = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_organization = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_organizational_unit = WsFaker.get_words(1)[0]
        to_populate.cert_issuer_state = WsFaker.get_words(1)[0]
        to_populate.cert_subject_common_name = WsFaker.get_domain_name()
        to_populate.cert_subject_country = WsFaker.get_words(1)[0]
        to_populate.cert_subject_email = WsFaker.get_words(1)[0]
        to_populate.cert_subject_hash = WsFaker.get_words(1)[0]
        to_populate.cert_subject_locality = WsFaker.get_words(1)[0]
        to_populate.cert_subject_organization = WsFaker.get_words(1)[0]
        to_populate.cert_subject_organizational_unit = WsFaker.get_words(1)[0]
        to_populate.cert_subject_state = WsFaker.get_words(1)[0]
        to_populate.cert_extension_names = WsFaker.get_words(5)
        to_populate.cert_has_authority_key_id = RandomHelper.flip_coin()
        to_populate.cert_authority_key_id = WsFaker.get_words(1)[0]
        to_populate.cert_has_subject_key_id = RandomHelper.flip_coin()
        to_populate.cert_subject_key_id = WsFaker.get_words(1)[0]
        to_populate.cert_has_extended_key_usage = RandomHelper.flip_coin()
        to_populate.cert_extended_key_usage = WsFaker.get_words(1)[0]
        to_populate.cert_has_certificate_policies = RandomHelper.flip_coin()
        to_populate.cert_certificate_policies = WsFaker.get_words(1)[0]
        to_populate.cert_has_crl_distribution_points = RandomHelper.flip_coin()
        to_populate.cert_crl_distribution_points = WsFaker.get_words(1)[0]
        to_populate.cert_has_subject_alt_name = RandomHelper.flip_coin()
        to_populate.cert_subject_alt_name = WsFaker.get_words(1)[0]
        to_populate.cert_has_authority_info_access = RandomHelper.flip_coin()
        to_populate.cert_authority_info_access = WsFaker.get_words(1)[0]
        to_populate.cert_is_valid = RandomHelper.flip_coin()
        to_populate.supports_fallback_scsv = RandomHelper.flip_coin()
        to_populate.is_vulnerable_to_heartbleed = RandomHelper.flip_coin()
        to_populate.is_vulnerable_to_ccs_injection = RandomHelper.flip_coin()
        to_populate.accepts_client_renegotiation = RandomHelper.flip_coin()
        to_populate.supports_secure_renegotiation = RandomHelper.flip_coin()
        to_populate.is_ticket_resumption_supported = RandomHelper.flip_coin()
        to_populate.supports_sslv3 = RandomHelper.flip_coin()
        to_populate.supports_tlsv1 = RandomHelper.flip_coin()
        to_populate.supports_tlsv1_1 = RandomHelper.flip_coin()
        to_populate.supports_tlsv1_2 = RandomHelper.flip_coin()
        to_populate.sslv3_preferred_cipher = WsFaker.get_words()
        to_populate.tlsv1_preferred_cipher = WsFaker.get_words()
        to_populate.tlsv1_1_preferred_cipher = WsFaker.get_words()
        to_populate.tlsv1_2_preferred_cipher = WsFaker.get_words()
        to_populate.sslv3_supported_ciphers = WsFaker.get_words()
        to_populate.tlsv1_supported_ciphers = WsFaker.get_words()
        to_populate.tlsv1_1_supported_ciphers = WsFaker.get_words()
        to_populate.tlsv1_2_supported_ciphers = WsFaker.get_words()
        to_populate.is_vulnerable = RandomHelper.flip_coin()
        to_populate.cert_is_trusted = RandomHelper.flip_coin()
        to_populate.scan_completed_at = WsFaker.get_time_in_past()
        to_populate.cert_extensions = WsFaker.get_certificate_extensions()
        to_populate.supports_sslv2 = RandomHelper.flip_coin()
        to_populate.sslv2_preferred_cipher = WsFaker.get_words()
        to_populate.sslv2_supported_ciphers = WsFaker.get_words()
        to_populate.heartbleed_test_errored = RandomHelper.flip_coin()
        to_populate.fallback_scsv_test_errored = RandomHelper.flip_coin()
        to_populate.ccs_injection_test_errored = RandomHelper.flip_coin()
        to_populate.session_renegotiation_test_errored = RandomHelper.flip_coin()
        to_populate.session_resumption_test_errored = RandomHelper.flip_coin()
        to_populate.cert_certificate_policy_oids = WsFaker.get_words()
        to_populate.cert_is_extended_validation = RandomHelper.flip_coin()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
