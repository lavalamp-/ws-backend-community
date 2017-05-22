# -*- coding: utf-8 -*-
from __future__ import absolute_import

import sys
import logging
import inspect
import pkgutil

logger = logging.getLogger(__name__)


class IntrospectionHelper(object):
    """
    This is a helper class for performing introspection.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def class_has_property(input_class=None, property_name=None):
        """
        Check to see whether the given class has a property by the name of property_name.
        :param input_class: The class to check.
        :param property_name: The name of the property to look for.
        :return: True if the class has a property by the specified name, False otherwise.
        """
        return any(
            [name is property_name for name, property in IntrospectionHelper.get_properties_from_class(input_class)])

    @staticmethod
    def get_all_classes_of_type(to_find=None, path="."):
        """
        Get all classes currently imported by the Python environment found
        in the given path.
        :param to_find: The class to find all instances of.
        :param path: The import path to walk.
        :return: A list of all classes that are subclasses of to_find as found
        in the given path.
        """
        to_return = []
        for importer, name, is_package in pkgutil.walk_packages(path=[path]):
            current_package_name = name if path is "." else ".".join([path.replace("/", "."), name])
            to_return.extend(IntrospectionHelper.get_classes_from_module_name(
                module_name=current_package_name,
                parent_class=to_find,
            ))
        return to_return

    @staticmethod
    def get_classes_from_module(module=None, parent_class=None):
        """
        Get a list of the classes contained within the specified
        module.
        :param module: A module to retrieve classes from.
        :param parent_class: A parent class that should be checked against for all classes
        returned by this method (to ensure that all returned classes are subclasses of
        parent_class). If this argument is not supplied, all classes will be returned.
        :return: A list of tuples containing (1) the name of the class and (2) the class itself
        for all classes contained within the specified module.
        """

        if not parent_class:
            return inspect.getmembers(module, inspect.isclass)
        else:
            return filter(lambda x: issubclass(x[1], parent_class), inspect.getmembers(module, inspect.isclass))

    @staticmethod
    def get_classes_from_module_name(module_name=None, parent_class=None, raise_error=False):
        """
        Get a list of the classes contained within the specified
        module.
        :param module_name: A string representing the module to retrieve all
        defined classes for.
        :param parent_class: A parent class that should be checked against for all classes
        returned by this method (to ensure that all returned classes are subclasses of
        parent_class). If this argument is not supplied, all classes will be returned.
        :param raise_error: Whether or not to raise an error when module_name is not found in
        sys.modules.
        :return: A list of tuples containing (1) the name of the class and (2) the class itself
        for all classes contained within the specified module.
        """
        if module_name not in sys.modules:
            if raise_error:
                raise ValueError(
                    "ImportsHelper.get_classes_from_module received a module that was "
                    "not found in sys.modules. Module name was %s."
                    % (module_name,)
                )
            else:
                logger.debug(
                    "ImportsHelper.get_classes_from_module received a module that was "
                    "not found in sys.modules. Module name was %s."
                    % (module_name,)
                )
                return []
        return IntrospectionHelper.get_classes_from_module(module=sys.modules[module_name], parent_class=parent_class)

    @staticmethod
    def get_constants_from_class(input_class):
        """
        Get all constants defined in the given class. Note that constants are defined as class
        variables whose names are in all caps, and start and end with alphabetic characters.
        :param input_class: The class to retrieve all constants for.
        :return: A dictionary containing constant values from input_class as keys, with their related
        values as dictionary values.
        """
        class_dir = dir(input_class)
        constant_keys = filter(
            lambda x: x.isupper() and not x.startswith("_") and not x.endswith("_"),
            class_dir,
        )
        return {constant_key: getattr(input_class, constant_key) for constant_key in constant_keys}

    @staticmethod
    def get_modules_starts_with(starts_with):
        """
        Get all imported modules where the module name starts with the given
        argument.
        :param starts_with: The string that all relevant modules should start with.
        :return: A list of tuples containing (1) the string representing the given
        module's import path and (2) the module itself.
        """
        module_names = filter(lambda x: x.startswith(starts_with), sys.modules)
        modules = {module_name: sys.modules[module_name] for module_name in module_names if
                   sys.modules[module_name]}
        return [(k, v) for k, v in modules.iteritems()]

    @staticmethod
    def get_properties_from_class(input_class):
        """
        Get all properties declared within the given class.
        :param input_class: The class to retrieve all properties for.
        :return: A list of tuples containing (1) the string representation of the given property and
        (2) the property itself for all properties found within the given class.
        """
        class_vars = vars(input_class)
        property_keys = filter(lambda x: isinstance(class_vars[x], property), class_vars)
        return [(property_key, class_vars[property_key]) for property_key in property_keys]

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class WsIntrospectionHelper(object):
    """
    This is a helper class for performing introspection on all Web Sight-specific modules.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def get_data_type_wrapper_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all data type wrapper
        classes.
        :return: A list of tuples containing (1) the class name and (2) the class for all data type wrapper
        classes.
        """
        from lib.parsing.wrappers.mime.base import BaseDataTypeWrapper, BaseMarkupWrapper
        from lib.parsing.wrappers.mime.html import BaseHtmlElementWrapper
        from lib.parsing.wrappers.mime import JavaScriptElementWrapper
        base_classes = [
            BaseDataTypeWrapper,
            BaseMarkupWrapper,
        ]
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseDataTypeWrapper,
            path="lib/parsing/wrappers/mime",
        )))
        to_return = filter(lambda x: x[1] not in base_classes, to_return)
        to_return = filter(lambda x: not issubclass(x[1], BaseHtmlElementWrapper), to_return)
        to_return = filter(lambda x: x[1] != JavaScriptElementWrapper, to_return)
        return to_return

    @staticmethod
    def get_domain_name_mixin_model_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all Elasticsearch model
        classes that make use of the DomainNameMixin mixin.
        :return: A list of tuples containing (1) the class name and (2) the class for all Elasticsearch model
        classes that make use of the DomainNameMixin mixin.
        """
        from wselasticsearch.models.mixin import DomainNameMixin
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=DomainNameMixin,
            path="wselasticsearch/models",
        )))
        return filter(lambda x: x[1] != DomainNameMixin, to_return)

    @staticmethod
    def get_domain_name_scan_query_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all Elasticsearch model
        classes that subclass BaseDomainNameModel.
        :return: a list of tuples containing (1) the class name and (2) the class for all Elasticsearch model
        classes that subclass BaseDomainNameModel.
        """
        from wselasticsearch.models.dns.base import BaseDomainNameScanModel
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseDomainNameScanModel,
            path="wselasticsearch/models/dns",
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    @staticmethod
    def get_elasticsearch_model_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the non-base
        Elasticsearch model classes.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the non-base
        Elasticsearch model classes.
        """
        from wselasticsearch.models.base import BaseElasticsearchModel
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseElasticsearchModel,
            path="wselasticsearch/models"
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    @staticmethod
    def get_export_type_wrapper_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all data exporter classes.
        :return: A list of tuples containing (1) the class name and (2) the class for all data exporter classes.
        """
        from lib.export.base import BaseExporter
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseExporter,
            path="lib/export",
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    @staticmethod
    def get_fingerprinting_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the non-base
        fingerprinting classes in the fingerprinting module.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the
        non-base fingerprinting classes in the fingerprinting module.
        """
        from lib.fingerprinting.base import BaseSslTcpFingerprinter, BaseTcpFingerprinter, BaseFingerprinter
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseFingerprinter,
            path="lib/fingerprinting",
        )))
        return filter(lambda x: x[1] not in [BaseFingerprinter, BaseTcpFingerprinter, BaseSslTcpFingerprinter], to_return)

    @staticmethod
    def get_html_element_wrapper_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the HTML element
        wrapper classes.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the HTML element
        wrapper classes.
        """
        from lib.parsing.wrappers.mime.html import BaseHtmlElementWrapper
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseHtmlElementWrapper,
            path="lib/parsing/wrappers/mime",
        )))
        return filter(lambda x: x[1] != BaseHtmlElementWrapper, to_return)

    @staticmethod
    def get_http_header_wrapper_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the HTTP header wrapper
        classes.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the HTTP header wrapper
        classes.
        """
        from lib.parsing.wrappers.http.headers import BaseHttpHeaderWrapper
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseHttpHeaderWrapper,
            path="lib/parsing/wrappers/http",
        )))
        return filter(lambda x: x[1] != BaseHttpHeaderWrapper, to_return)

    @staticmethod
    def get_ip_address_scan_query_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all Elasticsearch model
        classes that subclass BaseIpAddressScanModel.
        :return: a list of tuples containing (1) the class name and (2) the class for all Elasticsearch model
        classes that subclass BaseIpAddressScanModel.
        """
        from wselasticsearch.models.networks.base import BaseIpAddressScanModel
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseIpAddressScanModel,
            path="wselasticsearch/models/networks",
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    @staticmethod
    def get_network_service_scan_query_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all Elasticsearch model classes
        that subclass BaseNetworkServiceScanModel.
        :return: A list of tuples containing (1) the class name and (2) the class for all Elasticsearch model classes
        that subclass BaseNetworkServiceScanModel.
        """
        from wselasticsearch.models.services.base import BaseNetworkServiceScanModel
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseNetworkServiceScanModel,
            path="wselasticsearch/models",
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    @staticmethod
    def get_scrapy_item_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the Scrapy item
        classes defined in the crawling module.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the Scrapy item
        classes defined in the crawling module.
        """
        import lib.inspection.web.crawling.item
        import scrapy
        return list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=scrapy.Item,
            path="lib/inspection/web/crawling",
        )))

    @staticmethod
    def get_ssl_support_related_query_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all Elasticsearch models that
        inherit from SslSupportRelatedMixin.
        :return: A list of tuples containing (1) the class name and (2) the class for all Elasticsearch models that
        inherit from SslSupportRelatedMixin.
        """
        from wselasticsearch.models.mixin import SslSupportRelatedMixin
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=SslSupportRelatedMixin,
            path="wselasticsearch/models",
        )))
        return filter(lambda x: not x[0].endswith("Mixin"), to_return)

    @staticmethod
    def get_web_resource_model_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the Elasticsearch model
        classes that inherit from BaseWebResourceModel.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the Elasticsearch model
        classes that inherit from BaseWebResourceModel.
        """
        from wselasticsearch.models.web.resource import BaseWebResourceModel
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseWebResourceModel,
            path="wselasticsearch/models/web",
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    @staticmethod
    def get_web_service_scan_query_classes():
        """
        Get a list of tuples containing (1) the class name and (2) the class for all of the Elasticsearch query
        classes that subclass BaseWebServiceScanQuery.
        :return: A list of tuples containing (1) the class name and (2) the class for all of the Elasticsearch query
        classes that subclass BaseWebServiceScanQuery.
        """
        from wselasticsearch.models.web.base import BaseWebServiceScanModel
        to_return = list(set(IntrospectionHelper.get_all_classes_of_type(
            to_find=BaseWebServiceScanModel,
            path="wselasticsearch/models/web",
        )))
        return filter(lambda x: not x[0].startswith("Base"), to_return)

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
