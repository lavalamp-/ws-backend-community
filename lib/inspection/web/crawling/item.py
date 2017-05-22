# -*- coding: utf-8 -*-
from __future__ import absolute_import

import scrapy
import logging

from lib import ElasticsearchableMixin
from lib.exception import ValidationError
from lib.parsing import UrlWrapper, HttpReferenceWrapper
from lib.parsing.wrappers.exception import InvalidUrlError

logger = logging.getLogger(__name__)


class HttpTransaction(scrapy.Item, ElasticsearchableMixin):
    """
    This is a Scrapy item that extracts an HTTP transaction (request and response details).
    """

    requested_url = scrapy.Field()
    request_headers = scrapy.Field()
    request_method = scrapy.Field()
    query_arguments = scrapy.Field()
    body_arguments = scrapy.Field()
    response_status = scrapy.Field()
    response_headers = scrapy.Field()
    response_content_type = scrapy.Field()
    response_content_length = scrapy.Field()
    response_content_hash = scrapy.Field()
    response_content_secondary_hash = scrapy.Field()

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import HttpTransactionModel
        return HttpTransactionModel

    def _to_es_model(self):
        from wselasticsearch.models import HttpTransactionModel
        return HttpTransactionModel(
            response_headers=self["response_headers"],
            content_type=self["response_content_type"],
            content_length=self["response_content_length"],
            content_hash=self["response_content_hash"],
            content_secondary_hash=self["response_content_secondary_hash"],
            url=self["requested_url"],
            request_headers=self["request_headers"],
            request_method=self["request_method"],
            query_arguments=self["query_arguments"],
            body_arguments=self["body_arguments"],
            response_status=self["response_status"],
        )


class GenericWebResourceItem(scrapy.Item, ElasticsearchableMixin):
    """
    This is a scrapy item that extracts a generic resource from an HTTP transaction.
    """

    # Class Members

    url_path = scrapy.Field()
    request_headers = scrapy.Field()
    request_method = scrapy.Field()
    response_headers = scrapy.Field()
    query_arguments = scrapy.Field()
    body_arguments = scrapy.Field()
    response_status = scrapy.Field()
    content_type = scrapy.Field()
    coalesced_content_type = scrapy.Field()
    content_length = scrapy.Field()
    content_md5_hash = scrapy.Field()
    content_sha256_hash = scrapy.Field()

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import GenericWebResourceModel
        return GenericWebResourceModel

    # Public Methods

    # Protected Methods

    def _get_es_model_kwargs(self):
        """
        Get a dictionary of keyword arguments to provide to the Elasticsearch model instantiation.
        :return: A dictionary of keyword arguments to provide to the Elasticsearch model instantiation.
        """
        return {
            "url_path": self["url_path"],
            "request_headers": self["request_headers"],
            "request_method": self["request_method"],
            "response_headers": self["response_headers"],
            "query_arguments": self["query_arguments"],
            "body_arguments": self["body_arguments"],
            "response_status": self["response_status"],
            "content_type": self["content_type"],
            "coalesced_content_type": self["coalesced_content_type"],
            "content_length": self["content_length"],
            "content_md5_hash": self["content_md5_hash"],
            "content_sha256_hash": self["content_sha256_hash"],
        }

    def _to_es_model(self):
        from wselasticsearch.models import GenericWebResourceModel
        return GenericWebResourceModel(**self._get_es_model_kwargs())

    # Private Methods

    # Properties

    # Representation and Comparison


class HtmlWebResourceItem(GenericWebResourceItem):
    """
    This is a scrapy item that extracts HTML-relevant data from an HTTP transaction.
    """

    # Class Members

    title = scrapy.Field()
    tag_decomposition = scrapy.Field()
    total_tag_count = scrapy.Field()
    html_tags = scrapy.Field()
    url_references = scrapy.Field()
    forms = scrapy.Field()
    meta_refresh_location = scrapy.Field()

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import HtmlWebResourceModel
        return HtmlWebResourceModel

    # Public Methods

    def to_es_model(self, site_url=None, **kwargs):
        """
        Convert the contents of this item into an Elasticsearch model, and update all of the necessary contents
        of the Elasticsearch model that require information about the inspected site.
        :param site_url: The URL of the site that this item was retrieved from.
        :param kwargs: Keyword arguments to pass to super.
        :return: The newly-created Elasticsearch model object.
        """
        to_return = super(GenericWebResourceItem, self).to_es_model(**kwargs)
        if not isinstance(site_url, UrlWrapper):
            site_url = UrlWrapper(site_url)
        if len(self["url_references"]) == 0:
            to_return.internal_url_reference_count = 0
            to_return.external_url_reference_count = 0
        else:
            internal_ref_count = 0
            external_ref_count = 0
            for reference_source, reference in self["url_references"]:
                if not reference.startswith("http://") and \
                        not reference.startswith("https://") and \
                        not reference.startswith("#"):
                    internal_ref_count += 1
                else:
                    ref_wrapper = HttpReferenceWrapper(reference)
                    if not ref_wrapper.has_http_protocol:
                        continue
                    try:
                        ref_url_wrapper = ref_wrapper.to_url_wrapper()
                        if ref_url_wrapper.has_same_origin(url_wrapper=site_url):
                            internal_ref_count += 1
                        else:
                            external_ref_count += 1
                    except (ValidationError, InvalidUrlError):
                        logger.error(
                            "Could not convert reference %s to URL."
                            % (reference,)
                        )
                        internal_ref_count += 1
            to_return.internal_url_reference_count = internal_ref_count
            to_return.external_url_reference_count = external_ref_count
        resource_url = site_url.resolve_against(self["url_path"])
        to_return.has_login_form = False
        to_return.has_local_login_form = False
        for form in self["forms"]:
            if form["has_action"]:
                action = form["action"]
                if action == "":
                    form["resolved_action"] = str(resource_url)
                    form["internal_action"] = True
                elif action.startswith("http://") or action.startswith("https://"):
                    form["resolved_action"] = action
                    try:
                        action_wrapper = UrlWrapper(action)
                        form["internal_action"] = site_url.has_same_origin(url_wrapper=action_wrapper)
                    except (ValidationError, InvalidUrlError):
                        logger.error(
                            "Could not convert action %s to URL."
                            % (action,)
                        )
                        form["internal_action"] = False
                else:
                    form["resolved_action"] = str(resource_url.resolve_against(action))
                    form["internal_action"] = True
            else:
                form["resolved_action"] = str(resource_url)
            action_wrapper = UrlWrapper(form["resolved_action"])
            form["https_submission"] = action_wrapper.is_https_scheme
            form["has_password_input"] = False
            form["has_email_input"] = False
            form["has_password_name"] = False
            for html_input in form["inputs"]:
                if html_input["type"] == "password":
                    form["has_password_input"] = True
                if html_input["type"] == "email":
                    form["has_email_input"] = True
                if html_input["name"] is not None:
                    if "password" in html_input["name"].lower():
                        form["has_password_name"] = True
            if form["has_password_input"]:
                to_return.has_login_form = True
                if form["internal_action"]:
                    to_return.has_local_login_form = True
        return to_return

    # Protected Methods

    def _get_es_model_kwargs(self):
        to_return = super(HtmlWebResourceItem, self)._get_es_model_kwargs()
        to_return.update({
            "title": self["title"],
            "tag_decomposition": self["tag_decomposition"],
            "total_tag_count": self["total_tag_count"],
            "html_tags": self["html_tags"],
            "forms": self["forms"],
            "meta_refresh_location": self["meta_refresh_location"],
        })
        return to_return

    def _to_es_model(self):
        from wselasticsearch.models import HtmlWebResourceModel
        return HtmlWebResourceModel(**self._get_es_model_kwargs())

    # Private Methods

    # Properties

    # Representation and Comparison


class HttpResource(scrapy.Item, ElasticsearchableMixin):
    """
    This is a Scrapy item that extracts a resource retrieved via HTTP request.
    """

    requested_url = scrapy.Field()
    request_headers = scrapy.Field()
    request_method = scrapy.Field()
    query_arguments = scrapy.Field()
    body_arguments = scrapy.Field()
    response_status = scrapy.Field()
    content_type = scrapy.Field()
    content_length = scrapy.Field()
    content_hash = scrapy.Field()
    content_secondary_hash = scrapy.Field()
    content = scrapy.Field()

    def _to_es_model(self):
        from wselasticsearch.models import GenericWebResourceModel
        return GenericWebResourceModel(
            content_type=self["content_type"],
            content_length=self["content_length"],
            content_hash=self["content_hash"],
            content_secondary_hash=self["content_secondary_hash"],
            content=self["content"],
            url=self["requested_url"],
            request_headers=self["request_headers"],
            request_method=self["request_method"],
            query_arguments=self["query_arguments"],
            body_arguments=self["body_arguments"],
            response_status=self["response_status"],
        )
