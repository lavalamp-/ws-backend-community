# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import BulkElasticsearchQuery
from wselasticsearch.models import GenericWebResourceModel, HtmlWebResourceModel
from .base import BaseAnalysisInspectorTestCase
from lib.sqlalchemy import get_open_ports_for_web_service


class TestWebScanInspector(BaseAnalysisInspectorTestCase):
    """
    This is a test case for testing the WebScanInspector analysis class.
    """

    _organization = None
    _web_service_scan = None

    def tearDown(self):
        """
        Test this inspector class down by ensuring any of the lazily-loaded data is invalidated.
        :return: None
        """
        self._web_service_scan = None
        self._organization = None
        super(TestWebScanInspector, self).tearDown()

    def __get_generic_web_resource_models(self):
        """
        Get a list of generic web resource model objects to add to Elasticsearch.
        :return: A list of generic web resource model objects to add to Elasticsearch.
        """
        to_return = []
        for i in range(50):
            web_resource_model = GenericWebResourceModel.create_dummy()
            web_resource_model = GenericWebResourceModel.from_database_model(
                self.web_service_scan,
                to_populate=web_resource_model,
            )
            to_return.append(web_resource_model)
        for i in range(10):
            to_return[i].response_status = 200
            to_return[i+10].response_status = 301
            to_return[i+20].response_status = 401
            to_return[i+30].response_status = 403
            to_return[i+40].response_status = 500
        return to_return

    def __get_html_web_resource_models(self):
        """
        Get a list of HTML web resource model objects to add to Elasticsearch.
        :return: A list of HTML web resource model objects to add to Elasticsearch.
        """
        to_return = []
        for i in range(50):
            html_resource_model = HtmlWebResourceModel.create_dummy()
            html_resource_model = HtmlWebResourceModel.from_database_model(
                self.web_service_scan,
                to_populate=html_resource_model,
            )
            to_return.append(html_resource_model)
        for i in range(10):
            to_return[i].response_status = 200
            to_return[i+10].response_status = 301
            to_return[i+20].response_status = 401
            to_return[i+30].response_status = 403
            to_return[i+40].response_status = 500
        root_resource_model = HtmlWebResourceModel.create_dummy()
        root_resource_model = HtmlWebResourceModel.from_database_model(
            self.web_service_scan,
            to_populate=root_resource_model,
        )
        root_resource_model.title = "This is the root title"
        root_resource_model.url_path = "/"
        to_return.append(root_resource_model)
        return to_return

    def _get_inspector_class(self):
        from lib.inspection import WebScanInspector
        return WebScanInspector

    def _get_inspector_kwargs(self):
        return {
            "db_session": self.db_session,
            "web_scan_uuid": self.web_service_scan.uuid,
        }

    def _populate_elasticsearch(self):
        query = BulkElasticsearchQuery()
        query.add_models_for_indexing(models=self.__get_generic_web_resource_models(), index=self.organization.uuid)
        query.add_models_for_indexing(models=self.__get_html_web_resource_models(), index=self.organization.uuid)
        query.save()

    def test_open_ports_on_host(self):
        """
        Tests that the value of the open_ports_on_host property is correct.
        :return: None
        """
        open_ports = get_open_ports_for_web_service(
            db_session=self.db_session,
            web_service_uuid=self.web_service_scan.web_service.uuid,
        )
        self.assertTupleListsEqual(open_ports, self.inspector.open_ports_on_host)

    def test_landing_resource_exists(self):
        """
        Tests that the landing_resource property is properly populated.
        :return: None
        """
        self.assertIsNotNone(self.inspector.landing_resource)

    def test_forms(self):
        """
        Tests that the forms property is properly populated.
        :return: None
        """
        self.assertGreater(len(self.inspector.forms), 0)

    @property
    def organization(self):
        """
        Get the organization owned by the test user to use during testing.
        :return: the organization owned by the test user to use during testing.
        """
        if self._organization is None:
            self._organization = self.get_organization_for_user(user="user_1")
        return self._organization

    @property
    def web_service_scan(self):
        """
        Get the web service scan that this test case is meant to run analysis against.
        :return: the web service scan that this test case is meant to run analysis against.
        """
        if self._web_service_scan is None:
            self._web_service_scan = self.create_web_service_scan_for_user(user="user_1")
            self.db_session.commit()
        return self._web_service_scan

