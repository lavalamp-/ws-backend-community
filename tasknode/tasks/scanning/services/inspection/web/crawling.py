# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from lib.inspection import CrawlRunner
from lib.sqlalchemy import get_endpoint_information_for_web_service, WebServiceScan
from ......app import websight_app
from .....base import WebServiceTask
from lib import FilesystemHelper
from lib.parsing import UrlWrapper
from wselasticsearch.query import BulkElasticsearchQuery

logger = get_task_logger(__name__)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def crawl_web_service(
        self,
        web_service_uuid=None,
        org_uuid=None,
        web_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Crawl the given web service and index the results in Elasticsearch.
    :param web_service_uuid: The UUID of the web service to crawl.
    :param org_uuid: The UUID of the organization to crawl the web service on behalf of.
    :param web_service_scan_uuid: The UUID of the scan that this crawling session is part of.
    :return: None
    """
    ip_address, port, hostname, use_ssl = get_endpoint_information_for_web_service(
        web_service_uuid=web_service_uuid,
        db_session=self.db_session,
    )
    logger.info(
        "Now crawling endpoint at %s:%s for scan %s. Organization is %s."
        % (ip_address, port, web_service_scan_uuid, org_uuid)
    )
    runner = CrawlRunner()
    results_file_path, results_wrapper = runner.crawl_endpoint_to_file(
        ip_address=ip_address,
        port=port,
        use_ssl=use_ssl,
        hostname=hostname,
        in_separate_process=True,
    )
    logger.info(
        "Crawling completed for endpoint at %s:%s. Indexing results to Elasticsearch."
        % (ip_address, port)
    )
    bulk_query = BulkElasticsearchQuery()
    for es_model in results_wrapper.iter_es_models(web_service_scan=self.web_service_scan, site_url=self.web_service_url):
        bulk_query.add_model_for_indexing(model=es_model, index=org_uuid)
    logger.info(
        "Now updating Elasticsearch via bulk query. Total operations: %s."
        % (bulk_query.batch_length,)
    )
    bulk_query.save()
    FilesystemHelper.delete_file(results_file_path)
    logger.info(
        "Elasticsearch updated with crawling results for endpoint %s:%s and local file deleted."
        % (ip_address, port)
    )
