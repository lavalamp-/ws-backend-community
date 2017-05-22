# -*- coding: utf-8 -*-
from __future__ import absolute_import

from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from requests.packages.urllib3 import PoolManager
import ssl

from lib import Singleton, ValidationHelper, ConfigManager
from .query import HttpTransactionQuery

config = ConfigManager.instance()


class WsSslConnectionAdapter(HTTPAdapter):
    """
    This is an adapter class that forces the SSL version for SSL requests to a specific version.
    """

    SSL_VERSION = ssl.PROTOCOL_TLSv1_2

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        """
        Initializes a urllib3 PoolManager.

        This method should not be called from user code, and is only
        exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param connections: The number of urllib3 connection pools to cache.
        :param maxsize: The maximum number of connections to save in the pool.
        :param block: Block when no free connections are available.
        :param pool_kwargs: Extra keyword arguments used to initialize the Pool Manager.
        """
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            strict=True,
            ssl_version=self.SSL_VERSION,
            **pool_kwargs
        )


class WsElasticsearchConnection(RequestsHttpConnection):
    """
    A class for enabling HTTP proxies in Elasticsearch connections.
    """

    def __init__(self, *args, **kwargs):
        proxies = kwargs.pop("proxies", {})
        super(WsElasticsearchConnection, self).__init__(*args, **kwargs)
        self.session.proxies = proxies


@Singleton
class ElasticsearchQueryHelper(object):
    """
    This class contains methods that abstract away the hairy details of querying Elasticsearch to
    return Python data types.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def get_server_headers_for_web_service_scan(self, scan_uuid=None, org_uuid=None):
        """
        Get a list of strings representing the contents of all server header values retrieved during
        the given web service scan.
        :param scan_uuid: The UUID of the web service scan to get results for.
        :param org_uuid: The UUID of the organization that owns the related web service.
        :return: A list of strings representing the contents of all server header values retrieved during
        the given web service scan.
        """
        query = HttpTransactionQuery(size=10000)
        query.filter_by_web_service_scan(scan_uuid)
        query.must_by_term(key="response_headers.key", value="Server")
        query.queried_fields = ["response_headers"]
        response = query.search(org_uuid)
        response_header_sets = response.get_field_from_results("response_headers")
        server_values = []
        for response_header_set in response_header_sets:
            for header in response_header_set:
                if header["key"] == "Server":
                    server_values.append(header["value"])
        return list(set(server_values))

    def get_transactions_by_url_for_web_service_scan(self, scan_uuid=None, url_term=None, org_uuid=None):
        """
        Get a list of all the HttpTransactionModel objects for the given web service scan whose URLs
        contain the given term.
        :param scan_uuid: The web service scan UUID to search within.
        :param url_term: The URL term to search for.
        :param org_uuid: The UUID of the organization that owns the web service scan.
        :return: A list of all the HttpTransactionModel objects for the given web service scan whose URLs
        contain the given term.
        """
        query = HttpTransactionQuery(size=10000)
        query.filter_by_web_service_scan(scan_uuid)
        query.must_by_wildcard(key="url", value=url_term)
        response = query.search(org_uuid)
        return response.results

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


@Singleton
class ElasticsearchHelper(object):
    """
    Wrapper class for interacting with Elasticsearch.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._connection = None

    # Static Methods

    # Class Methods

    # Public Methods

    def bulk_request(self, *args, **kwargs):
        """
        Perform a bulk request against the Elasticsearch endpoint.
        :param args: Positional arguments for elasticsearch.bulk.
        :param kwargs: Keyword arguments for elasticsearch.bulk.
        :return: The response from the bulk operation.
        """
        return self.connection.bulk(*args, **kwargs)

    def index_document(self, *args, **kwargs):
        """
        Create a new Elasticsearch document.
        :param args: Positional arguments for elasticsearch.index.
        :param kwargs: Keyword arguments for elasticsearch.index.
        :return: The result of indexing the given document.
        """
        return self.connection.index(*args, **kwargs)

    def index_model(self, model=None, *args, **kwargs):
        """
        Create and index a new Elasticsearch document based on the contents of model.
        :param model: An instance of an Elasticsearch model to index.
        :param args: Positional arguments for elasticsearch.index.
        :param kwargs: Keyword arguments for elasticsearch.index.
        :return: The result of indexing the given document.
        """
        ValidationHelper.validate_es_model_type(model)
        kwargs["body"] = model.to_es_dict()
        kwargs["doc_type"] = model.doc_type
        return self.index_document(*args, **kwargs)

    def create_default_index(self):
        """
        Create the default Elasticsearch index.
        :return: The Elasticsearch API response.
        """
        return self.create_index(config.es_default_index)

    def create_index(self, name, ignore=400):
        """
        Create an index with the specified name.
        :param name: The name of the index to create.
        :param ignore: The status code (or codes) to ignore when attempting to create
        the index.
        :return: None
        """
        return self.connection.indices.create(index=name, ignore=ignore)

    def delete_index(self, name, ignore=[400, 404]):
        """
        Delete the index with the specified name.
        :param name: The name of the index to delete.
        :param ignore: The status code (or codes) to ignore when attempting to delete the
        index.
        :return: None
        """
        return self.connection.indices.delete(index=name, ignore=ignore)

    def delete_model_by_query(self, query=None, index=None):
        """
        Perform a delete_by_query query against the Elasticsearch backend that deletes all documents
        matching the query in query found within the given index.
        :param query: An Elasticsearch query instance.
        :param index: The index to perform the delete upon.
        :return: The Elasticsearch response.
        """
        ValidationHelper.validate_es_query_type(query)
        return self.connection.delete_by_query(
            index=index,
            doc_type=query.doc_type,
            body=query.to_query_dict(),
        )

    def get_document(
            self,
            doc_id=None,
            doc_type=None,
            index=None,
            *args,
            **kwargs
    ):
        """
        Get the Elasticsearch document matching the given document type and ID from the given index.
        :param doc_id: The ID of the document to retrieve.
        :param doc_type: The type of the document to retrieve.
        :param index: The index to retrieve the document from.
        :param args: Positional arguments for the get command.
        :param kwargs: Keyword arguments for the get command.
        :return: The Elasticsearch response.
        """
        kwargs["index"] = index
        kwargs["id"] = doc_id
        kwargs["doc_type"] = doc_type
        return self.connection.get(*args, **kwargs)

    def get_indices(self):
        """
        Get all of the indices currently found in the Elasticsearch backend.
        :return: A list containing all of the indices currently found in the Elasticsearch backend.
        """
        return self.connection.indices.get_alias().keys()

    def get_info(self):
        """
        Get general information about the Elasticsearch node.
        :return: A dictionary containing general information about the Elasticsearch node.
        """
        return self.connection.info()

    def search_index(self, *args, **kwargs):
        """
        Search an index using the Elasticsearch query DSL.
        :param args: Positional arguments for elasticsearch.search.
        :param kwargs: Keyword arguments for elasticsearch.search.
        :return: The result of elasticsearch.search.
        """
        return self.connection.search(*args, **kwargs)

    def search_model(self, model_class=None, *args, **kwargs):
        """
        Search an index for the referenced model type using the Elasticsearch query DSL.
        :param model_class: A model class to search for.
        :param args: Positional arguments for elasticsearch.search.
        :param kwargs: Keyword arguments for elasticsearch.search.
        :return: The result of elasticsearch.search.
        """
        ValidationHelper.validate_es_model_class(model_class)
        kwargs["doc_type"] = model_class.get_doc_type()
        return self.search_index(*args, **kwargs)

    def search_model_by_query(self, query=None, index=None):
        """
        Search an index and a model using the Elasticsearch query DSL based on the contents
        of the given query.
        :param query: The BaseElasticsearchQuery object to query off of.
        :return: The result of elasticsearch.search.
        """
        ValidationHelper.validate_es_query_type(query)
        return self.search_index(
            index=index,
            doc_type=query.doc_type,
            body=query.to_query_dict(),
        )

    def update_mapping_for_model(self, model_class=None, index=None):
        """
        Update the document type mapping for the document represented by the given model class.
        :param model_class: The model class to update the mappings for.
        :param index: The index to update the mapping in.
        :return: None
        """
        ValidationHelper.validate_es_model_class(model_class)
        self.connection.indices.put_mapping(
            model_class.get_doc_type(),
            index=index,
            body=model_class.get_mapping_dict(),
        )

    def update_mapping_for_models(self, model_classes=None, index=None):
        """
        Update the document type mapping for the documents represented by the given model classes.
        :param model_classes: A list of Elasticsearch model classes to update the mappings for the
         given index for.
        :param index: The index to update mappings for.
        :return: The Elasticsearch response.
        """
        body = {"mappings": {}}
        for model_class in model_classes:
            ValidationHelper.validate_es_model_class(model_class)
            body["mappings"][model_class.get_doc_type()] = model_class.get_mapping_dict()
        return self.connection.indices.put_mapping(
            None,
            index=index,
            body=body,
        )

    def update_model(self, model=None, index=None, *args, **kwargs):
        """
        Perform an update for the document associated with the given model in the given index.
        :param model: An instance of an Elasticsearch model class to perform the update based on.
        :param index: The index to perform the update in.
        :param args: Positional arguments for the Elasticsearch update method.
        :param kwargs: Keyword arguments for the Elasticsearch update method.
        :return: The Elasticsearch response.
        """
        ValidationHelper.validate_es_model_type(model)
        kwargs["index"] = index
        kwargs["doc_type"] = model.doc_type
        kwargs["id"] = model.id
        kwargs["body"] = {
            "doc": model.to_es_dict(),
        }
        return self.connection.update(*args, **kwargs)

    def update_model_by_query(self, query=None, index=None):
        """
        Perform an update_by_query action on the Elasticsearch backend to update the model referenced
        inside of query by its contents.
        :param query: The query to use for the update.
        :param index: The index to perform the update on.
        :return: The Elasticsearch response.
        """
        ValidationHelper.validate_es_query_type(query)
        return self.connection.update_by_query(
            index=index,
            doc_type=query.doc_type,
            body=query.to_query_dict(),
        )

    # Protected Methods

    # Private Methods

    def __get_aws_es_connection(self):
        """
        Create a new Elasticsearch connection to an AWS endpoint and return it.
        :return: An Elasticsearch connection.
        """
        from requests_aws4auth import AWS4Auth
        awsauth = AWS4Auth(config.aws_key_id, config.aws_secret_key, config.aws_default_region, "es")
        if config.http_proxy_enabled:
            proxies = {
                "http": config.http_proxy,
                "https": config.http_proxy,
            }
        else:
            proxies = {}
        return Elasticsearch(
            hosts=[{"host": config.es_host, "port": config.es_port}],
            http_auth=awsauth,
            use_ssl=True,
            verify_certs=True,
            connection_class=WsElasticsearchConnection,
            proxies=proxies,
        )

    def __get_es_connection(self):
        """
        Create a new connection to Elasticsearch and return it.
        :return: An Elasticsearch connection.
        """
        if config.es_use_aws:
            return self.__get_aws_es_connection()
        else:
            return self.__get_standard_es_connection()

    def __get_standard_es_connection(self):
        """
        Create a new standard Elasticsearch connection and return it.
        :return: An Elasticsearch connection.
        """
        if config.http_proxy_enabled:
            proxies = {
                "http": config.http_proxy,
                "https": config.http_proxy,
            }
        else:
            proxies = {}
        return Elasticsearch(
            [config.es_url],
            connection_class=WsElasticsearchConnection,
            proxies=proxies,
        )

    # Properties

    @property
    def connection(self):
        """
        Get the Elasticsearch connection to use.
        :return: the Elasticsearch connection to use.
        """
        if self._connection is None:
            self._connection = self.__get_es_connection()
        return self._connection

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)