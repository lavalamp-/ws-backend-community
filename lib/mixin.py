# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .filesystem import FilesystemHelper


class DictableMixin(object):
    """
    A mixin class for providing the to_dict method.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def to_dict(self):
        """
        Get a dictionary representation of this object.
        :return: A dictionary representation of this object.
        """
        return {self.key: self.value}

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def key(self):
        """
        Get the key to use for the dictionary.
        :return: The key to use for the dictionary.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def value(self):
        """
        Get the value to use for the dictionary.
        :return: The value to use for the dictionary.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison


class TempFileMixin(object):
    """
    A mixin class for keeping track of temporary files.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._temp_file_paths = None
        self._temp_directory_paths = None
        self.reset_file_paths()

    # Static Methods

    # Class Methods

    # Public Methods

    def delete_all(self):
        """
        Delete all temporary files and directories currently in use by this class.
        :return: None
        """
        self.delete_temporary_files()
        self.delete_temporary_directories()

    def delete_temporary_directories(self):
        """
        Delete all of the temporary directories.
        :return: None
        """
        for dir_path in self.temp_directory_paths:
            if FilesystemHelper.does_directory_exist(dir_path):
                FilesystemHelper.delete_directory(dir_path)
        self.reset_directory_paths()

    def delete_temporary_files(self):
        """
        Delete all of the temporary files.
        :return: None
        """
        for file_path in self.temp_file_paths:
            if FilesystemHelper.does_file_exist(file_path):
                FilesystemHelper.delete_file(file_path)
        self.reset_file_paths()

    def get_temporary_directory_path(self):
        """
        Get a local directory path that is guaranteed to not be in use currently.
        :return: A local directory path that is guaranteed to not be in use currently.
        """
        to_return = FilesystemHelper.get_temporary_file_path()
        self._temp_directory_paths.append(to_return)
        return to_return

    def get_temporary_file_path(self, file_ext=None):
        """
        Get a local file path that is guaranteed to not be in use currently.
        :param file_ext: The file extension to add to the temporary file path.
        :return: A local file path that is guaranteed to not be in use currently.
        """
        to_return = FilesystemHelper.get_temporary_file_path(file_ext=file_ext)
        self._temp_file_paths.append(to_return)
        return to_return

    def reset_directory_paths(self):
        """
        Reset the list of temporary directory paths.
        :return: None
        """
        self._temp_directory_paths = []

    def reset_file_paths(self):
        """
        Reset the list of temporary file paths.
        :return: None
        """
        self._temp_file_paths = []

    def reset_paths(self):
        """
        Reset all of the temporary paths held by this object.
        :return: None
        """
        self.reset_directory_paths()
        self.reset_file_paths()

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def temp_directory_paths(self):
        """
        Get a list of paths to temporary directories.
        :return: a list of paths to temporary directories.
        """
        return self._temp_directory_paths

    @property
    def temp_file_paths(self):
        """
        Get a list of local file paths to temporary files used by this object.
        :return: a list of local file paths to temporary files used by this object.
        """
        return self._temp_file_paths

    # Representation and Comparison


class ElasticsearchableMixin(object):
    """
    This is a mixin class that provides functionality for mapping inheritting classes to
    Elasticsearch documents.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        """
        Get the Elasticsearch model class that this mixin will generate instances of.
        :return: The Elasticsearch model class that this mixin will generate instances of.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    def to_es_model(self, model_uuid=None, db_session=None, model=None, **kwargs):
        """
        Get an Elasticsearch model instance representing the contents of this object.
        :param model_uuid: The UUID of the database model instance that the returned Elasticsearch
        model instance should be populated from.
        :param db_session: A SQLAlchemy session.
        :param model: The database model instance that the returned Elasticsearch model instance should
        be populated from. Note that only this or model_uuid and db_session should be populated - populating
        both is not supported.
        :param kwargs: Key-value pairs to set as values on the returned model.
        :return: An Elasticsearch model instance representing the contents of this object.
        """
        if model_uuid is not None:
            to_return = self.mapped_es_model_class.from_database_model_uuid(
                uuid=model_uuid,
                db_session=db_session,
            )
        elif model is not None:
            to_return = self.mapped_es_model_class.from_database_model(model)
        else:
            to_return = self.mapped_es_model_class()
        update_instance = self._to_es_model()
        mapped_fields = self.mapped_es_model_class.get_all_mapping_fields()
        for mapped_field in mapped_fields:
            update_attribute = getattr(update_instance, mapped_field)
            if update_attribute is not None:
                setattr(to_return, mapped_field, update_attribute)
        for k, v in kwargs.iteritems():
            setattr(to_return, k, v)
        return to_return

    def update_document(self, doc_id=None, **kwargs):
        """
        Update the document associated with the given ID based on the contents of this mixin class.
        :param doc_id: The ID of the document to update.
        :param kwargs: Keyword arguments to supply to self.to_es_model.
        :return: The Elasticsearch response.
        """
        document = self.to_es_model(**kwargs)
        document.id = doc_id
        if hasattr(document, "org_uuid"):
            index = document.org_uuid
        else:
            raise ValueError(
                "No index found on document %s."
                % (document,)
            )
        return document.save(index, as_update=True)

    # Protected Methods

    def _to_es_model(self):
        """
        Gather the contents of this object into an Elasticsearch model class.
        :return: The Elasticsearch model instance.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def mapped_es_model_class(self):
        """
        Get the Elasticsearch model class that this mixin will generate instances of.
        :return: The Elasticsearch model class that this mixin will generate instances of.
        """
        return self.__class__.get_mapped_es_model_class()

    # Representation and Comparison


class CrawlableMixin(object):
    """
    This is a mixin class that provides functionality for extracting URLs and URL paths from
    an object's contents.
    """

    # Class Members

    _url_tuples = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_url_tuples(self):
        """
        Get a list of tuples containing (1) a string describing where the URL or URL path was stored and (2)
        the URL or URL path itself.
        :return: A list of tuples containing (1) a string describing where the URL or URL path was stored
        and (2) the URL or URL path itself.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    def __get_url_tuples(self):
        """
        Get a list of tuples containing (1) a string describing where the URL or URL path was stored and (2)
        the URL or URL path itself.
        :return: A list of tuples containing (1) a string describing where the URL or URL path was stored
        and (2) an HttpReferenceWrapper wrapping the URL or URL path itself.
        """
        to_return = self._get_url_tuples()
        to_return = list(set(to_return))
        from lib.parsing import HttpReferenceWrapper
        return [(found_method, HttpReferenceWrapper(url)) for found_method, url in to_return]

    # Properties

    @property
    def url_tuples(self):
        """
        Get a list of tuples containing (1) a string describing where the URL or URL path was stored and (2)
        the URL or URL path itself.
        :return: A list of tuples containing (1) a string describing where the URL or URL path was stored
        and (2) an HttpReferenceWrapper wrapping the URL or URL path itself.
        """
        if self._url_tuples is None:
            self._url_tuples = self.__get_url_tuples()
        return self._url_tuples

    # Representation and Comparison


class ScrapyItemizableMixin(object):
    """
    This is a mixin class that provides functionality for extracting Scrapy items from inheriting
    classes.
    """

    def get_scrapy_item(self):
        """
        Get an instance of the Scrapy item as populated by the contents of this object.
        :return: An instance of the Scrapy item as populated by the contents of this object.
        """
        return self.get_scrapy_item_class()(self.get_scrapy_item_kwargs())

    def get_scrapy_item_class(self):
        """
        Get the Scrapy item class that this object creates instances of.
        :return: The Scrapy item class that this object creates instances of.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def get_scrapy_item_kwargs(self):
        """
        Get a dictionary of key-word arguments that should be passed as values to an instantiation of
        the referenced scrapy item class.
        :return: A dictionary of key-word arguments that should be passed as values to an instantiation of
        the referenced scrapy item class.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def iter_scrapy_items(self):
        """
        Get a generator that will iterate over all of the Scrapy items that this mixin class is
        capable of producing. This method should be overridden by classes that return multiple items.
        :return: A generator that will iterate over all of the Scrapy items that this mixin class is
        capable of producing.
        """
        yield self.get_scrapy_item()

    @property
    def has_many(self):
        """
        Get whether or not this mixin class can return multiple Scrapy items.
        :return: whether or not this mixin class can return multiple Scrapy items.
        """
        return False


class JsonSerializableMixin(object):
    """
    This is a mixin class for providing functionality that enables an object to be serialized to/from JSON.
    """

    @staticmethod
    def from_json(to_parse):
        """
        Create an instance of this object based on the contents of the given JSON dictionary.
        :param to_parse: The JSON dictionary to parse.
        :return: The newly-created object.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def to_json(self):
        """
        Get a JSON dictionary representing the internal state of this object.
        :return: A JSON dictionary representing the internal state of this object.
        """
        raise NotImplementedError("Subclasses must implement this!")
