# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import ValidationHelper, DatetimeHelper
from wselasticsearch.query.response import ElasticsearchQueryResponse
from ..helper import ElasticsearchHelper
from .types import *
from .exception import NoMappedParentClassFoundError


class BaseElasticsearchModel(object):
    """
    A base class for all object models that shall be stored in Elasticsearch.
    """

    # Class Members

    created = DateElasticsearchType()

    # Instantiation

    def __init__(self, created=None):
        self._id = None
        if created is None:
            created = DatetimeHelper.now()
        self.created = created

    # Static Methods

    # Class Methods

    @classmethod
    def create_dummies(cls, count):
        """
        Create and return the specified number of dummy instances of this model class.
        :param count: The number of dummy model instances to create.
        :return: A list containing the specified number of dummy instances of this
        model class.
        """
        return [cls.create_dummy() for i in range(count)]

    @classmethod
    def create_dummy(cls):
        """
        Create and return a dummy instance of this model class.
        :return: A dummy instance of this model class.
        """
        to_populate = cls()
        return cls.populate_dummy(to_populate)

    @classmethod
    def from_response_result(cls, result):
        """
        Create and return an instance of this model class populated by the contents of the given
        ElasticsearchQuery result.
        :param result: The result to process.
        :return: An instance of cls populated by the contents of the given query result.
        """
        to_return = cls(**result["_source"])
        to_return.id = result["_id"]
        return to_return

    @classmethod
    def from_response(cls, response):
        """
        Create and return a list of instances of this class as populated by the results found in the
        given ElasticsearchQueryResponse.
        :param response: The ElasticsearchQueryResponse to process.
        :return: A list of instances of this class as populated by the results found in the
        given ElasticsearchQueryResponse.
        """
        ValidationHelper.validate_type(to_check=response, expected_class=ElasticsearchQueryResponse)
        return [cls.from_response_result(x) for x in response.results]

    @classmethod
    def populate_dummy(cls, to_populate):
        """
        Populate the contents of the given Elasticsearch model as a dummy instance.
        :param to_populate: The Elasticsearch model to populate.
        :return: The newly-populated dummy model instance.
        """
        parent_class = cls.__bases__[0]
        if parent_class != object:
            if parent_class.get_can_populate_dummy():
                to_populate = parent_class.populate_dummy(to_populate=to_populate)
        return cls._populate_dummy(to_populate)

    @classmethod
    def _populate_dummy(cls, to_populate):
        """
        Populate the contents of the given instance of this class with fake data.
        :param to_populate: The object to populate
        :return: The populated object.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_all_mapping_fields(cls):
        """
        Get a list of strings representing the properties of self that are Elasticsearch fields.
        :return: A list of strings representing the properties of self that are Elasticsearch fields.
        """
        props = filter(lambda x: not x.startswith("_"), dir(cls))
        return filter(lambda x: isinstance(getattr(cls, x), BaseElasticsearchType), props)

    @classmethod
    def get_can_populate_dummy(cls):
        """
        Get whether or not this Elasticsearch model has functionality for populating a dummy
        model.
        :return: True if this Elasticsearch model has functionality for populating a dummy model,
        False otherwise.
        """
        return False

    @classmethod
    def get_diff_key_fields(cls):
        """
        Get a list of strings representing the fields of this model class that represent the key that is used
        to query Elasticsearch for the last instance of collected data during diff checks.
        :return: A list of strings representing the fields of this model class that represent the key that is used
        to query Elasticsearch for the last instance of collected data during diff checks.
        """
        to_return = []
        props = filter(lambda x: not x.startswith("_"), dir(cls))
        for prop in props:
            class_attr = getattr(cls, prop)
            if isinstance(class_attr, BaseElasticsearchType) and class_attr.diff_key:
                to_return.append(prop)
        return to_return

    @classmethod
    def get_diffable_mapping_fields(cls):
        """
        Get a list of strings representing the fields of this model class that are checked against for the
        Web Sight versioning system.
        :return: A list of strings representing the fields of this model class that are checked against for the
        Web Sight versioning system.
        """
        to_return = []
        props = filter(lambda x: not x.startswith("_"), dir(cls))
        for prop in props:
            class_attr = getattr(cls, prop)
            if isinstance(class_attr, BaseElasticsearchType) and class_attr.diffable:
                to_return.append(prop)
        return to_return

    @classmethod
    def get_doc_type(cls):
        """
        Get the Elasticsearch type that this model object represents.
        :return: The Elasticsearch type that this model object represents.
        """
        from lib import StringHelper
        class_name = cls.__name__.replace("Model", "")
        return StringHelper.to_dash_case(class_name)

    @classmethod
    def get_mapping_dict(cls):
        """
        Get a dictionary describing the types and mappings used by this model class.
        :return: A dictionary describing the types and mappings used by this model class.
        """
        prop_dict = {prop: getattr(cls, prop).to_dict() for prop in cls.get_all_mapping_fields()}
        return {
            "properties": prop_dict,
        }

    @classmethod
    def get_mapping_fields(cls):
        """
        Get a list of strings representing the properties of self that are both Elasticsearch fields and
        are instantiated in this class.
        :return: A list of strings representing the properties of self that are both Elasticsearch fields and
        are instantiated in this class.
        """
        to_return = []
        for k, v in cls.__dict__.iteritems():
            if isinstance(v, BaseElasticsearchType):
                to_return.append(k)
        return to_return

    @classmethod
    def update_mapping(cls, index):
        """
        Update the Elasticsearch mapping for this model class.
        :param index: The index to update.
        :return: The result of the Elasticsearch API call.
        """
        es_helper = ElasticsearchHelper.instance()
        return es_helper.update_mapping_for_model(model_class=cls, index=index)

    # Public Methods

    def get_diff_key_kwargs(self):
        """
        Get a dictionary containing key-value arguments for the contents of this model that should be
        searched for in Elasticsearch to find the last instance of data collected about the data source that
        this model represents.
        :return: A dictionary containing key-value arguments for the contents of this model that should be
        searched for in Elasticsearch to find the last instance of data collected about the data source that
        this model represents.
        """
        return {diff_field: getattr(self, diff_field) for diff_field in self.diff_key_fields}

    def save(self, index, as_update=False):
        """
        Save this model to the Elasticsearch backend.
        :param index: The index to save the model to.
        :param as_update: Whether or not to save this model as an update to an existing document. If
        this is True, then self.id must be populated.
        :return: The Elasticsearch response.
        """
        if as_update:
            if self.id is None:
                raise ValueError(
                    "Attempted to save model %s as an update, but no ID was present."
                    % (self.__class__.__name__,)
                )
            return self.es_helper.update_model(model=self, index=index)
        else:
            return self.es_helper.index_model(model=self, index=index)

    def to_es_dict(self):
        """
        Convert the contents of this model object into a Python dictionary for indexing into
        Elasticsearch.
        :return: The contents of this model in Python dictionary representation.
        """
        return {x: getattr(self, x) for x in self.__class__.get_all_mapping_fields()}

    # Protected Methods

    def _tuples_to_key_value_dicts(self, tuples):
        """
        Process the contents of header_tuples into key-value dictionaries for use as a
        KeyValueElasticsearchType.
        :param tuples: The list of tuples to process.
        :return: A list of dictionaries representing the contents of tuples.
        """
        if tuples is None:
            return []
        to_return = []
        for key, value in tuples:
            to_return.append({
                "key": key,
                "value": value,
            })
        return to_return

    # Private Methods

    # Properties

    @property
    def all_mapping_fields(self):
        """
        Get a list of the fields that are mapped to Elasticsearch types for this object.
        :return: a list of the fields that are mapped to Elasticsearch types for this object.
        """
        return self.__class__.get_all_mapping_fields()

    @property
    def can_populate_dummy(self):
        """
        Get whether or not this Elasticsearch model has functionality for populating a dummy
        model
        :return: True if this Elasticsearch model has functionality for populating a dummy model,
        False otherwise.
        """
        return self.__class__.get_can_populate_dummy()

    @property
    def diff_key_fields(self):
        """
        Get a list of strings representing the fields of this model class that represent the key that is used
        to query Elasticsearch for the last instance of collected data during diff checks.
        :return: A list of strings representing the fields of this model class that represent the key that is used
        to query Elasticsearch for the last instance of collected data during diff checks.
        """
        return self.__class__.get_diff_key_fields()

    @property
    def diffable_mapping_fields(self):
        """
        Get a list of strings representing the fields of this model class that are checked against for the
        Web Sight versioning system.
        :return: A list of strings representing the fields of this model class that are checked against for the
        Web Sight versioning system.
        """
        return self.__class__.get_diffable_mapping_fields()

    @property
    def doc_type(self):
        """
        Get the Elasticsearch document type that this object represents.
        :return: the Elasticsearch document type that this object represents.
        """
        return self.__class__.get_doc_type()

    @property
    def es_helper(self):
        """
        Get the ElasticsearchHelper instance.
        :return: The ElasticsearchHelper instance.
        """
        return ElasticsearchHelper.instance()

    @property
    def has_diff_key_fields(self):
        """
        Get whether or not this model class has any fields that are used to calculate diff keys.
        :return: whether or not this model class has any fields that are used to calculate diff keys.
        """
        return len(self.diff_key_fields) > 0

    @property
    def has_diffable_mapping_fields(self):
        """
        Get whether or not this model class has any fields that diffs can be calculated upon.
        :return: whether or not this model class has any fields that diffs can be calculated upon.
        """
        return len(self.diffable_mapping_fields) > 0

    @property
    def id(self):
        """
        Get the ID associated with this Elasticsearch model's document.
        :return: the ID associated with this Elasticsearch model's document.
        """
        return self._id

    @id.setter
    def id(self, new_value):
        """
        Set the ID associated with this Elasticsearch model's document.
        :param new_value: The ID value.
        :return: None
        """
        self._id = new_value

    @property
    def mapping_fields(self):
        """
        Get a list of strings representing the properties of self that are both Elasticsearch fields and
        are instantiated in this class.
        :return: A list of strings representing the properties of self that are both Elasticsearch fields and
        are instantiated in this class.
        """
        return self.__class__.get_mapping_fields()

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class BaseMappedElasticsearchModel(BaseElasticsearchModel):
    """
    This is a base class for all Elasticsearch models that are mapped to database models.
    """

    # Class Members

    flags = FlagElasticsearchType()

    # Instantiation

    def __init__(self, flags=None, **kwargs):
        super(BaseMappedElasticsearchModel, self).__init__(**kwargs)
        self.flags = flags

    # Static Methods

    @staticmethod
    def populate_from_database_model(mapped_class=None, database_model=None, to_populate=None):
        """
        Populate the contents of to_populate based on the contents of database_model. Calling this
        method will recurse up to the top-most model instance and Elasticsearch model, populating all
        fields on the way down. This method is very hacky, and has to alternate between classmethod
        and staticmethod calls to traverse the inheritance chain to only those classes which define
        the mapping methods.
        :param mapped_class: The mapped class to populate the model contents from.
        :param database_model: The database model to populate the object based on.
        :param to_populate: The Elasticsearch model to populate.
        :return: The populated Elasticsearch model.
        """
        if mapped_class.get_has_mapped_parent():
            parent_es_model_class = mapped_class.__bases__[0]
            parent_model_attribute = mapped_class.get_mapped_model_parent()
            parent_model = getattr(database_model, parent_model_attribute)
            to_populate = parent_es_model_class.populate_from_database_model(
                mapped_class=parent_es_model_class,
                database_model=parent_model,
                to_populate=to_populate,
            )
        to_populate = mapped_class._populate_from_database_model(
            database_model=database_model,
            to_populate=to_populate,
        )
        return to_populate

    # Class Methods

    @classmethod
    def from_database_model(cls, database_model, **kwargs):
        """
        Create and return a new instance of cls based on the contents of the given
        database model.
        :param database_model: A database model to populate this object from.
        :param kwargs: Additional keyword arguments to set on the returned model.
        :return: A newly-created instance of this class populated via the contents of database_model.
        """
        # ValidationHelper.validate_type(to_check=database_model, expected_class=cls.get_mapped_model_class())
        to_populate = kwargs.pop("to_populate", None)
        if to_populate is None:
            to_populate = cls(**kwargs)
        next_mapped_parent = cls.__get_next_mapping_parent_class()
        to_return = cls.populate_from_database_model(
            mapped_class=next_mapped_parent,
            database_model=database_model,
            to_populate=to_populate,
        )
        return to_return

    @classmethod
    def from_database_model_uuid(cls, uuid=None, db_session=None, **kwargs):
        """
        Create and return a new instance of cls based on the contents of a database model corresponding
        to the given UUID.
        :param uuid: The UUID of the model to create the instance based off of.
        :param db_session: A SQLAlchemy session.
        :param kwargs: Additional keyword arguments to set on the returned model.
        :return: A newly-created instance of this class populated by the contents of the database model
        corresponding to uuid.
        """
        model_class = cls.get_mapped_model_class()
        database_model = model_class.by_uuid(db_session=db_session, uuid=uuid)
        return cls.from_database_model(database_model, **kwargs)

    @classmethod
    def get_has_mapped_parent(cls):
        """
        Get a boolean depicting whether or not this class has a parent database model class that
        should be mapped as well.
        :return: A boolean depicting whether or not this class has a parent database model class that
        should be mapped as well.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_mapped_model_class(cls):
        """
        Get the database model class that this Elasticsearch model is mapped to.
        :return: The database model class that this Elasticsearch model is mapped to.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_mapped_model_parent(cls):
        """
        Get a string representing the attribute on the mapped model class where its parent
        resides.
        :return: A string representing the attribute on the mapped model class where its parent
        resides.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        """
        Populate the contents of to_populate based on the contents of the given database model.
        :param database_model: The database model to populate to_populate with.
        :param to_populate: An Elasticsearch model to populate.
        :return: The populated Elasticsearch model.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def __get_next_mapping_parent_class(cls):
        """
        Get the closest parent class (or this class) that defines a get_mapped_model_class method.
        :return: The closest parent class (or this class) that defines a get_mapped_model_class method.
        """
        cur_class = cls
        while True:
            if "get_mapped_model_class" in cur_class.__dict__:
                return cur_class
            cur_class = cur_class.__bases__[0]
            if cur_class == object:
                raise NoMappedParentClassFoundError("Current class is %s." % (cls,))
        return cur_class

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def has_mapped_parent(self):
        """
        Get a boolean depicting whether or not this class has a parent database model class that
        should be mapped as well.
        :return: A boolean depicting whether or not this class has a parent database model class that
        should be mapped as well.
        """
        return self.__class__.get_has_mapped_parent()

    @property
    def mapped_model_class(self):
        """
        Get the database model class that this Elasticsearch model is mapped to.
        :return: The database model class that this Elasticsearch model is mapped to.
        """
        return self.__class__.get_mapped_model_class()

    @property
    def mapped_model_parent(self):
        """
        Get a string representing the attribute on the mapped model class where its parent
        resides.
        :return: A string representing the attribute on the mapped model class where its parent
        resides
        """
        return self.__class__.get_mapped_model_parent()

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (parent %s)>" % (
            self.__class__.__name__,
            self.mapped_model_class,
            self.mapped_model_parent,
        )


class BaseScanElasticsearchModel(BaseElasticsearchModel):
    """
    A base class for all object models that shall be stored in Elasticsearch that are populated during
    a scan.
    """

    # Class Members

    org_uuid = KeywordElasticsearchType()
    scan_uuid = KeywordElasticsearchType()

    # Instantiation

    def __init__(self, org_uuid=None, scan_uuid=None):
        self.org_uuid = org_uuid
        self.scan_uuid = scan_uuid

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseScanTrackingElasticsearchModel(BaseScanElasticsearchModel):
    """
    A base class for all object models that contain data about the results of a given type of scan.
    """

    # Class Members

    start_time = DateElasticsearchType()
    end_time = DateElasticsearchType()
    scan_type = KeywordElasticsearchType()

    # Instantiation

    def __init__(
            self,
            start_time=None,
            end_time=None,
            **kwargs
    ):
        super(BaseScanTrackingElasticsearchModel, self).__init__(**kwargs)
        self.start_time = start_time
        self.end_time = end_time
        self.scan_type = self._get_scan_type()

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_scan_type(self):
        """
        Get a string representing the scan type that this scan model is related to.
        :return: A string representing the scan type that this scan model is related to.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    # Representation and Comparison
