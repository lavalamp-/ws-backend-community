# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import HashHelper
from lib import ValidationHelper, ConversionHelper, WsIntrospectionHelper, ComparisonHelper, ScrapyItemizableMixin
from ..base import BaseWrapper
from .exception import InvalidMimeStringError, MarkupAttributeNotFoundError

logger = logging.getLogger(__name__)


def get_data_type_wrapper_map():
    """
    Get a dictionary that maps MIME type strings to wrapper classes that are built to parse
    the given type of data.
    :return: A dictionary that maps MIME type strings to wrapper classes that are built to parse
    the given type of data.
    """
    class_tuples = WsIntrospectionHelper.get_data_type_wrapper_classes()
    return {wrapper_class.get_mime_type(): wrapper_class for class_name, wrapper_class in class_tuples}


class BaseDataTypeWrapper(BaseWrapper, ScrapyItemizableMixin):
    """
    This is a base class for all wrapper classes that wrap a specific MIME type of data.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_mime_type(cls):
        """
        Get a string representing the MIME data type that this class is meant to parse.
        :return: A string representing the MIME data type that this class is meant to parse.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    def get_scrapy_item_class(self):
        from lib.inspection import GenericWebResourceItem
        return GenericWebResourceItem

    def get_scrapy_item_kwargs(self):
        return {
            "coalesced_content_type": self.mime_type,
            "content_md5_hash": HashHelper.md5_digest(self.wrapped_data),
            "content_sha256_hash": HashHelper.sha256_digest(self.wrapped_data),
        }

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def mime_type(self):
        """
        Get a string representing the MIME data type that this class is meant to parse.
        :return: A string representing the MIME data type that this class is meant to parse.
        """
        return self.__class__.get_mime_type()

    # Representation and Comparison


class BaseMarkupWrapper(BaseDataTypeWrapper):
    """
    This is a wrapper class for wrapping any content that follows the syntax of a mark-up language.
    """

    # Class Members

    _child_decomposition = None
    _full_decomposition = None
    _retrieved_children = None
    _root_element = None
    _unexpected_count = None

    # Instantiation

    def __init__(self, to_wrap):
        """
        Initialize this class to have a parser that can analyze the contents of to_wrap based
        on adherence to a specific mark-up language.
        :param to_wrap: The data to wrap.
        """
        self._root_element = self._get_parser_method()(to_wrap)
        self._retrieved_attributes = {}
        self._retrieved_children = {}
        self._unexpected_count = 0
        super(BaseMarkupWrapper, self).__init__(to_wrap)

    # Static Methods

    # Class Methods

    # Public Methods

    def get_distance_from(self, other_wrapper):
        """
        Get a measure of distance between the structure of the markup wrapped by this class
        and the structure of the markup wrapped by other_wrapper.
        :param other_wrapper: A markup wrapper class instance.
        :return: A measure of distance between the markup structure of self vs. other_wrapper.
        """
        return ComparisonHelper.compare_strings_by_edit_distance(
            first=self.full_decomposition,
            second=other_wrapper.full_decomposition,
        )

    # Protected Methods

    def _get_element_attribute(self, key=None, required=False):
        """
        Get the attribute from self.root_element as specified by name, and raise
        an error if is_required is True and the attribute is not found.
        :param key: The name of the attribute to retrieve.
        :param required: Whether or not the attribute is required.
        :return: The value of the specified attribute in self.root_element.
        """
        if key not in self.root_element.attrib and required:
            raise MarkupAttributeNotFoundError(
                "Attribute with key %s not found in tag %s. Element was %s."
                % (key, self.tag_name, self.root_element.tag)
            )
        return self.root_element.attrib.get(key, None)

    def _get_parser_method(self):
        """
        Get the method that the wrapped data should be fed to to create a parser that can
        then be used for consumption of the wrapped data.
        :return: The method that the wrapped data should be fed to
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _tag_to_string(self, element):
        """
        Get a string representation of the type of tag represented by the given element.
        :param element: The element to process.
        :return: A string representing the type of tag the element represents.
        """
        return element.tag

    # Private Methods

    def __decompose(self, iterator):
        """
        Reduce the contents of the wrapped markup to a string representing the structure
        of the wrapped markup.
        :param iterator: An iterator to iterate over for the decomposition process.
        :return: A string representing the structure of the wrapped markup.
        """
        decomp_list = []
        index = 0
        for index, tag in enumerate(iterator):
            decomp_list.append(self.__tag_to_id(tag))
        to_return = "".join(decomp_list)
        logger.debug(
            "Decomposed a total of %s elements into the string %s."
            % (index, to_return)
        )
        return to_return

    def __tag_to_id(self, element):
        """
        Return a string representing an identifier for the given markup tag. This is used by
        self.__decompose to map tags to their string representations.
        :param element: The element to process.
        :return: A string representing an ID attached to the tag.
        """
        to_process = self._tag_to_string(element)
        return to_process.strip().lower()[0]

    # Properties

    @property
    def child_decomposition(self):
        """
        Get a string representing the structure of markup of the immediate children
        of self.root_element.
        :return: a string representing the structure of markup of the immediate
        children of self.root_element.
        """
        if self._child_decomposition is None:
            self._child_decomposition = self.__decompose(self.root_element.iterchildren())
        return self._child_decomposition

    @property
    def full_decomposition(self):
        """
        Get a string representing the structure of the wrapped markup.
        :return: a string representing the structure of the wrapped markup.
        """
        if self._full_decomposition is None:
            self._full_decomposition = self.__decompose(self.root_element.iterdescendants())
        return self._full_decomposition

    @property
    def has_content(self):
        """
        Get whether or not self.root_element has any content (other than child tags) within
        it.
        :return: True if self.root_element has any content other than child tags within it,
        False otherwise.
        """
        return bool(self.text)

    @property
    def tag_name(self):
        """
        Get the name of the tag that this element is wrapping.
        :return: the name of the tag that this element is wrapping.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def text(self):
        """
        Get the text contents of self.root_element.
        :return: the text contents of self.root_element.
        """
        return self.root_element.text

    @property
    def root_element(self):
        """
        Get the root element of the mark-up language to use for parsing.
        :return: the root element of the mark-up language to use for parsing.
        """
        return self._root_element

    # Representation and Comparison

    def __eq__(self, other):
        """
        Check to see whether two markup wrapper instances are equivalent.
        :param other: An instance of a MarkupWrapper subclass to compare.
        :return: True if self and other are equivalent.
        """
        return self.get_distance_from(other) == 0


class MimeWrapper(BaseWrapper):
    """
    A wrapper class for wrapping a string that contains a MIME type.
    """

    # Class Members

    _subtype = None
    _parameter_string = None
    _type_string = None
    _type = None

    # Instantiation

    def __init__(self, mime_string):
        """
        Initializes the class to maintain a reference to the MIME string in mime_string.
        :param mime_string: A string containing a MIME type.
        :return: None
        """
        try:
            ValidationHelper.validate_mime_string(mime_string)
        except ValueError as e:
            raise InvalidMimeStringError(message=e.message)
        super(MimeWrapper, self).__init__(mime_string)
        self.__prepare_string_components()

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    def __prepare_string_components(self):
        """
        Analyzes self._mime_string and sets self._type, self._subtype, and self._parameter_string
        as appropriate.
        :return: None
        """
        to_process = self.wrapped_data
        if ";" in to_process:
            self._parameter_string = to_process[to_process.find(";") + 1:].strip()
            mime_body = to_process[:to_process.find(";")]
            self._type_string = mime_body[:mime_body.find("/")].strip()
            self._subtype = mime_body[mime_body.find("/")+1:].strip()
        else:
            self._type_string = to_process[:to_process.find("/")].strip()
            self._subtype = to_process[to_process.find("/")+1:].strip()

    # Properties

    @property
    def is_css_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to CSS
        content.
        :return: True if self._mime_string indicates CSS content type, False otherwise.
        """
        return self.type == "css"

    @property
    def is_html_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to HTML
        content.
        :return: True if self._mime_string indicates an HTML content type, False otherwise.
        """
        return self.type == "html"

    @property
    def is_image_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to image
        content.
        :return: True if self._mime_string indicates image content type, False otherwise.
        """
        return self.type == "image"

    @property
    def is_media_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to media
        content.
        :return: True if self._mime_string indicates a media content type, False otherwise.
        """
        return self.type == "media"

    @property
    def is_javascript_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to
        Javascript content.
        :return: True if self._mime_string indicates Javascript content type, False otherwise.
        """
        return self.type == "javascript"

    @property
    def is_json_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to
        JSON content.
        :return: True if self._mime_string indicates JSON content type, False otherwise.
        """
        return self.type == "json"

    @property
    def is_pdf_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to
        PDF content.
        :return: True if self._mime_string indicates PDF content type, False otherwise.
        """
        return self.type == "pdf"

    @property
    def is_text_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to
        text content.
        :return: True if self._mime_string indicates text content type, False otherwise.
        """
        return self.type == "text"

    @property
    def is_xml_mime_type(self):
        """
        Checks to see whether the MIME string wrapped by the object corresponds to XML
        content.
        :return: True if self._mime_string indicates XML content type, False otherwise.
        """
        return self.type == "xml"

    @property
    def parameter_string(self):
        """
        Gets the contents of self._mime_string after the ";" character, if a semi-color
        existed in the input string.
        :return: The contents of self._mime_string after ";" if ";" in self._mime_string,
        otherwise None.
        """
        return self._parameter_string

    @property
    def subtype(self):
        """
        Gets the MIME string's subtype value.
        :return: The MIME string's subtype value.
        """
        return self._subtype

    @property
    def type(self):
        """
        Get a constant representing the MIME type that the wrapped string represents.
        :return: a constant representing the MIME type that the wrapped string represents.
        """
        if self._type is None:
            self._type = ConversionHelper.mime_wrapper_to_mime_type(self)
        return self._type

    @property
    def type_string(self):
        """
        Gets the MIME string's type value as a string.
        :return: The MIME string's type value as a string.
        """
        return self._type_string

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.wrapped_data)