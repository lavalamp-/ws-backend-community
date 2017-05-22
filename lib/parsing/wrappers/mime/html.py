# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from lxml import etree

from .base import BaseMarkupWrapper
from lib import CrawlableMixin, SanitationHelper, ConversionHelper, WsIntrospectionHelper, ConfigManager, \
    S3Helper, FilesystemHelper
from .js import JavaScriptElementWrapper
from wselasticsearch.models import MalformedHtmlModel

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


def get_html_tag_wrapper_map():
    """
    Get a dictionary that maps HTML tags to the wrapper classes that are meant to parse the
    tag contents.
    :return: A dictionary that maps HTML tags to the wrapper classes that are meant to parse the
    tag contents.
    """
    class_tuples = WsIntrospectionHelper.get_html_element_wrapper_classes()
    return {wrapper_class.get_element_type(): wrapper_class for class_name, wrapper_class in class_tuples}


class HtmlWrapper(BaseMarkupWrapper, CrawlableMixin):
    """
    This is a wrapper class for wrapping a string containing HTML.
    """

    # Class Members

    _children = None
    _children_loaded = None
    _child_map = None
    _tag_to_wrapper_map = None
    _unknown_wrapper_class = None

    # Instantiation

    def __init__(self, to_wrap):
        """
        Initialize this object to have an empty children map, and to mark that its
        children have not been loaded.
        :param to_wrap: The HTML to wrap.
        """
        to_wrap = self.__sanitize_html(to_wrap)
        self._children = []
        self._children_loaded = False
        self._child_map = {}
        self._tag_map = None
        self._title = None
        self._tag_count = None
        self._tag_count_map = None
        try:
            super(HtmlWrapper, self).__init__(to_wrap)
        except Exception as e:
            if config.gen_track_malformed_html:
                logger.warning(
                    "Exception thrown when parsing HTML: %s. Uploading HTML for troubleshooting."
                    % (e.message,)
                )
                self.__upload_malformed_html(html=to_wrap, error=e)
            super(HtmlWrapper, self).__init__("<html></html>")

    # Static Methods

    # Class Methods

    @classmethod
    def get_mime_type(cls):
        return "html"

    # Public Methods

    def find_url_references(self):
        """
        Get a list of tuples containing (1) a constant describing where the URL path was found and
        (2) the URL path for all URL paths found within this element and all of its descendants.
        :return: A list of tuples containing (1) a constant describing where the URL path was found and
        (2) the URL path for all URL paths found within this element and all of its descendants.
        """
        to_return = self._find_url_references()
        to_return.extend(self.__find_urls_in_attributes())
        for child in self.children:
            to_return.extend(child.find_url_references())
        return to_return

    def get_children_by_name(self, name):
        """
        Get all tags with the given name that are found in this HTML document.
        :param name: The name of the tag to retrieve.
        :return: A list containing all of the tags of the given type as found in this HTML document.
        """
        return self.tag_map.get(name, [])

    def get_es_html_tag_counts(self):
        """
        Get a list of dictionaries that format the contents of self.tag_count_map into the data types
        expected by Elasticsearch's HtmlWebResourceModel.
        :return: A list of dictionaries that format the contents of self.tag_count_map into the data types
        expected by Elasticsearch's HtmlWebResourceModel.
        """
        to_return = []
        for k, v in self.tag_count_map.iteritems():
            to_return.append({
                "tag": k,
                "count": v,
            })
        return to_return

    def get_scrapy_item_class(self):
        from lib.inspection import HtmlWebResourceItem
        return HtmlWebResourceItem

    def get_scrapy_item_kwargs(self):
        to_return = super(HtmlWrapper, self).get_scrapy_item_kwargs()
        to_return.update({
            "total_tag_count": self.tag_count,
            "title": self.title,
            "tag_decomposition": self.full_decomposition,
            "html_tags": self.get_es_html_tag_counts(),
            "url_references": [(x, y.wrapped_data) for x, y in self.url_tuples],
            "forms": [x.get_es_form_representation() for x in self.get_children_by_name("form")],
            "meta_refresh_location": self.refresh_meta_tag.refresh_url if self.refresh_meta_tag else None,
        })
        return to_return

    # Protected Methods

    def _count_children(self):
        """
        Count the number of children that are descendants from this element.
        :return: The number of children that are descendants from this element.
        """
        to_return = 0
        for cur_child in self.children:
            to_return += 1
            to_return += cur_child._count_children()
        return to_return

    def _find_url_references(self):
        """
        Search the contents of this element to see if it contains any references to URL paths, and return
        a list of tuples containing (1) a string indicating where the URL path was found and (2) the URL
        path itself.
        :return: A list of tuples containing (1) a string indicating where the URL path was found and (2) the URL
        path itself.
        """
        return []

    def _get_child_tag_name_map(self):
        """
        Get a dictionary mapping tag names to lists of all the instances of the given tag for all children
        that are descendant of this element.
        :return: A dictionary mapping tag names to lists of all the instances of the given tag for all children
        that are descendant of this element.
        """
        to_return = {}
        for cur_child in self.children:
            if cur_child.tag_name not in to_return:
                to_return[cur_child.tag_name] = []
            to_return[cur_child.tag_name].append(cur_child)
            child_tag_name_map = cur_child._get_child_tag_name_map()
            for k, v in child_tag_name_map.iteritems():
                if k not in to_return:
                    to_return[k] = []
                to_return[k].extend(v)
        return to_return

    def _get_hashable_data(self):
        return self.full_decomposition

    def _get_parser_method(self):
        return etree.HTML

    def _get_url_tuples(self):
        return self.find_url_references()

    def _get_tags_by_name(self, name):
        """
        Get a list containing all of the HTML tags that match the given name from all children that
        are descendant from this element.
        :return: A list containing all of the HTML tags that match the given name from all children that
        are descendant from this element.
        """
        to_return = []
        for cur_child in self.children:
            if cur_child.tag_name == name:
                to_return.append(cur_child)
            to_return.extend(cur_child._get_tags_by_name(name))
        return to_return

    def _tag_to_string(self, element):
        if callable(element.tag):
            called_tag = str(element.tag())
            if "<!--" in called_tag:
                return "comment"
            else:
                logger.error(
                    "Unable to determine what sort of tag element is. Tag is %s, called_tag is %s."
                    % (element, called_tag)
                )
                return "unknown"
        return super(HtmlWrapper, self)._tag_to_string(element)

    # Private Methods

    def __find_urls_in_attributes(self):
        """
        Inspect the contents of the attributes associated with self.root_element to see if
        any of the attributes contain URLs, and return a list of tuples containing any URLs that
        were found.
        :return: A list of tuples containing (1) the discovery method and (2) the URL path found
        in the attributes associated with self.root_element.
        """
        to_return = []
        url_attrs = filter(lambda x: "url" in x.lower(), self.root_element.attrib.keys())
        for url_attr in url_attrs:
            if not hasattr(self, url_attr):
                url_val = self.root_element.attrib[url_attr]
                logger.debug(
                    "Found a potential URL in attribute %s on tag %s (%s)."
                    % (url_attr, self.tag_name, url_val)
                )
                to_return.append(("attribute", url_val))
        return to_return

    def __getattr__(self, item):
        if not self.children_loaded:
            self.__load_children()
        if item in self._child_map:
            return self._child_map[item]
        else:
            return super(BaseMarkupWrapper, self).__getattribute__(item)

    def __load_children(self):
        """
        Load all of the child element wrappers for all of the children of self.root_element.
        :return: None
        """
        for element in self.root_element.getchildren():
            element_name = self._tag_to_string(element)
            if element_name == "comment":
                continue
            if element_name not in self.tag_to_wrapper_map:
                logger.debug(
                    "No wrapper class found for HTML element of type %s. Using unknown wrapper."
                    % (element_name,)
                )
                wrapper = self.unknown_wrapper_class(etree.tostring(element))
            else:
                wrapper_class = self.tag_to_wrapper_map[element_name]
                wrapper = wrapper_class(etree.tostring(element))
            if element_name not in self._child_map:
                self._child_map[element_name] = []
            self._child_map[element_name].append(wrapper)
            self._children.append(wrapper)
        self._children_loaded = True

    def __sanitize_html(self, to_sanitize):
        """
        Sanitize the contents of to_sanitize so that the lxml parser does not choke on it.
        :param to_sanitize: The HTML to sanitize.
        :return: The sanitized HTML.
        """
        return SanitationHelper.truncate_at_last_instance(to_process=to_sanitize, trunc_char=">")

    def __upload_malformed_html(self, html=None, error=None):
        """
        Upload the contents of to_upload to keep track of the data as malformed HTML that this class
        could not handle parsing.
        :param html: The contents of the HTML that caused an error.
        :param error: The error that was thrown.
        :return: None
        """
        s3_helper = S3Helper.instance()
        temp_file = FilesystemHelper.get_temporary_file_path()
        FilesystemHelper.write_to_file(file_path=temp_file, write_mode="wb+", data=html)
        response, key = s3_helper.upload_bad_html(temp_file, bucket=config.aws_s3_bucket)
        FilesystemHelper.delete_file(temp_file)
        bad_html_model = MalformedHtmlModel(traceback="", error_message=error.message)
        bad_html_model.set_s3_attributes(bucket=config.aws_s3_bucket, key=key, file_type="malformed-html")
        bad_html_model.save(config.es_default_index)
        logger.info("Successfully uploaded malformed HTML to S3, record to Elasticsearch.")

    # Properties

    @property
    def children(self):
        """
        Get a list of all the children of self.root_element wrapped by Web Sight wrapper classes.
        :return: a list of all the children of self.root_element wrapped by Web Sight wrapper classes.
        """
        if not self.children_loaded:
            self.__load_children()
        return self._children

    @property
    def children_loaded(self):
        """
        Get whether or not the children of self.root_element have been loaded yet.
        :return: whether or not the children of self.root_element have been loaded yet.
        """
        return self._children_loaded

    @property
    def child_map(self):
        """
        Get a dictionary that maps tag names to lists of elements of that type found as
        children of self.root_element.
        :return: a dictionary that maps tag names to lists of elements of that type found
        as children of self.root_element.
        """
        if not self.children_loaded:
            self.__load_children()
        return self._child_map

    @property
    def child_names(self):
        """
        Get a list of strings representing the child tag types that can be loaded by
        this element.
        :return: a list of strings representing the child tag types that can be loaded by
        this element.
        """
        return self.child_map.keys()

    @property
    def refresh_meta_tag(self):
        """
        Get the refresh meta tag found within this document if such a tag exists, otherwise None.
        :return: the refresh meta tag found within this document if such a tag exists, otherwise None.
        """
        to_return = filter(lambda x: x.is_refresh_type, self.get_children_by_name("meta"))
        if len(to_return) == 0:
            return None
        elif len(to_return) > 1:
            logger.warning(
                "Too many refresh meta tags found (%s)."
                % (len(to_return),)
            )
        return to_return[0]

    @property
    def tag_count(self):
        """
        Get the total number of tags found in this HTML document.
        :return: the total number of tags found in this HTML document.
        """
        if self._tag_count is None:
            self._tag_count = self._count_children()
        return self._tag_count

    @property
    def tag_count_map(self):
        """
        Get a dictionary that maps tag names to the number of instances of that tag found in all children
        that are descendants of this element.
        :return: a dictionary that maps tag names to the number of instances of that tag found in all
        children that are descendants of this element.
        """
        if self._tag_count_map is None:
            self._tag_count_map = {k: len(v) for k, v in self.tag_map.iteritems()}
        return self._tag_count_map

    @property
    def tag_map(self):
        """
        Get a dictionary that maps tag names to all instances of this tag found in descendant children of
        this element.
        :return: a dictionary that maps tag names to all instances of this tag found in descendant children
        of this element.
        """
        if self._tag_map is None:
            self._tag_map = self._get_child_tag_name_map()
        return self._tag_map

    @property
    def tag_to_wrapper_map(self):
        """
        Get a map of HTML tag names to the wrapper classes that can wrap them.
        :return: a map of HTML tag names to the wrapper classes that can wrap them.
        """
        if self._tag_to_wrapper_map is None:
            self._tag_to_wrapper_map = get_html_tag_wrapper_map()
        return self._tag_to_wrapper_map

    @property
    def title(self):
        """
        Get the title of the wrapped HTML document.
        :return: the title of the wrapped HTML document.
        """
        if self._title is None:
            title_tags = self.get_children_by_name("title")
            if len(title_tags) > 0:
                self._title = title_tags[0].title
        return self._title

    @property
    def unknown_wrapper_class(self):
        """
        Get the HTML element wrapper class that should be used to wrap unrecognized elements.
        :return: the HTML element wrapper class that should be used to wrap unrecognized elements.
        """
        return UnknownHtmlElementWrapper

    @property
    def wrapped_type(self):
        return "HTML document"

    # Representation and Comparison


class BaseHtmlElementWrapper(HtmlWrapper):
    """
    This class is a base wrapper class for wrapping a single HTML element. This switches
    back to lxml's XML wrapper, as the HTML wrapper automatically changes wrapped strings to
    match various HTML specs.
    """

    # Class Members

    _classes = None
    _el_class = None
    _id = None
    _style = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        """
        Get a string representing the type of element that this HTML element wrapper is meant to wrap.
        :return: A string representing the type of element that this HTML element wrapper is meant to wrap.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    def _get_parser_method(self):
        return etree.XML

    # Private Methods

    # Properties

    @property
    def classes(self):
        """
        Get a list of strings representing the classes associated with this element.
        :return: a list of strings representing the classes associated with this element.
        """
        if self.has_class:
            self._classes = [x.strip() for x in self.el_class.strip().split(",")]
        else:
            self._classes = []
        return self._classes

    @property
    def el_class(self):
        """
        Get the class associated with this element.
        :return: the class associated with this element.
        """
        if self._el_class is None:
            self._el_class = self._get_element_attribute(key="class", required=False)
        return self._el_class

    @property
    def has_class(self):
        """
        Get whether or not this element has a class attribute.
        :return: whether or not this element has a class attribute.
        """
        return self.el_class is not None

    @property
    def has_id(self):
        """
        Get whether or not self.root_element has an id attribute.
        :return: whether or not self.root_element has an id attribute.
        """
        return self.id is not None

    @property
    def has_style(self):
        """
        Get whether or not self.root_element has a style attribute.
        :return: whether or not self.root_element has a style attribute.
        """
        return self.style is not None

    @property
    def id(self):
        """
        Get the id attribute from self.root_element.
        :return: the id attribute from self.root_element.
        """
        if self._id is None:
            self._id = self._get_element_attribute(key="id", required=False)
        return self._id

    @property
    def style(self):
        """
        Get the style attribute from self.root_element.
        :return: the style attribute from self.root_element.
        """
        return self._style

    @property
    def tag_name(self):
        return self.__class__.get_element_type()

    # Representation and Comparison


class HtmlDocumentWrapper(BaseHtmlElementWrapper):
    """
    A class for wrapping the contents of an HTML document.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "html"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "HTML Document"

    # Representation and Comparison


class UnknownHtmlElementWrapper(BaseHtmlElementWrapper):
    """
    Documentation for UnknownHtmlElementWrapper.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "unknown"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "Unknown HTML Element"

    # Representation and Comparison


class HtmlDivWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <div> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "div"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "HTML <div> Element"

    # Representation and Comparison


class HtmlAnchorWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <a> element.
    """

    # Class Members

    _href = None
    _name = None
    _target = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "a"

    # Public Methods

    # Protected Methods

    def _find_url_references(self):
        to_return = []
        if self.has_href and not self.is_javascript_href:
            to_return.append(("anchor href", self.href))
        return to_return

    # Private Methods

    # Properties

    @property
    def has_href(self):
        """
        Get whether or not this anchor element has an href attribute.
        :return: whether or not this anchor element has an href attribute.
        """
        return self.href is not None

    @property
    def has_name(self):
        """
        Get whether or not self.root_element has a name attribute.
        :return: whether or not self.root_element has a name attribute.
        """
        return self.name is not None

    @property
    def has_target(self):
        """
        Get whether or not self.root_element has a target attribute.
        :return: whether or not self.root_element has a target attribute.
        """
        return self.target is not None

    @property
    def href(self):
        """
        Get the href attribute found in self.root_element.
        :return: the href attribute found in self.root_element.
        """
        if self._href is None:
            self._href = self._get_element_attribute(key="href")
        return self._href

    @property
    def is_javascript_href(self):
        """
        Get whether or not the contents of the href attribute on this anchor
        tag represent JavaScript code.
        :return: whether or not the contents of the href attribute on this anchor
        tag represent JavaScript code.
        """
        if self.has_href:
            return self.href.strip().lower().startswith("javascript")
        else:
            return False

    @property
    def name(self):
        """
        Get the contents of the name attribute of self.root_element.
        :return: the contents of the name attribute of self.root_element.
        """
        if self._name is None:
            self._name = self._get_element_attribute(key="name")
        return self._name

    @property
    def target(self):
        """
        Get the anchor target associated with self.root_element.
        :return: the anchor target associated with self.root_element.
        """
        if self._target is None:
            self._target = self._get_element_attribute(key="target")
        return self._target

    @property
    def wrapped_type(self):
        return "HTML <anchor> Element"

    # Representation and Comparison


class HtmlParagraphWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <p> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "p"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "HTML <p> Element"

    # Representation and Comparison


class HtmlImageWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <img> element.
    """

    # Class Members

    _src = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "img"

    # Public Methods

    # Protected Methods

    def _find_url_references(self):
        if self.has_src:
            return [("img src", self.src)]
        else:
            return []

    # Private Methods

    # Properties

    @property
    def has_src(self):
        """
        Get whether or not this image element has a src attribute.
        :return: whether or not this image element has a src attribute.
        """
        return self.src is not None

    @property
    def src(self):
        """
        Get the src attribute associated with self.root_element.
        :return: the src attribute associated with self.root_element.
        """
        if self._src is None:
            self._src = self._get_element_attribute(key="src", required=False)
        return self._src

    @property
    def wrapped_type(self):
        return "HTML <img> Element"

    # Representation and Comparison


class HtmlScriptWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <script> element.
    """

    # Class Members

    _src = None
    _type = None
    _type_string = None
    _wrapped_content = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "script"

    # Public Methods

    # Protected Methods

    def _find_url_references(self):
        to_return = []
        if self.has_src:
            to_return.append(("script src", self.src))
        return to_return

    # Private Methods

    # Properties

    @property
    def is_javascript_type(self):
        """
        Get whether or not self.type is the JavaScript HTML element tag type.
        :return: whether or not self.type is the JavaScript HTML element tag type.
        """
        return self.type == "javascript"

    @property
    def has_src(self):
        """
        Get whether or not self.root_element has an src attribute.
        :return: whether or not self.root_element has an src attribute.
        """
        return self.src is not None

    @property
    def src(self):
        """
        Get the src attribute from self.root_element.
        :return: the src attribute from self.root_element.
        """
        if self._src is None:
            self._src = self._get_element_attribute(key="src", required=False)
        return self._src

    @property
    def type(self):
        """
        Get a constant representing the type of script found within this element.
        :return: a constant representing the type of script found within this element.
        """
        if self._type is None:
            if self.type_string is not None:
                self._type = ConversionHelper.string_to_html_script_tag_type(self.type_string)
            else:
                self._type = "unknown"
        return self._type

    @property
    def type_string(self):
        """
        Get a string representing the script type as found in the attributes of self.root_element.
        :return: A string representing the script type as found in the attributes of self.root_element.
        """
        if self._type_string is None:
            self._type_string = self._get_element_attribute(key="type", required=False)
        return self._type_string

    @property
    def wrapped_content(self):
        """
        Get the contents of self.text wrapped by a wrapper class that can parse it.
        :return: the contents of self.text wrapped by a wrapper class that can parse it.
        """
        if not self.has_content:
            logger.warning(
                "Attempted to get a wrapped version of tag content, but tag did not have content. Tag was %s."
                % (self,)
            )
            return None
        if self._wrapped_content is None:
            if self.is_javascript_type:
                self._wrapped_content = JavaScriptElementWrapper(self.text)
            else:
                logger.warning(
                    "No wrapper class found for script type of %s. Wrapped element was %s."
                    % (self.type, self)
                )
        return self._wrapped_content

    @property
    def wrapped_type(self):
        return "HTML <script> Element"

    # Representation and Comparison


class HtmlStyleWrapper(BaseHtmlElementWrapper):
    """
    Documentation for HtmlStyleWrapper.
    """

    # Class Members

    _type_string = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "style"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def has_type_string(self):
        """
        Get whether or not this element has a type attribute.
        :return: whether or not this element has a type attribute.
        """
        return self.type_string is not None

    @property
    def type_string(self):
        """
        Get a string representing the type of stylization that this tag contains.
        :return: a string representing the type of stylization that this tag contains.
        """
        if self._type_string is None:
            self._type_string = self._get_element_attribute(key="type", required=False)
        return self._type_string

    @property
    def wrapped_type(self):
        return "HTML <style> Element"

    # Representation and Comparison


class HtmlLinkWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <link> element.
    """

    # Class Members

    _href = None
    _link_type = None
    _media = None
    _rel = None
    _sizes = None
    _title = None
    _type = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "link"

    # Public Methods

    # Protected Methods

    def _find_url_references(self):
        return [("link href", self.href)]

    # Private Methods

    # Properties

    @property
    def has_media(self):
        """
        Get whether or not self.root_element has a media attribute.
        :return: whether or not self.root_element has a media attribute.
        """
        return self.media is not None

    @property
    def has_sizes(self):
        """
        Get whether or not self.root_element has a sizes attribute.
        :return: whether or not self.root_element has a sizes attribute.
        """
        return self.sizes is not None

    @property
    def has_title(self):
        """
        Get whether or not self.root_element has a title attribute.
        :return: whether or not self.root_element has a title attribute.
        """
        return self.title is not None

    @property
    def has_type(self):
        """
        Get whether or not self.root_element has a type attribute.
        :return: whether or not self.root_element has a type attribute.
        """
        return self.type is not None

    @property
    def href(self):
        """
        Get the href attribute value from self.root_element.
        :return: the href attribute value from self.root_element.
        """
        if self._href is None:
            self._href = self._get_element_attribute(key="href", required=False)
        return self._href

    @property
    def link_type(self):
        """
        Get a constant representing the type of link tag self.root_element represents.
        :return: a constant representing the type of link tag self.root_element represents.
        """
        if self._link_type is None:
            self._link_type = ConversionHelper.string_to_html_link_tag_type(self.rel)
        return self._link_type

    @property
    def media(self):
        """
        Get the media attribute value from self.root_element.
        :return: the media attribute value from self.root_element.
        """
        if self._media is None:
            self._media = self._get_element_attribute(key="media", required=False)
        return self._media

    @property
    def rel(self):
        """
        Get the rel attribute value from self.root_element.
        :return: the rel attribute value from self.root_element.
        """
        if self._rel is None:
            self._rel = self._get_element_attribute(key="rel", required=False)
        return self._rel

    @property
    def sizes(self):
        """
        Get the sizes attribute value from self.root_element.
        :return: the sizes attribute value from self.root_element.
        """
        if self._sizes is None:
            self._sizes = self._get_element_attribute(key="sizes", required=False)
        return self._sizes

    @property
    def title(self):
        """
        Get the contents of the title attribute associated with self.root_element.
        :return: the contents of the title attribute associated with self.root_element.
        """
        if self._title is None:
            self._title = self._get_element_attribute(key="title", required=False)
        return self._title

    @property
    def type(self):
        """
        Get the type attribute from self.root_element.
        :return: the type attribute from self.root_element.
        """
        if self._type is None:
            self._type = self._get_element_attribute(key="type", required=False)
        return self._type

    @property
    def wrapped_type(self):
        return "HTML <link> Element (%s)" % (self.rel,)

    # Representation and Comparison


class HtmlMetaWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <meta> element.
    """

    # Class Members

    _content = None
    _http_equiv = None
    _meta_type = None
    _name = None
    _refresh_duration = None
    _refresh_url = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "meta"

    # Public Methods

    # Protected Methods

    def _find_url_references(self):
        to_return = []
        if self.is_refresh_type and self.has_refresh_url:
            to_return.append(("meta refresh", self.refresh_url))
        return to_return

    # Private Methods

    def __check_meta_type(self, check_against):
        """
        Check to see whether this meta tag is of the type represented by check_against.
        :param check_against: The meta tag type constant to check against.
        :return: True if this meta tag is of the queried type, False otherwise.
        """
        return self.meta_type == check_against if self.name is not None else False

    # Properties

    @property
    def content(self):
        """
        Get the contents of the content attribute associated with this meta tag.
        :return: the contents of the content attribute associated with this meta tag.
        """
        if self._content is None:
            self._content = self._get_element_attribute(key="content", required=False)
        return self._content

    @property
    def has_http_equiv(self):
        """
        Get whether or not self.root_element has an http-equiv attribute.
        :return: whether or not self.root_element has an http-equiv attribute.
        """
        return self.http_equiv is not None

    @property
    def has_name(self):
        """
        Get whether or not this element has a name attribute.
        :return: whether or not this element has a name attribute.
        """
        return self.name is not None

    @property
    def has_refresh_url(self):
        """
        Get whether or not this meta refresh tag has a URL specified.
        :return: whether or not this meta refresh tag has a URL specified.
        """
        return self.refresh_url != ""

    @property
    def http_equiv(self):
        """
        Get the contents of the http_equiv attribute found in self.root_element.
        :return: the contents of the http_equiv attribute found in self.root_element.
        """
        if self._http_equiv is None:
            self._http_equiv = self._get_element_attribute(key="http-equiv", required=False)
        return self._http_equiv

    @property
    def is_description_type(self):
        """
        Get whether or not this meta tag represents the description meta tag.
        :return: whether or not this meta tag represents the description meta tag.
        """
        return self.__check_meta_type("description")

    @property
    def is_keywords_type(self):
        """
        Get whether or not this meta tag represents the keywords meta tag.
        :return: whether or not this meta tag represents the keywords meta tag.
        """
        return self.__check_meta_type("keywords")

    @property
    def is_referrer_type(self):
        """
        Get whether or not this meta tag represents the referrer meta tag.
        :return: whether or not this meta tag represents the referrer meta tag.
        """
        return self.__check_meta_type("referrer")

    @property
    def is_refresh_type(self):
        """
        Get whether or not this meta tag represents a refresh meta tag.
        :return: whether or not this meta tag represents a refresh meta tag.
        """
        return self.has_http_equiv and self.http_equiv.strip().lower() == "refresh"

    @property
    def is_viewport_type(self):
        """
        Get whether or not this meta tag represents the viewport meta tag.
        :return: whether or not this meta tag represents the viewport meta tag.
        """
        return self._is_viewport_type

    @property
    def meta_type(self):
        """
        Get a constant representing the type of meta tag that this wrapper wraps.
        :return: a constant representing the type of meta tag that this wrapper wraps.
        """
        if self._meta_type is None:
            if self.has_name:
                self._meta_type = ConversionHelper.string_to_html_meta_tag_type(self.name)
            elif self.has_http_equiv:
                self._meta_type = "http-equiv"
            else:
                self._meta_type = "unknown"
        return self._meta_type

    @property
    def name(self):
        """
        Get the name attribute associated with self.root_element.
        :return: the name attribute associated with self.root_element.
        """
        if self._name is None:
            self._name = self._get_element_attribute(key="name", required=False)
        return self._name

    @property
    def refresh_duration(self):
        """
        Get the amount of time in seconds that this meta refresh tag is configured
        to refresh the page after.
        :return: the amount of time in seconds that this meta refresh tag is configured
        to refresh the page after.
        """
        if self._refresh_duration is None:
            if ";" in self.content:
                self._refresh_duration = int(self.content[:self.content.find(";")].strip())
            else:
                self._refresh_duration = int(self.content.strip())
        return self._refresh_duration

    @property
    def refresh_url(self):
        """
        Get the URL that this meta refresh tag is configured to refresh to.
        :return: the URL that this meta refresh tag is configured to refresh to.
        """
        if self._refresh_url is None:
            if ";" in self.content:
                url_string = self.content[self.content.find(";") + 1:].strip()
                if url_string.lower().startswith("url="):
                    url_string = url_string[4:]
                if url_string.startswith("'") or url_string.startswith("\""):
                    url_string = url_string[1:]
                if url_string.endswith("'") or url_string.endswith("\""):
                    url_string = url_string[:-1]
                self._refresh_url = url_string
            else:
                self._refresh_url = ""
        return self._refresh_url

    @property
    def wrapped_type(self):
        return "HTML <meta> Element (%s)" % (self.name,)

    # Representation and Comparison


class HtmlTitleWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <title> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "title"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def title(self):
        """
        Get the text contents of this title tag.
        :return: the text contents of this title tag.
        """
        return self.text

    @property
    def wrapped_type(self):
        return "HTML <title> Element"

    # Representation and Comparison


class HtmlBodyWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <body> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "body"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "HTML <body> Element"

    # Representation and Comparison


class HtmlHeadWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <head> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "head"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <head> Element"


class HtmlListItemWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <li> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "li"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <li> Element"


class HtmlSpanWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <span> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "span"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <span> Element"


class HtmlUnorderedListWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <ul> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "ul"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <ul> Element"


class HtmlOrderedListWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <ol> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "ol"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <ol> Element"


class HtmlTimeWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <time> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "time"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <time> Element"


class HtmlInputWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <input> element.
    """

    # Class Members

    _input_type = None
    _name = None
    _value = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "input"

    # Public Methods

    def get_es_input_representation(self):
        """
        Get a dictionary that represents the contents of this input element in a manner that can
        be ingested by Elasticsearch.
        :return: A dictionary that represents the contents of this input element in a manner that can
        be ingested by Elasticsearch.
        """
        return {
            "has_type": self.has_input_type,
            "type": self.input_type,
            "has_name": self.has_name,
            "name": self.name,
            "has_value": self.has_value,
            "value": self.value,
        }

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def has_input_type(self):
        """
        Get whether or not this input tag has a type attribute.
        :return: whether or not this input tag has a type attribute.
        """
        return self.input_type is not None

    @property
    def has_name(self):
        """
        Get whether or not this input tag has a name attribute.
        :return: whether or not this input tag has a name attribute.
        """
        return self.name is not None

    @property
    def has_value(self):
        """
        Get whether or not this input tag has a value attribute.
        :return: whether or not this input tag has a value attribute.
        """
        return self.value is not None

    @property
    def input_type(self):
        """
        Get the contents of the type attribute associated with this input tag.
        :return: The contents of the type attribute associated with this input tag.
        """
        if self._input_type is None:
            self._input_type = self._get_element_attribute(key="type", required=False)
        return self._input_type

    @property
    def name(self):
        """
        Get the contents of the name attribute associated with this input tag.
        :return: The contents of the name attribute associated with this input tag.
        """
        if self._name is None:
            self._name = self._get_element_attribute(key="name", required=False)
        return self._name

    @property
    def value(self):
        """
        Get the contents of the value attribute associated with this input tag.
        :return: The contents of the value attribute associated with this input tag.
        """
        if self._value is None:
            self._value = self._get_element_attribute(key="value", required=False)
        return self._value

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <input> Element"


class HtmlButtonWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <button> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "button"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <button> Element"


class HtmlStrongWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <strong> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "strong"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <strong> Element"


class HtmlFormWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <form> element.
    """

    # Class Members

    _action = None
    _method = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "form"

    # Public Methods

    def get_es_form_representation(self):
        """
        Get a dictionary that represents the content of this form in a way that can be persisted to
        Elasticsearch.
        :return: A dictionary that represents the content of this form in a way that can be persisted to
        Elasticsearch.
        """
        return {
            "has_action": self.has_action,
            "action": self.action,
            "has_method": self.has_method,
            "method": self.method,
            "inputs": [x.get_es_input_representation() for x in self.get_children_by_name("input")],
        }

    # Protected Methods

    def _find_url_references(self):
        to_return = []
        if self.has_action:
            to_return.append(("form action", self.action))
        return to_return

    # Private Methods

    # Properties

    @property
    def action(self):
        """
        Get the contents of the action attribute associated with this form tag.
        :return: The contents of the action attribute associated with this form tag.
        """
        if self._action is None:
            self._action = self._get_element_attribute(key="action", required=False)
        return self._action

    @property
    def has_action(self):
        """
        Get whether or not the wrapped form has an action attribute.
        :return: Whether or not the wrapped form has an action attribute.
        """
        return self.action is not None

    @property
    def has_method(self):
        """
        Get whether or not the wrapped form has a method attribute.
        :return: Whether or not the wrapped form has a method attribute.
        """
        return self.method is not None

    @property
    def method(self):
        """
        Get the contents of the method attribute associated with this form tag.
        :return: the contents of the method attribute associated with this form tag.
        """
        if self._method is None:
            self._method = self._get_element_attribute(key="method", required=False)
        return self._method

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <form> Element"


class HtmlCodeWrapper(BaseHtmlElementWrapper):
    """
    A wrapper for the HTML <code> element.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_element_type(cls):
        return "code"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    @property
    def wrapped_type(self):
        return "HTML <code> Element"
