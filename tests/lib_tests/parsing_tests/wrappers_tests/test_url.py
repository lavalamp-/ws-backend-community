# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ....base import BaseWebSightTestCase
from lib.parsing.wrappers.url import QueryStringWrapper, UrlPathWrapper, UrlWrapper


class UrlWrapperTestCase(BaseWebSightTestCase):
    """
    This is a test case for testing the functionality contained within the UrlWrapper class.
    """

    def test_authority_no_login_name(self):
        """
        Tests that the authority value is populated correctly when given a URL with no login name.
        :return: None
        """
        wrapper = UrlWrapper("http://:password@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, ":password@www.foobar.com")

    def test_authority_no_login_pass(self):
        """
        Tests that the authority value is populated correctly when given a URL with no login password.
        :return: None
        """
        wrapper = UrlWrapper("http://username:@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, "username:@www.foobar.com")

    def test_authority_no_login_name_or_pass(self):
        """
        Tests that the authority value is populated correctly when given a URL with an empty login name
        and password.
        :return: None
        """
        wrapper = UrlWrapper("http://:@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, ":@www.foobar.com")

    def test_authority_no_login_data(self):
        """
        Tests that the authority value is populated correctly when given a URL with no login information.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_specified_port(self):
        """
        Tests that the authority value is populated correctly when given a URL with a specific port.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:123/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com:123")

    def test_authority_http_scheme(self):
        """
        Tests that authority is populated correctly when scheme is HTTP.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_https_scheme(self):
        """
        Tests that authority is populated correctly when scheme is HTTPS.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_no_path(self):
        """
        Tests that authority is populated correctly when no URL path is given.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com?foo=bar#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_path(self):
        """
        Tests that authority is populated correctly when a URL path is given.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_no_query(self):
        """
        Tests that authority is populated correctly when no query string is given.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123/asd.html#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_query(self):
        """
        Tests that authority is populated correctly when a query string is given.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com?foo=bar")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_no_fragment(self):
        """
        Tests that authority is populated correctly when no URL fragment is given.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html?foo=bar")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_authority_fragment(self):
        """
        Tests that authority is populated correctly when a URL fragment is given.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com#bazbang")
        self.assertEqual(wrapper.authority, "www.foobar.com")

    def test_destination_no_login_data(self):
        """
        Tests that destination is populated correctly when given no login information.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.destination, "www.foobar.com")

    def test_destination_login_data(self):
        """
        Tests that destination is populated correctly when given login data.
        :return: None
        """
        wrapper = UrlWrapper("http://username:password@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.destination, "www.foobar.com")

    def test_destination_port(self):
        """
        Tests that destination is populated correctly when given a port number.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.destination, "www.foobar.com")

    def test_destination_no_path(self):
        """
        Tests that destination is populated correctly when given no URL path.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com?foo=bar#bazbang")
        self.assertEqual(wrapper.destination, "www.foobar.com")

    def test_destination_no_query(self):
        """
        Tests that destination is populated correctly when not given a query string.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html#bazbang")
        self.assertEqual(wrapper.destination, "www.foobar.com")

    def test_destination_no_fragment(self):
        """
        Tests that destination is populated correctly when not given a URL fragment.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar")
        self.assertEqual(wrapper.destination, "www.foobar.com")

    def test_password_no_login(self):
        """
        Tests that password is populated correctly when not given login data.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertFalse(wrapper.password)

    def test_password_empty(self):
        """
        Tests that password is populated correctly when given login data with an empty password.
        :return: None
        """
        wrapper = UrlWrapper("http://username:@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.password, "")

    def test_password_login_data(self):
        """
        Tests that password is populated correctly when given login data.
        :return: None
        """
        wrapper = UrlWrapper("http://username:password@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.password, "password")

    def test_path_login_data(self):
        """
        Tests that path is populated correctly when given login data.
        :return: None
        """
        wrapper = UrlWrapper("http://username:password@www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.path, "/asd/123.html")

    def test_path_http_scheme(self):
        """
        Tests that path is populated correctly when given an HTTP scheme.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.path, "/asd/123.html")

    def test_path_https_scheme(self):
        """
        Tests that path is populated correctly when given an HTTPS scheme.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.path, "/asd/123.html")

    def test_path_no_port(self):
        """
        Tests that path is populated correctly when not given a port.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.path, "/asd/123.html")

    def test_path_no_query(self):
        """
        Tests that path is populated correctly when not given a query string.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html#bazbang")
        self.assertEqual(wrapper.path, "/asd/123.html")

    def test_path_no_fragment(self):
        """
        Tests that path is populated correctly when not given a URL fragment.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html?foo=bar")
        self.assertEqual(wrapper.path, "/asd/123.html")

    def test_full_path_string_login_data(self):
        """
        Tests that full_path_string is populated correctly when given login data.
        :return: None
        """
        wrapper = UrlWrapper("http://username:password@www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.full_path_string, "/asd/123.html?foo=bar#bazbang")

    def test_full_path_string_http_scheme(self):
        """
        Tests that full_path_string is populated correctly when given an HTTP scheme.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.full_path_string, "/asd/123.html?foo=bar#bazbang")

    def test_full_path_string_https_scheme(self):
        """
        Tests that full_path_string is populated correctly when given an HTTPS scheme.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.full_path_string, "/asd/123.html?foo=bar#bazbang")

    def test_full_path_string_no_port(self):
        """
        Tests that full_path_string is populated correctly when not given a port.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.full_path_string, "/asd/123.html?foo=bar#bazbang")

    def test_full_path_string_no_query(self):
        """
        Tests that full_path_string is populated correctly when not given a query string.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html#bazbang")
        self.assertEqual(wrapper.full_path_string, "/asd/123.html#bazbang")

    def test_full_path_string_no_fragment(self):
        """
        Tests that full_path_string is populated correctly when not given a URL fragment.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html?foo=bar")
        self.assertEqual(wrapper.full_path_string, "/asd/123.html?foo=bar")

    def test_port_no_login_data(self):
        """
        Tests that port is populated correctly when given no login data.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.port, 1234)

    def test_port_login_data(self):
        """
        Tests that port is populated correctly when given login data.
        :return: None
        """
        wrapper = UrlWrapper("http://username:password@www.foobar.com:1234/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.port, 1234)

    def test_port_http_scheme(self):
        """
        Tests that port is populated correctly when given an HTTP scheme.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.port, 80)

    def test_port_https_scheme(self):
        """
        Tests that port is populated correctly when given an HTTPS scheme.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.port, 443)

    def test_port_no_query(self):
        """
        Tests that port is populated correctly when not given a query string.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html#bazbang")
        self.assertEqual(wrapper.port, 443)

    def test_port_no_fragment(self):
        """
        Tests that port is populated correctly when not given a URL fragment.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html?foo=bar")
        self.assertEqual(wrapper.port, 443)

    def test_username_no_login(self):
        """
        Tests that username is populated correctly when not given login data.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertFalse(wrapper.username)

    def test_username_empty(self):
        """
        Tests that username is populated correctly when given login data with an empty password.
        :return: None
        """
        wrapper = UrlWrapper("https://:password@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.username, "")

    def test_username_login_data(self):
        """
        Tests that username is populated correctly when given login data.
        :return: None
        """
        wrapper = UrlWrapper("https://username:password@www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.username, "username")

    def test_scheme_http(self):
        """
        Tests that scheme is populated correctly when given an HTTP URL.
        :return: None
        """
        wrapper = UrlWrapper("http://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.scheme, "http")

    def test_scheme_https(self):
        """
        Tests that scheme is populated correctly when given an HTTPS URL.
        :return:
        """
        wrapper = UrlWrapper("https://www.foobar.com/asd/123.html?foo=bar#bazbang")
        self.assertEqual(wrapper.scheme, "https")

    def test_has_same_origin_success(self):
        """
        Tests that has_same_origin returns the expected value when given two same-origin URLs.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "https://www.foobar.com:1234/asd.html?foo=bar#asd123"
        self.assertTrue(wrapper.has_same_origin(url_string=url))

    def test_has_same_origin_fails_wrong_protocol(self):
        """
        Tests that has_same_origin returns the expected value when given two non-same-origin URLs that
        differ by protocol.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "http://www.foobar.com:1234/asd.html?foo=bar#asd123"
        self.assertFalse(wrapper.has_same_origin(url_string=url))

    def test_has_same_origin_fails_wrong_host(self):
        """
        Tests that has_same_origin returns the expected value when given two non-same-origin URLs that
        differ by host.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "https://asd123.foobar.com:1234/asd.html?foo=bar#asd123"
        self.assertFalse(wrapper.has_same_origin(url_string=url))

    def test_has_same_origin_fails_wrong_port(self):
        """
        Tests that has_same_origin returns the expected value when given two non-same-origin URLs that
        differ by port.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "http://www.foobar.com:12345/asd.html?foo=bar#asd123"
        self.assertFalse(wrapper.has_same_origin(url_string=url))

    def test_has_same_origin_no_protocol_success(self):
        """
        Tests that has_same_origin returns the expected value when given two same-origin URLs and protocol
        is ignored.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "http://www.foobar.com:1234/asd.html?foo=bar#asd123"
        self.assertTrue(wrapper.has_same_origin(url_string=url, include_protocol=False))

    def test_has_same_origin_no_protocol_fails(self):
        """
        Tests that has_same_origin returns the expected value when given two non-same-origin URLs and protocol
        is ignored.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "http://www.foobar.com:12345/asd.html?foo=bar#asd123"
        self.assertFalse(wrapper.has_same_origin(url_string=url, include_protocol=False))

    def test_has_same_origin_no_host_success(self):
        """
        Tests that has_same_origin returns the expected value when given two same-origin URLs and host
        is ignored.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "https://asd123.foobar.com:1234/asd.html?foo=bar#asd123"
        self.assertTrue(wrapper.has_same_origin(url_string=url, include_host=False))

    def test_has_same_origin_no_host_fails(self):
        """
        Tests that has_same_origin returns the expected value when given two non-same-origin URLs and host
        is ignored.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "https://asd123.foobar.com:12345/asd.html?foo=bar#asd123"
        self.assertFalse(wrapper.has_same_origin(url_string=url, include_host=False))

    def test_has_same_origin_no_port_success(self):
        """
        Tests that has_same_origin returns the expected value when given two same-origin URLs and port
        is ignored.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "https://www.foobar.com:12345/asd.html?foo=bar#asd123"
        self.assertTrue(wrapper.has_same_origin(url_string=url, include_port=False))

    def test_has_same_origin_no_port_fails(self):
        """
        Tests that has_same_origin returns the expected value when given two non-same-origin URLs and port
        is ignored.
        :return: None
        """
        wrapper = UrlWrapper("https://www.foobar.com:1234/asd.html?foo=bar#asd123")
        url = "https://asd123.foobar.com:12345/asd.html?foo=bar#asd123"
        self.assertFalse(wrapper.has_same_origin(url_string=url, include_port=False))


class UrlPathWrapperTestCase(BaseWebSightTestCase):
    """
    This is a test case class for testing the UrlPathWrapper class.
    """

    def test_empty_string_succeeds(self):
        """
        Tests that initializing the wrapper class with an empty string does not throw an error.
        :return: None
        """
        UrlPathWrapper("")

    def test_none_succeeds(self):
        """
        Tests that initializing the wrapper class with None does not throw an error.
        :return: None
        """
        UrlPathWrapper(None)

    def test_init_assigns_wrapped_data(self):
        """
        Tests that initializing the wrapper class correctly assigns wrapped_data.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz")
        self.assertEqual(wrapper.wrapped_data, "/foo/bar/baz")

    def test_no_fragment_has_fragment(self):
        """
        Tests that has_fragment returns False when no fragment is supplied.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz")
        self.assertFalse(wrapper.has_fragment)

    def test_fragment_has_fragment(self):
        """
        Tests that has_fragment returns True when a fragment is supplied.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz#asd123")
        self.assertTrue(wrapper.has_fragment)

    def test_no_fragment_fragment(self):
        """
        Tests that fragment returns None when no fragment is supplied.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz")
        self.assertEqual(wrapper.fragment, None)

    def test_fragment_fragment(self):
        """
        Tests that fragment returns the expected value when a fragment is supplied.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz#asd123")
        self.assertEqual(wrapper.fragment, "asd123")

    def test_file_path_is_directory_path(self):
        """
        Tests that is_directory_path returns False when the path points to a file.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        self.assertFalse(wrapper.is_directory_path)

    def test_dir_path_is_directory_path(self):
        """
        Tests that is_directory_path returns True when the path points to a directory.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        self.assertTrue(wrapper.is_directory_path)

    def test_file_path_is_file_path(self):
        """
        Tests that is_file_path returns True when the path points to a file.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        self.assertTrue(wrapper.is_file_path)

    def test_dir_path_is_file_path(self):
        """
        Tests that is_file_path returns False when thepath points to a directory.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        self.assertFalse(wrapper.is_file_path)

    def test_path_empty_no_query_string_no_fragment(self):
        """
        Tests that path returns the expected value when the path is empty and no query string
        or fragment are provided.
        :return: None
        """
        wrapper = UrlPathWrapper("")
        self.assertEqual(wrapper.path, "/")

    def test_path_file_path_no_query_string_no_fragment(self):
        """
        Tests that path returns the expected value when the path points to a file and no
        query string or fragment are provided.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        self.assertEqual(wrapper.path, "/foo/bar/baz.html")

    def test_path_dir_path_no_query_string_no_fragment(self):
        """
        Tests that path returns the expected value when the path points to a directory and no
        query string or fragment are provided.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        self.assertEqual(wrapper.path, "/foo/bar/baz/")
    
    def test_path_empty_query_string_no_fragment(self):
        """
        Tests that path returns the expected value when the path is empty and a query string 
        is provided and a fragment is not.
        :return: None
        """
        wrapper = UrlPathWrapper("?foo=bar&baz=bang")
        self.assertEqual(wrapper.path, "/")

    def test_path_file_path_query_string_no_fragment(self):
        """
        Tests that path returns the expected value when the path points to a file and a query 
        string is provided and a fragment is not.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?foo=bar&baz=bang")
        self.assertEqual(wrapper.path, "/foo/bar/baz.html")

    def test_path_dir_path_query_string_no_fragment(self):
        """
        Tests that path returns the expected value when the path points to a directory and a 
        query string is provided and a fragment is not.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/?foo=bar&baz=bang")
        self.assertEqual(wrapper.path, "/foo/bar/baz/")

    def test_path_empty_query_string_fragment(self):
        """
        Tests that path returns the expected value when the path is empty and a query string 
        is provided and a fragment is as well.
        :return: None
        """
        wrapper = UrlPathWrapper("?foo=bar&baz=bang#asd123")
        self.assertEqual(wrapper.path, "/")

    def test_path_file_path_query_string_fragment(self):
        """
        Tests that path returns the expected value when the path points to a file and a query 
        string is provided and a fragment is as well.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?foo=bar&baz=bang#asd123")
        self.assertEqual(wrapper.path, "/foo/bar/baz.html")

    def test_path_dir_path_query_string_fragment(self):
        """
        Tests that path returns the expected value when the path points to a directory and a 
        query string is provided and a fragment is as well.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/?foo=bar&baz=bang#asd123")
        self.assertEqual(wrapper.path, "/foo/bar/baz/")

    def test_query_string_empty_path_no_fragment(self):
        """
        Tests that query_string returns the expected value when no path is provided and no fragment
        is provided.
        :return: None
        """
        wrapper = UrlPathWrapper("?asd=123")
        self.assertEqual(wrapper.query_string, "asd=123")
    
    def test_query_string_file_path_no_fragment(self):
        """
        Tests that query_string returns the expected value when a file path is provided and no 
        fragment is provided.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123")
        self.assertEqual(wrapper.query_string, "asd=123")
    
    def test_query_string_dir_path_no_fragment(self):
        """
        Tests that query_string returns the expected value when a directory path is provided and no
        fragment is provided.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/?asd=123")
        self.assertEqual(wrapper.query_string, "asd=123")

    def test_query_string_empty_path_fragment(self):
        """
        Tests that query_string returns the expected value when no path is provided and a fragment
        is provided as well.
        :return: None
        """
        wrapper = UrlPathWrapper("?asd=123#asd123")
        self.assertEqual(wrapper.query_string, "asd=123")

    def test_query_string_file_path_fragment(self):
        """
        Tests that query_string returns the expected value when a file path is provided and a fragment
        is provided as well.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123#asd123")
        self.assertEqual(wrapper.query_string, "asd=123")

    def test_query_string_dir_path_fragment(self):
        """
        Tests that query_string returns the expected value when a directory path is provided and a
        fragment is provided as well.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/?asd=123#asd123")
        self.assertEqual(wrapper.query_string, "asd=123")

    def test_query_string_wrapper(self):
        """
        Tests that the value returned by query_string_wrapper is of the expected class.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123#asd123")
        self.assertTrue(isinstance(wrapper.query_string_wrapper, QueryStringWrapper))

    def test_resolved_path_empty_no_query_no_fragment(self):
        """
        Tests that resolved_path returns the expected value when an empty string is passed to init.
        :return: None
        """
        wrapper = UrlPathWrapper("")
        self.assertEqual(wrapper.resolved_path, "/")

    def test_resolved_path_none(self):
        """
        Tests that resolved_path returns the expected value when a None value is passed to init.
        :return: None
        """
        wrapper = UrlPathWrapper(None)
        self.assertEqual(wrapper.resolved_path, "/")

    def test_resolved_path_file_path_no_query_no_fragment(self):
        """
        Tests that resolved_path returns the expected value when a file path is provided without
        a query string or fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")

    def test_resolved_path_dir_path_no_query_no_fragment(self):
        """
        Tests that resolved_path returns the expected value when a directory path is provided
        without a query string or fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/")

    def test_resolved_path_file_path_query_no_fragment(self):
        """
        Tests that resolved_path returns the expected value when a file path is provided with
        a query string and no fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")

    def test_resolved_path_dir_path_query_no_fragment(self):
        """
        Tests that resolved_path returns the expected value when a directory path is provided with
        a query string and no fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/?asd=123")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/")

    def test_resolved_path_file_path_query_fragment(self):
        """
        Tests that resolved_path returns the expeted value when a file path is provided with a
        query string and a fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123#asd123")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")

    def test_resolved_path_dir_path_query_fragment(self):
        """
        Tests that resolved_path returns the expected value when a directory path is provided with
        a query string and a fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/?asd=123#asd123")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/")

    def test_to_string_no_query_string(self):
        """
        Tests that to_string returns a string that does not contain a query string when the wrapped
        path does not contain a query string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        self.assertNotIn("?", str(wrapper))

    def test_to_string_contains_query_string(self):
        """
        Tests that to_string returns a string that contains a query string when the wrapped path
        contains a query string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123")
        self.assertIn("?", str(wrapper))

    def test_to_string_no_fragment(self):
        """
        Tests that to_string returns a string that does not contain a fragment when the wrapped path does
        not contain a fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        self.assertNotIn("#", str(wrapper))

    def test_to_string_contains_fragment(self):
        """
        Tests that to_string returns a string that contains a fragment when the wrapped path contains a
        fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html#asd123asd123")
        self.assertIn("#asd123asd123", str(wrapper))

    def test_to_string_contains_query_and_fragment(self):
        """
        Tests that to_string returns a string that contains both a query string and a URL fragment when the
        wrapped path has both a query string and a fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123#asd123asd123")
        self.assertTrue(all([
            "?" in str(wrapper),
            "#asd123asd123" in str(wrapper),
        ]))

    def test_to_string_starts_with_path(self):
        """
        Tests that to_string returns a string that starts with path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123#asd123")
        self.assertTrue(str(wrapper).startswith("/foo/bar/baz.html"))

    def test_to_string_empty(self):
        """
        Tests that to_string returns the expected value when an empty string or None value are passed to
        init.
        :return: None
        """
        wrapper = UrlPathWrapper("")
        self.assertEqual(str(wrapper), "/")

    def test_resolved_path_single_dot_sequence(self):
        """
        Tests that resolved_path correctly handles a sequence of single dots.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/./././././././././bar/baz.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")

    def test_resolved_path_multi_single_dots(self):
        """
        Tests that resolved_path correctly handles single dots in multiple places.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/./bar/./baz.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")

    def test_resolved_path_empty_starts_with_double_dot(self):
        """
        Tests that resolved_path correctly handles a path that starts with double dot paths.
        :return: None
        """
        wrapper = UrlPathWrapper("/../../../../../../../../")
        self.assertEqual(wrapper.resolved_path, "/")

    def test_resolved_path_empty_ends_with_double_dot(self):
        """
        Tests that resolved_path correctly handles a path that ends with so many double dot paths
        that the resulting path is /.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/foo/bar/baz/foo/../../../../../../../../../../../../")
        self.assertEqual(wrapper.resolved_path, "/")

    def test_resolved_path_double_dot_file(self):
        """
        Tests that resolved_path correctly handles a file path that contains double dots.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/../../bang.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bang.html")

    def test_resolved_path_double_dot_directory(self):
        """
        Tests that resolved_path correctly handles a directory path that contains double dots.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/../../hoodyhoo/")
        self.assertEqual(wrapper.resolved_path, "/foo/hoodyhoo/")

    def test_resolved_path_interspersed_double_dot(self):
        """
        Tests that resolved_path correctly handles a path that contains double dot sequences interspersed
        in multiple places.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/../bang/../hoobly/../doobly.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/doobly.html")

    def test_file_resolve_against_empty(self):
        """
        Tests that resolve_against returns the correct value when passed an empty string and when the wrapper
        contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")
        
    def test_directory_resolve_against_empty(self):
        """
        Tests that resolve_against returns the correct value when passed an empty string and when the wrapper
        contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/")

    def test_file_resolve_against_none(self):
        """
        Tests that resolve_against returns the correct value when passed a None value and when the wrapper
        contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against(None)
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz.html")

    def test_directory_resolve_against_none(self):
        """
        Tests that resolve_against returns the correct value when passed a None value and when the wrapper
        contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against(None)
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/")

    def test_file_resolve_against_absolute_path(self):
        """
        Tests that resolve_against returns the correct value when passed an absolute path and when the wrapper
        contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("/bang/boom/boop.html")
        self.assertEqual(wrapper.resolved_path, "/bang/boom/boop.html")

    def test_directory_resolve_against_absolute_path(self):
        """
        Tests that resolve_against returns the correct value when passed an absolute path and when the wrapper
        contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("/bang/boom/boop.html")
        self.assertEqual(wrapper.resolved_path, "/bang/boom/boop.html")

    def test_file_resolve_against_relative_file_path(self):
        """
        Tests that resolve against returns the correct value when passed a relative file path and when the wrapper
        contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("and/one.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/and/one.html")

    def test_file_resolve_against_relative_dir_path(self):
        """
        Tests that resolve against returns the correct value when passed a relative directory path and 
        when the wrapper contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("and/one/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/and/one/")

    def test_dir_resolve_against_relative_file_path(self):
        """
        Tests that resolve against returns the correct value when passed a relative file path and when the wrapper
        contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("and/one.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/and/one.html")

    def test_dir_resolve_against_relative_dir_path(self):
        """
        Tests that resolve against returns the correct value when passed a relative directory path and 
        when the wrapper contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("and/one/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/and/one/")
        
    def test_file_resolve_against_single_dot_file_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative file path that contains
        a single dot and the wrapper contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("asd/./test.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/asd/test.html")

    def test_file_resolve_against_single_dot_directory_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative directory path that
        contains a single dot and the wrapper contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("asd/./test/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/asd/test/")
        
    def test_dir_resolve_against_single_dot_file_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative file path that contains
        a single dot and the wrapper contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("asd/./test.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/asd/test.html")

    def test_dir_resolve_against_single_dot_directory_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative directory path that
        contains a single dot and the wrapper contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("asd/./test/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/asd/test/")

    def test_file_resolve_against_double_dot_file_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative file path that contains
        double dots and the wrapper contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("asd/123/../test.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/asd/test.html")

    def test_file_resolve_against_double_dot_directory_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative directory path that
        contains double dots and the wrapper contains a file path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html")
        wrapper.resolve_against("asd/123/../test/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/asd/test/")

    def test_dir_resolve_against_double_dot_file_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative file path that contains
        double dots and the wrapper contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("asd/123/../test.html")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/asd/test.html")

    def test_dir_resolve_against_double_dot_directory_path(self):
        """
        Tests that resolve_against returns the correct value when passed relative directory path that
        contains double dots and the wrapper contains a directory path.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz/")
        wrapper.resolve_against("asd/123/../test/")
        self.assertEqual(wrapper.resolved_path, "/foo/bar/baz/asd/test/")

    def test_resolve_against_empty_keeps_query_string(self):
        """
        Tests that resolve_against keeps the original query string when called with an empty string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123")
        wrapper.resolve_against(None)
        self.assertEqual(wrapper.query_string, "asd=123")

    def test_resolve_against_empty_keeps_fragment(self):
        """
        Tests that resolve_against keeps the original fragment when called with an empty string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html#asd123")
        wrapper.resolve_against(None)
        self.assertEqual(wrapper.fragment, "asd123")

    def test_resolve_against_empty_keeps_query_and_fragment(self):
        """
        Tests that resolve_against keeps the original query string and fragment when called with
        an empty string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123#asd123")
        wrapper.resolve_against(None)
        self.assertTrue(all([
            wrapper.query_string == "asd=123",
            wrapper.fragment == "asd123",
        ]))

    def test_resolve_against_loses_query_string(self):
        """
        Tests that resolve_against results in the wrapper losing its query string when the resolution path
        does not contain a query string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123")
        wrapper.resolve_against("and/one/two/three.html")
        self.assertIsNone(wrapper.query_string)

    def test_resolve_against_assigns_query_string(self):
        """
        Tests that resolve_against results in the proper value being set for query_string when the resolution
        path contains a query string.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html?asd=123")
        wrapper.resolve_against("and/one/two/three.html?def=456")
        self.assertEqual(wrapper.query_string, "def=456")

    def test_resolve_against_loses_url_fragment(self):
        """
        Tests that resolve_against results in the wrapper losing its URL fragment when the resolution path
        does not contain a URL fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html#asd123")
        wrapper.resolve_against("and/one/two/three.html")
        self.assertIsNone(wrapper.fragment)

    def test_resolve_against_assigns_url_fragment(self):
        """
        Tests that resolve_against results in the proper value being set for fragment when the resolution path
        contains a URL fragment.
        :return: None
        """
        wrapper = UrlPathWrapper("/foo/bar/baz.html#asd123")
        wrapper.resolve_against("and/one/two/three.html#def456")
        self.assertEqual(wrapper.fragment, "def456")


class QueryStringWrapperTestCase(BaseWebSightTestCase):
    """
    This is a test case class for testing the QueryStringWrapper class.
    """

    def test_empty_string_init_succeeds(self):
        """
        Tests that initializing the wrapper with an empty string does not throw an exception.
        :return: None
        """
        QueryStringWrapper("")

    def test_none_init_succeeds(self):
        """
        Tests that initializing the wrapper with None does not throw an exception.
        :return: None
        """
        QueryStringWrapper(None)

    def test_wrapped_data_set(self):
        """
        Tests that the wrapped_data property of QueryStringWrapper classes is correctly populated
        upon initialization.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar")
        self.assertEqual(wrapper.wrapped_data, "foo=bar")

    def test_no_equals_tuple_value(self):
        """
        Tests that a query string segment that does not have an equals sign has the expected value
        populated in argument_tuples.
        :return: None
        """
        wrapper = QueryStringWrapper("fooooooo")
        self.assertIsNone(wrapper.argument_tuples[0][1])
    
    def test_equals_tuple_value(self):
        """
        Tests that a query string segment that has an equals sign has the expected value populated in
        argument_tuples.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar")
        self.assertEqual(wrapper.argument_tuples[0][1], "bar")
    
    def test_empty_string_tuples(self):
        """
        Tests that a query string wrapper that is given an empty string has an empty argument_tuples
        property.
        :return: None
        """
        wrapper = QueryStringWrapper("")
        self.assertEqual(len(wrapper.argument_tuples), 0)
    
    def test_none_string_tuples(self):
        """
        Tests that a query string wrapper that is given a None value has an empty argument_tuples property.
        :return: None
        """
        wrapper = QueryStringWrapper(None)
        self.assertEqual(len(wrapper.argument_tuples), 0)
    
    def test_no_ands_tuples_length(self):
        """
        Tests that a query string wrapper that is given a query string with no & has the expected tuples
        length.
        :return: None 
        """
        wrapper = QueryStringWrapper("foo=bar")
        self.assertEqual(len(wrapper.argument_tuples), 1)
    
    def test_one_and_tuples_length(self):
        """
        Tests that a query string wrapper that is given a query string with one & has the expected tuples
        length.
        :return: None 
        """
        wrapper = QueryStringWrapper("foo=bar&baz=bang")
        self.assertEqual(len(wrapper.argument_tuples), 2)
    
    def test_two_ands_tuples_length(self):
        """
        Tests that a query string wrapper that is given a query string with two &'s has the expected tuples
        length.
        :return: None 
        """
        wrapper = QueryStringWrapper("foo=bar&baz=bang&shooby=wooby")
        self.assertEqual(len(wrapper.argument_tuples), 3)

    def test_no_ands_dictionary_length(self):
        """
        Tests that a query string wrapper that is given a query string with no & has the expected dictionary
        length.
        :return: None 
        """
        wrapper = QueryStringWrapper("foo=bar")
        self.assertEqual(len(wrapper.dictionary), 1)

    def test_one_and_dictionary_length(self):
        """
        Tests that a query string wrapper that is given a query string with one & has the expected dictionary
        length.
        :return: None 
        """
        wrapper = QueryStringWrapper("foo=bar&baz=bang")
        self.assertEqual(len(wrapper.dictionary), 2)

    def test_two_ands_dictionary_length(self):
        """
        Tests that a query string wrapper that is given a query string with two &'s has the expected dictionary
        length.
        :return: None 
        """
        wrapper = QueryStringWrapper("foo=bar&baz=bang&shooby=wooby")
        self.assertEqual(len(wrapper.dictionary), 3)

    def test_none_is_empty(self):
        """
        Tests that is_empty returns True when None is passed to init.
        :return: None
        """
        wrapper = QueryStringWrapper(None)
        self.assertTrue(wrapper.is_empty)

    def test_empty_string_is_empty(self):
        """
        Tests that is_empty returns True when an empty string is passed to init.
        :return: None
        """
        wrapper = QueryStringWrapper("")
        self.assertTrue(wrapper.is_empty)

    def test_non_empty_string_is_empty(self):
        """
        Tests that is_empty returns False when a non-empty string is passed to init.
        :return: None
        """
        wrapper = QueryStringWrapper("woopdywoopppp")
        self.assertFalse(wrapper.is_empty)

    def test_add_argument_adds_key(self):
        """
        Tests that add_argument successfully adds the given key to the query string dictionary.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar")
        wrapper.add_argument(key="bang", value="bazinga")
        self.assertTrue("bang" in wrapper.dictionary)

    def test_add_argument_adds_value(self):
        """
        Tests that add_argument successfully adds the given value to the query string dictionary.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar")
        wrapper.add_argument(key="bang", value="bazinga")
        self.assertEqual(wrapper.dictionary["bang"], "bazinga")

    def test_to_string_one_and_count(self):
        """
        Tests that to_string returns a string containing the expected number of & characters when two
        arguments are in the dictionary.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar&baz=bang")
        query_string = str(wrapper)
        self.assertEqual(query_string.count("&"), 1)

    def test_to_string_no_and_count(self):
        """
        Tests that to_string returns a string containing the expected number of & characters when one argument
        is in the dictionary.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar")
        query_string = str(wrapper)
        self.assertEqual(query_string.count("&"), 0)

    def test_to_string_empty(self):
        """
        Tests that to_string returns the expected empty string when the dictionary is empty.
        :return: None
        """
        wrapper = QueryStringWrapper("")
        self.assertEqual(str(wrapper), "")

    def test_to_string_one_equals_count(self):
        """
        Tests that to_string returns the expected string when the dictionary has a single key-value.
        :return: None
        """
        wrapper = QueryStringWrapper("foo=bar")
        query_string = str(wrapper)
        self.assertEqual(query_string.count("="), 1)

    def test_to_string_no_equals_count(self):
        """
        Tests that to_string returns the expected string when the dictionary has a key-value pair where the
        value is None.
        :return: None
        """
        wrapper = QueryStringWrapper("foo&baz&bang")
        query_string = str(wrapper)
        self.assertEqual(query_string.count("="), 0)
