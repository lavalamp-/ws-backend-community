# -*- coding: utf-8 -*-
from __future__ import absolute_import

from json import JSONEncoder
from requests import PreparedRequest
from requests import Response
from requests.structures import CaseInsensitiveDict

from ..exception import BaseWsException
from .util import get_import_path_for_type, get_class_from_import_string


class UnsupportedDeserializationError(BaseWsException):
    """
    This is an exception for denoting that a given JSON dictionary does not contain the expected data
    required for deserialization.
    """

    _message = "Unsupported JSON deserialization dictionary."


def get_deserialization_map():
    """
    Get a dictionary that maps strings to the classes that they deserialize into.
    :return: A dictionary that maps strings to the classes that they deserialize into.
    """
    return {get_import_path_for_type(x): x for x in get_supported_serialization_classes()}


def get_supported_serialization_classes():
    """
    Get a list of the classes that are currently supported for serialization.
    :return: A list of the classes that are currently supported for serialization.
    """
    from lib.arin.response import BaseArinResponse
    from ..geolocation import IpGeolocation
    return [
        PreparedRequest,
        Response,
        BaseArinResponse,
        IpGeolocation,
    ]


class WsSerializableJSONEncoder(JSONEncoder):
    """
    This is a custom JSON encoder class that encodes various classes used by the Web Sight platform into
    JSON dictionaries.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(WsSerializableJSONEncoder, self).__init__(*args, **kwargs)
        self._deserialization_map = None

    # Static Methods

    # Class Methods

    # Public Methods

    def decode(self, o):
        """
        Decode the contents of the given JSON dictionary as an object used by Web Sight.
        :param o: The JSON dictionary to process.
        :return: The contents of the given JSON dictionary deserialized into an object.
        """
        from lib.arin.response import BaseArinResponse
        from ..geolocation import IpGeolocation
        if "__class_type" not in o:
            raise UnsupportedDeserializationError("No class type specified in JSON dictionary: %s" % o)
        class_type = o["__class_type"]
        deserialization_class = get_class_from_import_string(class_type)
        if deserialization_class == PreparedRequest:
            return self.__deserialize_requests_prepared_request(o)
        elif deserialization_class == Response:
            return self.__deserialize_requests_response(o)
        elif issubclass(deserialization_class, BaseArinResponse):
            return self.__deserialize_arin_response(o)
        elif deserialization_class == IpGeolocation:
            return self.__deserialize_ip_geolocation(o)
        else:
            raise UnsupportedDeserializationError(
                "Class %s does not have a deserialization method."
                % deserialization_class
            )

    def encode(self, o):
        """
        Encode the contents of the given object into JSON.
        :param o: The object to process.
        :return: The contents of the given object in JSON format.
        """
        from lib.arin.response import BaseArinResponse
        from ..geolocation import IpGeolocation
        if isinstance(o, PreparedRequest):
            return self.__serialize_requests_prepared_request(o)
        elif isinstance(o, Response):
            return self.__serialize_requests_response(o)
        elif isinstance(o, BaseArinResponse):
            return self.__serialize_arin_response(o)
        elif isinstance(o, IpGeolocation):
            return self.__serialize_ip_geolocation(o)
        else:
            return super(WsSerializableJSONEncoder, self).encode(o)

    # Protected Methods

    # Private Methods

    def __deserialize_arin_response(self, to_deserialize):
        """
        Create and return an ARIN API response based on the contents of the given dictionary.
        :param to_deserialize: The dictionary to create the ARIN response from.
        :return: An ARIN response object created by the contents of to_deserialize.
        """
        response_class = get_class_from_import_string(to_deserialize["__class_type"])
        return response_class(self.decode(to_deserialize["response"]))

    def __deserialize_ip_geolocation(self, to_deserialize):
        """
        Create and return an IpGeolocation based on the contents of the given dictionary.
        :param to_deserialize: The dictionary to create the IpGeolocation from.
        :return: An IpGeolocation based on the contents of the given dictionary.
        """
        from ..geolocation import IpGeolocation
        to_deserialize.pop("__class_type")
        return IpGeolocation(**to_deserialize)

    def __deserialize_requests_prepared_request(self, to_deserialize):
        """
        Create and return a PreparedRequest based on the contents of the given dictionary.
        :param to_deserialize: The dictionary to create the PreparedRequest from.
        :return: A PreparedRequest created by the contents of to_deserialize.
        """
        to_return = PreparedRequest()
        to_return.method = to_deserialize["method"]
        to_return.url = to_deserialize["url"]
        to_return.headers = to_deserialize["headers"]
        to_return.body = to_deserialize["body"]
        return to_return

    def __deserialize_requests_response(self, to_deserialize):
        """
        Create and return a Response based on the contents of the given dictionary.
        :param to_deserialize: The dictionary to create the Response from.
        :return: A Response created by the contents of to_deserialize.
        """
        to_return = Response()
        to_return.status_code = to_deserialize["status_code"]
        to_return.headers = CaseInsensitiveDict(to_deserialize["headers"])
        to_return.encoding = to_deserialize["encoding"]
        to_return._content = to_deserialize["content"]
        to_return._content_consumed = True
        to_return.reason = to_deserialize["reason"]
        to_return.url = to_deserialize["url"]
        to_return.request = self.decode(to_deserialize["request"])
        return to_return

    def __serialize_arin_response(self, to_serialize):
        """
        Serialize the contents of to_serialize as a response returned by the ARIN API.
        :param to_serialize: The ARIN response to serialize.
        :return: A JSON object representing the contents of the given ARIN response.
        """
        return {
            "response": self.encode(to_serialize.response),
            "__class_type": get_import_path_for_type(to_serialize),
        }

    def __serialize_ip_geolocation(self, to_serialize):
        """
        Serialize the contents of the given IpGeolocation.
        :param to_serialize: The IpGeolocation to serialize.
        :return: A JSON object representing the contents of the given IpGeolocation.
        """
        return {
            "country": to_serialize.country,
            "country_code": to_serialize.country_code,
            "isp": to_serialize.isp,
            "latitude": to_serialize.latitude,
            "longitude": to_serialize.longitude,
            "region": to_serialize.region,
            "region_name": to_serialize.region_name,
            "postal_code": to_serialize.postal_code,
            "geo_source": to_serialize.geo_source,
            "ip_address": to_serialize.ip_address,
            "__class_type": get_import_path_for_type(to_serialize),
        }

    def __serialize_requests_prepared_request(self, to_serialize):
        """
        Serialize the contents of the given requests library request object to a JSON dictionary. A request is
        populated by the requests session object as follows:

        def copy(self):
            p = PreparedRequest()
            p.method = self.method
            p.url = self.url
            p.headers = self.headers.copy() if self.headers is not None else None
            p._cookies = _copy_cookie_jar(self._cookies)
            p.body = self.body
            p.hooks = self.hooks
            p._body_position = self._body_position
            return p

        :param to_serialize: The request object to serialize.
        :return: A JSON object representing the contents of the given request.
        """
        return {
            "method": to_serialize.method,
            "url": to_serialize.url,
            "headers": dict(to_serialize.headers),
            "body": to_serialize.body,
            "__class_type": get_import_path_for_type(to_serialize),
        }

    def __serialize_requests_response(self, to_serialize):
        """
        Serialize the contents of the given requests library response object to a JSON dictionary. A response
        is populated by the requests adapter build_response method as follows:

        response = Response()
        response.status_code = getattr(resp, 'status', None)
        response.headers = CaseInsensitiveDict(getattr(resp, 'headers', {}))
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason
        if isinstance(req.url, bytes):
            response.url = req.url.decode('utf-8')
        else:
            response.url = req.url
        extract_cookies_to_jar(response.cookies, req, resp)
        response.request = req
        response.connection = self
        return response

        :param to_serialize: The response object to serialize.
        :return: A JSON object representing the contents of the given response.
        """
        return {
            "status_code": to_serialize.status_code,
            "headers": dict(to_serialize.headers),
            "encoding": to_serialize.encoding,
            "content": to_serialize.content,
            "reason": to_serialize.reason,
            "url": to_serialize.url,
            "request": self.encode(to_serialize.request),
            "__class_type": get_import_path_for_type(to_serialize),
        }

    # Properties

    @property
    def deserialization_map(self):
        """
        Get a dictionary that maps import path strings to the classes they deserialize into.
        :return: a dictionary that maps import path strings to the classes they deserialize into.
        """
        if self._deserialization_map is None:
            self._deserialization_map = get_deserialization_map()
        return self._deserialization_map

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)
