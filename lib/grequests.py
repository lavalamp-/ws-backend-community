# -*- coding: utf-8 -*-
from __future__ import absolute_import

import grequests, gevent
import logging
from grequests import AsyncRequest
from lib.exception import ValidationError
from .config import ConfigManager
import time

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


def RateLimited(maxPerSecondVar):
    """
        This decorator is used to limit the number of function calls per second,
        we use this inside of GRequestsHelper to limit requests per second
    :param maxPerSecondVar: This is the class variable that contains the limit of calls per second
    :return: The function to call
    """
    def decorate(func):
        lastTimeCalled = [0.0]
        def rateLimitedFunction(self, *args, **kargs):
            maxPerSecond = getattr(self, maxPerSecondVar)
            print 'limiting requests to [%d] per second' % (maxPerSecond)

            minInterval = 1.0 / float(maxPerSecond)
            elapsed = time.clock() - lastTimeCalled[0]
            leftToWait = minInterval - elapsed
            if leftToWait>0:
                gevent.sleep(leftToWait)
            ret = func(self, *args, **kargs)
            lastTimeCalled[0] = time.clock()
            return ret
        return rateLimitedFunction
    return decorate

class GRequestsHelper(object):
    """
    This class contains helper methods for querying the configuration / setup / capabilities of
    the host where the code is running.
    """

    # Class Members

    #This array contains all of the valid http verbs
    _all_http_methods = [
        'get',
        'head',
        'post',
        'put',
        'delete',
        'trace',
        'connect'
    ]

    #This is the max amount of requests we will send at any given time
    _default_batch_size = 100

    #This is the maximum timeout that we will wait for any request
    _default_timeout = 30

    #This is the requests per second, this is only enforced if it is greater than 0
    _requests_per_second = -1

    # Instantiation
    def __init__(self, batch_size=None, timeout=None, requests_per_second=None):
        if batch_size:
           self. _default_batch_size = batch_size
        if timeout:
            self._default_timeout = timeout
        if requests_per_second:
            self._requests_per_second = requests_per_second


    # Static Methods
    @staticmethod
    def exception_handler(request, exception):
        """
        This method handles all of the exceptions that happen while sending requests
        """
        logger.warning('[*] Exception loading request in GRequestHelper')
        logger.warning('[*] Exception: [%s] Method: [%s] Url: [%s]' % (exception, request.method, request.url))


    # Class Methods


    #Public Methods
    def send_requests(self, method, urls):
        """
        Requests all urls using the method specified in parallel using grequests
        :param method: The http method to use
        :param urls: The list of urls we will request
        :param batch_size: If specified, this will controll the maximum number of requests
        :return: A list of responses for each requested url
        """
        print 'Method: [%s] Urls %s' % (method, urls)

        if type(urls) is not list:
            raise ValidationError('Invalid urls parameter in send_requests, urls should be a list')

        if type(method) is not str:
            raise ValidationError('Invalid method parameter in send_requests, method should be a string')

        if len(method) <= 0:
            raise ValidationError('Invalid method parameter in send_requests, method should have a length')

        request_set = (AsyncRequest(method, str(u)) for u in urls)

        if self._requests_per_second > 0:
            #Throttle the speed of our requests
            results = []
            for request in request_set:
                results.append(self._send_request(request))
            return results
        else:
            return grequests.map(request_set, exception_handler=GRequestsHelper.exception_handler, size=self._default_batch_size)


    def send_requests_for_all_methods(self, urls):
        """
        Requests all urls using all http methods in parallel using grequests
        :param urls: The list of urls we will request
        :return: A list of responses for each requested url
        """
        print 'Urls %s' % (urls)

        if type(urls) is not list:
            raise ValidationError('Invalid urls parameter in send_request_for_all_methods, urls should be a list')

        request_set = []
        for method in GRequestsHelper._all_http_methods:
            method_set_for_url = (AsyncRequest(method, str(u)) for u in urls)
            request_set.extend(method_set_for_url)

        if self._requests_per_second > 0:
            #Throttle the speed of our requests
            results = []
            for request in request_set:
                results.append(self._send_request(request))
            return results
        else:
            return grequests.map(request_set, exception_handler=GRequestsHelper.exception_handler, size=self._default_batch_size)


    # Protected Methods
    @RateLimited('_requests_per_second')
    def _send_request(self, request):
        """
        Submits the actual request, this function is rate limited by requests per second
        This is controlled by the _requests_per_second class variable
        :param request: the request to submit
        :return: the AsyncRequest that grequests returns
        """
        return request.send()


    # Private Methods

    # Properties

    # Representation and Comparison
