# -*- coding: utf-8 -*-
from __future__ import absolute_import


class BaseWsMiddleware(object):
    """
    This is a base class for custom Scrapy middleware.
    """
    
    # Class Members

    # Instantiation

    def __init__(self):
        pass

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
    
    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class BaseWsSpiderMiddleware(BaseWsMiddleware):
    """
    This is a base class for custom Scrapy spidering middleware.
    """
    
    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseWsDownloaderMiddleware(BaseWsMiddleware):
    """
    This is a base class for custom Scrapy downloader middleware.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
