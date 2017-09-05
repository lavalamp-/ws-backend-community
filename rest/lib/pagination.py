# -*- coding: utf-8 -*-
from __future__ import absolute_import

import math
from rest_framework import pagination
from rest_framework.response import Response
from rest_framework.settings import api_settings


class PaginationSerializer(object):
    """
    This is a serilaizer that takes the results of a paginated request and converts the contents
    to a dictionary to be consumed by Django response objects.
    """

    def __init__(
            self,
            results=None,
            count=None,
            current_page=None,
            page_size=None,
    ):
        self.results = results
        self.count = count
        self.current_page = current_page
        self.page_size = page_size

    def to_response_dict(self):
        """
        Return a Python dictionary which should be used in Django response objects.
        :return: A Python dictionary which should be used in Django response objects.
        """
        last_page = max(1, int(math.ceil(self.count/float(self.page_size))))
        return {
            "count": self.count,
            "first_page": 1,
            "last_page": last_page,
            "page_size": self.page_size,
            "current_page": self.current_page,
            "results": self.results,
        }


class WebSightPagination(pagination.PageNumberPagination):
    """
    This is the pagination class to use when returning paginate-able data to users.
    """

    def get_paginated_response(self, data):
        serializer = PaginationSerializer(
            results=data,
            count=self.page.paginator.count,
            current_page=self.page.number,
            page_size=self.page_size,
        )
        return Response(serializer.to_response_dict())
