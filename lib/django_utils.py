# -*- coding: utf-8 -*-
from __future__ import absolute_import

class DjangoUtils(object):

    def __init__(self):
        pass

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    @staticmethod
    def get_user_agent(request):
        return request.META.get('HTTP_USER_AGENT', '')

