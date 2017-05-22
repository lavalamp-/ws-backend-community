# -*- coding: utf-8 -*-
from __future__ import absolute_import


class WsTestData(object):
    """
    This is a class for containing varied data used by Web Sight unit tests
    """

    TEST_USER_1 = {
        "username": "test1@websight.io",
        "password": "P@ssword123!",
        "first_name": "Test",
        "last_name": "User",
        "email": "test1@websight.io",
        "is_staff": False,
        "is_active": True,
        "is_superuser": False,
        "email_verified": True,
    }

    TEST_USER_2 = {
        "username": "test2@websight.io",
        "password": "P@ssword123!",
        "first_name": "Test",
        "last_name": "User",
        "email": "test2@websight.io",
        "is_staff": False,
        "is_active": True,
        "is_superuser": False,
        "email_verified": True,
    }

    ADMIN_USER_1 = {
        "username": "test3@websight.io",
        "password": "P@ssword123!",
        "first_name": "Test",
        "last_name": "User",
        "email": "test3@websight.io",
        "is_staff": True,
        "is_active": True,
        "is_superuser": True,
        "email_verified": True,
    }

    USERS = {
        "user_1": TEST_USER_1,
        "user_2": TEST_USER_2,
        "admin_1": ADMIN_USER_1,
    }

    CREATE_USER = {
        "username": "test4@websight.io",
        "password": "P@ssw0rd123!!",
        "first_name": "Barry",
        "last_name": "Bonds",
        "recaptcha_response": "asd123asd123",
    }

    UNUSED_IP_ADDRESS = "99.99.99.99"
    UNUSED_IP_CLASS_C = "99.99.99.0"
    UNUSED_IP_CLASS_B = "99.99.0.0"
    UNUSED_IP_CLASS_A = "99.0.0.0"

    WEB_SERVICE_ANALYSIS_UUID = "572b461a-a00c-4fe4-945a-70310069d202"
