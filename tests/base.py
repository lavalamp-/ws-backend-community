# -*- coding: utf-8 -*-
from __future__ import absolute_import

import unittest
import inspect

from .data import WsTestData


class BaseWebSightTestCase(unittest.TestCase):
    """
    This is a base class for all unit tests used by the Web Sight platform.
    """
    
    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        """
        Initializes the BaseWebSightTestCase to allow long messages.
        :param kwargs: Key word arguments supplied to this method.
        :return: None
        """
        super(BaseWebSightTestCase, self).__init__(*args, **kwargs)
        self.longMessage = True
        self._add_id = False

    # Static Methods

    # Class Methods

    @classmethod
    def get_test_names(cls):
        """
        Get all of the test names owned by this test case.
        :return: A list containing all of the test names owned by this test case.
        """
        return [x[0] for x in inspect.getmembers(cls.__class__, predicate=inspect.ismethod) if x[0].startswith("test")]

    @classmethod
    def count_tests(cls):
        """
        Get the number of tests within the test case class.
        :return: The number of tests within the test case class.
        """
        return len(cls.get_test_names())

    # Public Methods

    def fail(self, msg=None):
        super(BaseWebSightTestCase, self).fail(msg=self.__get_message(msg))

    def failIf(self, expr, msg=None):
        super(BaseWebSightTestCase, self).failIf(expr, msg=self.__get_message(msg))

    def failIfAlmostEqual(self, first, second, places=7, msg=None):
        super(BaseWebSightTestCase, self).failIfAlmostEqual(
            first,
            second,
            places=places,
            msg=self.__get_message(msg),
        )

    def failIfEqual(self, first, second, msg=None):
        super(BaseWebSightTestCase, self).failIfEqual(first, second, msg=self.__get_message(msg))

    def failUnless(self, expr, msg=None):
        super(BaseWebSightTestCase, self).failUnless(expr, msg=self.__get_message(msg))

    def failUnlessAlmostEqual(self, first, second, places=7, msg=None):
        super(BaseWebSightTestCase, self).failUnlessAlmostEqual(
            first,
            second,
            places=places,
            msg=self.__get_message(msg),
        )

    def failUnlessEqual(self, first, second, msg=None):
        super(BaseWebSightTestCase, self).failUnlessEqual(first, second, msg=self.__get_message(msg))

    assert_ = assertTrue = failUnless
    assertAlmostEqual = assertAlmostEquals = failUnlessAlmostEqual
    assertEqual = assertEquals = failUnlessEqual
    assertFalse = failIf
    assertNotAlmostEqual = assertNotAlmostEquals = failIfAlmostEqual
    assertNotEqual = assertNotEquals = failIfEqual

    def assertTupleListsEqual(self, first_list, second_list):
        """
        Assert that the given two lists of tuples are equivalent.
        :param first_list: The first list of tuples.
        :param second_list: The second list of tuples.
        :return: None
        """
        self.assertTupleEqual(tuple(sorted(first_list)), tuple(sorted(second_list)))

    def get_user_data(self, user="user_1"):
        """
        Get a dictionary containing the keyword arguments supplied to the creation of the given
        user.
        :param user: A string depicting which user dictionary to return.
        :return: A dictionary containing the keyword arguments passed to WsUser.objects.create_user.
        """
        if user == "user_1":
            return WsTestData.TEST_USER_1
        elif user == "user_2":
            return WsTestData.TEST_USER_2
        elif user == "admin_1":
            return WsTestData.ADMIN_USER_1
        else:
            raise ValueError(
                "Not sure how to handle user retrieval for user %s."
                % (user,)
            )

    # Protected Methods

    # Private Methods

    def __get_message(self, msg):
        """
        Get the message that should be displayed in the event of a failed test case.
        :param msg: The message body to process.
        :return: The message that should be displayed in the event of a failed test case.
        """
        if self._add_id:
            return "%s %s" % (msg, self.id()) if msg else self.id()
        else:
            return msg

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s tests>" % (self.__class__.__name__, self.__class__.count_tests())
