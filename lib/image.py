# -*- coding: utf-8 -*-
from __future__ import absolute_import

from PIL import Image

from .config import ConfigManager

config = ConfigManager.instance()


class ImageProcessingHelper(object):
    """
    This class contains a number of helper methods for working with images.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def crop_image(file_path=None, width=None, height=None):
        """
        Crop the image at the given path to the given size.
        :param file_path: The file path where the image resides/
        :param width: The width to crop the image to.
        :param height: The height to crop the image to.
        :return: A PIL image object representing the image at file_path cropped to the configured
        dimensions.
        """
        image = Image.open(file_path)
        box = (0, 0, width, height)
        return image.crop(box)

    @staticmethod
    def crop_selenium_screenshot(file_path):
        """
        Crop the screenshot taken by Selenium at the given file path to the default Selenium width
        and height.
        :param file_path: The file path where the screenshot resides.
        :return: A PIL image object representing the Selenium screenshot at file_path cropped to the
        default Selenium height and width.
        """
        return ImageProcessingHelper.crop_image(
            file_path=file_path,
            width=config.selenium_window_width,
            height=config.selenium_window_height,
        )

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
