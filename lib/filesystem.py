# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import errno
import json
from uuid import uuid4
import shutil
import math
import logging

from subprocess import check_output, CalledProcessError

from .config import ConfigManager

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class FilesystemHelper(object):
    """
    A class for containing all methods related to file system operations.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def calculate_hash_of_file(file_path):
        """
        Calculate the SHA256 hash hex digest of the file at the specified path.
        :param file_path: The path to the file that the SHA256 hex digest should be calculated for.
        :return: The SHA256 hash hex digest of the file at the specified path.
        """
        from .crypto import HashHelper
        with open(file_path, "r") as f:
            contents = f.read()
        return HashHelper.sha256_digest(contents)

    @staticmethod
    def count_lines_in_file(file_path):
        """
        Count the total number of lines in the file at file_path.
        :param file_path: The path for the file to review.
        :return: The number of lines found in the file.
        """
        line_count = 0
        with open(file_path, "r") as f:
            for line in f:
                line_count += 1
        return line_count

    @staticmethod
    def create_directories(dir_path):
        """
        Creates all of the currently non-existing directories found in dir_path.
        :param dir_path: A path containing directories (or a single directory) to
        create.
        :return: None
        """
        try:
            os.makedirs(dir_path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    @staticmethod
    def delete_directory(dir_path):
        """
        Deletes the directory specified at dir_path.
        :param dir_path: The path to the directory to delete.
        :return: None
        """
        shutil.rmtree(dir_path)

    @staticmethod
    def delete_file(file_path):
        """
        Deletes the file at the path denoted by file_path.
        :param file_path: The path to the file that should be deleted.
        :return: None
        """
        try:
            os.remove(file_path)
        except OSError:
            pass

    @staticmethod
    def does_directory_exist(dir_path):
        """
        Checks to see whether a directory currently exists at dir_path. Note
        that if dir_path points to a file that does exist, this method will
        return False.
        :param dir_path: The path of the directory to check for.
        :return: True if a directory exists at dir_path, otherwise False.
        """
        return os.path.isdir(dir_path)

    @staticmethod
    def does_file_exist(file_path):
        """
        Checks to see whether a file currently exists at file_path. Note that
        if file_path points to a directory that does exist, this method will
        return False.
        :param file_path: The path of the file to check for.
        :return: True if a file exists at file_path, otherwise False.
        """
        return os.path.isfile(file_path)

    @staticmethod
    def get_json_from_file(file_path, raise_error=True):
        """
        Attempt to read the contents of the specified file as a JSON object. Raises
        an error if the specified file does not contain valid JSON and raise_error
        is True, and returns None if the file does not contain valid JSON and raise_error
        is False.
        :param file_path: The path to the file to read.
        :return: A JSON object representing the file's contents if the file contains valid
        JSON, or None.
        """
        contents = FilesystemHelper.get_file_contents(file_path)
        try:
            return json.loads(contents)
        except ValueError as e:
            if raise_error:
                raise e
            else:
                return None

    @staticmethod
    def get_file_contents(path=None, read_mode="r"):
        """
        Get the contents of the file at the specified path.
        :param path: The path of the file to retrieve the contents of.
        :return: The contents of the file at the specified path.
        """
        if FilesystemHelper.is_dir_path(path):
            raise ValueError(
                "FilesystemHelper.get_file_contents received a path argument fhat pointed to a directory. "
                "Path was %s."
                % (path,)
            )
        with open(path, read_mode) as f:
            contents = f.read()
        return contents

    @staticmethod
    def get_file_information(file_path):
        """
        Get a number of data points about the given file.
        :param file_path: The local file path to the file to process.
        :return: A tuple containing (1) the file name, (2) a SHA-256 hash digest of the file's contents,
        (3) the number of lines in the file, and (4) the size of the file in bytes.
        """
        file_name = FilesystemHelper.get_file_name_from_path(file_path)
        file_hash = FilesystemHelper.calculate_hash_of_file(file_path)
        file_line_count = FilesystemHelper.count_lines_in_file(file_path)
        file_size = FilesystemHelper.get_file_size(file_path)
        return file_name, file_hash, file_line_count, file_size

    @staticmethod
    def get_file_name_from_path(path):
        """
        Parses the file name from the given path and returns it.
        :param path: The path to parse.
        :return: The file name from the given path.
        """
        if FilesystemHelper.is_dir_path(path):
            raise ValueError(
                "FilesystemHelper.get_file_name_from_path received a path argument that pointed to a "
                "directory. Path was %s."
                % (path,)
            )
        return os.path.basename(path)

    @staticmethod
    def get_file_size(file_path):
        """
        Get the size in bytes of the file at file_path.
        :param file_path: The path on disk to the file in question.
        :return: The size in bytes of the referenced file.
        """
        return os.path.getsize(file_path)

    @staticmethod
    def get_files_with_extension_from_directory(start_dir=".", extension=None):
        """
        Recursively walk the directories found within start_dir to find all files that have the specified
        extension and return a list of file paths to the discovered files.
        :param start_dir: Where to start walking directories from.
        :param extension: The extension to look for (ex: .py).
        :return: A list containing file paths pointing to all files sharing the specified extension as found
        recursively from start_dir.
        """
        to_return = []
        for root, dirs, files in os.walk(start_dir):
            match_files = filter(lambda x: x.endswith(extension), files)
            to_return.extend([os.path.join(root, match_file) for match_file in match_files])
        return to_return

    @staticmethod
    def get_lines_from_file(file_path=None, strip=True):
        """
        Get all of the lines in the file specified by file_path in an array.
        :param file_path: The path to the file to read.
        :param strip: Whether or not to aggressively strip whitespace from the file's contents.
        :return: An array of strings representing the lines in the specified file.
        """
        with open(file_path, "r") as f:
            contents = f.read()
        if strip:
            return [x.strip() for x in contents.strip().split("\n")]
        else:
            return contents.split("\n")

    @staticmethod
    def get_parent_directory_name(file_path):
        """
        Get the name of the parent directory found in the given path.
        :param file_path: The path to parse.
        :return: The name of the parent directory found in the given path.
        """
        return os.path.dirname(file_path).split(os.path.sep)[-1]

    @staticmethod
    def get_temporary_directory_path(path_base=None):
        """
        Returns a directory path that can be used to create a temporary directory.
        Note that the caller is responsible for deleting this directory when done
        using it.
        :param path_base: The base of the path to use for the temporary directory path.
        If this is None, config.temporary_file_dir will be used in its place.
        :return: A directory path that can be used to create a temporary directory.
        """
        if path_base:
            return "".join([path_base, str(uuid4()), os.pathsep])
        else:
            return "".join([config.fs_temporary_file_dir, str(uuid4()), os.pathsep])

    @staticmethod
    def get_temporary_file_path(path_base=None, file_ext=None):
        """
        Returns a file path that can be used to create a temporary file. Note
        that the caller is responsible for deleting this file when done using it.
        :param path_base: The base of the path to use for the temporary file path.
        If this is None, config.temporary_file_dir will be used in its place.
        :param file_ext: The file extension to place at the end of the created
        path
        :return: A file path that can be used to create a temporary file.
        """
        if file_ext is not None and not file_ext.startswith("."):
            file_ext = ".%s" % (file_ext,)
        else:
            file_ext = ""
        if path_base:
            return "".join([path_base, str(uuid4()), file_ext])
        else:
            return "".join([config.fs_temporary_file_dir, str(uuid4()), file_ext])

    @staticmethod
    def is_dir_path(path):
        """
        Check to see if the given path specifies a directory.
        :param path: The path to parse.
        :return: True if the path specifies a directory, False otherwise.
        """
        return os.path.isdir(path)

    @staticmethod
    def is_file_path(path):
        """
        Check to see if the given path specifies a file.
        :param path: The path to parse.
        :return: True if the path specifies a file, False otherwise.
        """
        return os.path.isfile(path)

    @staticmethod
    def move_file(from_path=None, to_path=None):
        """
        Move the file found at the specified from_path to to_path.
        :param from_path: The file path where the file currently resides.
        :param to_path: The path where the file should be moved to.
        :return: None
        """
        os.rename(from_path, to_path)

    @staticmethod
    def split_file(file_path=None, output_file_name=None, chunk_count=None):
        """
        Split the file pointed to by file_path into chunk_count number of files, and name
        these new files based on output_file_name.
        :param file_path: The local file path to the file to split up.
        :param output_file_name: The file name base to write resulting files to.
        :param chunk_count: The number of chunks to split the file into.
        :return: None
        """
        contents = FilesystemHelper.get_file_contents(path=file_path, read_mode="rb")
        content_length = len(contents)
        chunk_size = int(math.ceil(content_length / float(chunk_count)))
        logger.debug(
            "Now splitting file at %s into %s chunks (%s bytes each) and writing to file with name %s."
            % (file_path, chunk_count, chunk_size, output_file_name)
        )
        start_offset = 0
        end_offset = chunk_size + 1
        for i in range(chunk_count):
            file_name = "%s.%s" % (output_file_name, i)
            logger.debug(
                "Writing first chunk of length %s to %s."
                % (file_name, chunk_size)
            )
            FilesystemHelper.write_to_file(
                file_path=file_name,
                data=contents[start_offset:end_offset],
                write_mode="wb+",
            )
            start_offset += chunk_size
            end_offset += chunk_size
        logger.debug("File split successfully.")

    @staticmethod
    def touch(path):
        """
        Emulates the Linux 'touch' utility - creates a file if it
        does not exist.
        :param path: The path of the file to create.
        :return: None
        """
        # TODO handle exceptions
        if os.path.exists(path):
            os.utime(path, None)
        else:
            open(path, "a").close()

    @staticmethod
    def write_to_file(file_path=None, data=None, write_mode="w+"):
        """
        Write the contents of data to the file at file_path using the specified write mode.
        :param file_path: The file path where the data should be written to.
        :param data: The data to write.
        :param write_mode: The mode that the data should be written to the file.
        :return: None
        """
        with open(file_path, write_mode) as f:
            f.write(data)

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class FileHelper(object):
    """
    This class contains helper methods for retrieving the contents of files associated with the
    Web Sight platform.
    """

    @staticmethod
    def get_dns_record_types():
        """
        Get a list of tuples containing (1) the DNS record type, (2) whether or not to collect data
        about the DNS record type by default and (3) whether or not to scan IP addresses associated with the
        the record type from the default DNS record types file.
        :return: A list of tuples containing (1) the DNS record type, (2) whether or not to collect data
        about the DNS record type by default and (3) whether or not to scan IP addresses associated with the
        the record type from the default DNS record types file.
        """
        contents = FilesystemHelper.get_file_contents(path=config.files_dns_record_types_path)
        contents = [x.strip() for x in contents.strip().split("\n")]
        to_return = []
        for line in contents:
            line_split = [x.strip() for x in line.split(",")]
            to_return.append((
                line_split[0],
                line_split[1].lower() == "true",
                line_split[2].lower() == "true",
            ))
        return to_return

    @staticmethod
    def get_scan_ports_and_protocols():
        """
        Get a list of tuples containing (1) the port number and (2) the protocol for all of the
        ports that are scanned by default.
        :return: A list of tuples containing (1) the port number and (2) the protocol for all of the
        ports that are scanned by default.
        """
        contents = FilesystemHelper.get_file_contents(path=config.files_default_scan_ports_path)
        contents = [x.strip() for x in contents.strip().split("\n")]
        ports = []
        for line in contents:
            line_split = [x.strip() for x in line.split(",")]
            ports.append((int(line_split[0]), line_split[1]))
        return ports


class PathHelper(object):
    """
    This class contains helper methods for interacting with the current PATH environment
    variable.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def is_executable_in_path(to_check):
        """
        Check to see if the specified executable is found in the current environment's
        PATH environment variable.
        :param to_check: The executable to search for.
        :return: True of the referenced executable is found, False otherwise.
        """
        try:
            result = check_output(["which", to_check]).strip()
            return bool(result)
        except CalledProcessError:
            return False

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
