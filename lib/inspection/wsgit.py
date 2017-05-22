# -*- coding: utf-8 -*-
from __future__ import absolute_import

from git import Repo
import git.exc

from .base import BaseInspector


class GitInspector(BaseInspector):
    """
    This is an inspector class that can analyze a Git repository.
    """

    # Class Members

    # Instantiation

    def __init__(self, git_url=None, local_directory_path=None):
        """
        Initialize this GitInspector to have a reference to the Git repository it's meant to
        investigate and a local file path to the contents of the Git repository (if the repo has already
        been cloned).
        :param git_url: The URL to the Git repository.
        :param local_directory_path: The local file path where the git repository is stored.
        """
        self._git_url = git_url
        if local_directory_path is None:
            self._local_directory_path = self.get_temporary_directory_path()
        else:
            self._local_directory_path = local_directory_path
        super(GitInspector, self).__init__()

    # Static Methods

    # Class Methods

    # Public Methods

    def get_commits(self):
        """
        Get a list containing all of the commits in the repository.
        :return: A list containing all of the commits in the repository.
        """
        to_return = []
        for cur_commit in self.get_repo().iter_commits():
            to_return.append(cur_commit)
        return to_return

    def get_commit_diffs(self, commit_1=None, commit_2=None):
        """
        Get a list containing the diffs between the two commits.
        :param commit_1: A string representing the commit, or a commit object.
        :param commit_2: A string representing the commit, or a commit object.
        :return: A list containing the diffs between the two commits.
        """
        repo = self.get_repo()
        if isinstance(commit_1, str):
            commit_1 = repo.commit(commit_1)
        if isinstance(commit_1, str):
            commit_2 = repo.commit(commit_2)
        return commit_1.diff(commit_2)

    def get_commit_tuples(self, branch=None):
        """
        Get a list of tuples containing (1) the commit SHA hex value and (2) the commit name for
        all commits in the given branch.
        :param branch: The branch to retrieve commits for.
        :return: A list of tuples containing (1) the commit SHA hex value and (2) the commit name for
        all commits in the given branch.
        """
        return [x.name_rev.split() for x in self.get_commits()]

    def get_diffs_of_types(self, types=None, commit_1=None, commit_2=None):
        """
        Get all of the diffs between the two given commits of the given types.
        :param types: A list of strings representing the Git diff types to check for.
        :param commit_1: The first commit to check from.
        :param commit_2: The second commit to get the diffs between.
        :return: A list containing all of the diffs between the given commits of the given types.
        """
        return [x for x in self.get_commit_diffs(commit_1=commit_1, commit_2=commit_2) if x.change_type in types]

    def get_repo(self):
        """
        Get the Git repository that this inspector is meant to inspect. If the repository has not
        been cloned yet, then the repository will be cloned first.
        :return: The Git repository to inspect.
        """
        try:
            return Repo(self.local_directory_path)
        except git.exc.InvalidGitRepositoryError:
            return self.clone_repo()

    def clone_repo(self, local_directory_path=None):
        """
        Clone the Git repository to the given file path.
        :param local_directory_path: The file path to clone the repository to. If None, then use the default
        directory path.
        :return: The Git repository.
        """
        if local_directory_path is None:
            local_directory_path = self.local_directory_path
        return Repo.clone_from(self.git_url, local_directory_path)

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def git_url(self):
        """
        Get the URL to the Git repository.
        :return: the URL to the Git repository.
        """
        return self._git_url

    @property
    def inspection_target(self):
        return self.git_url

    @property
    def local_directory_path(self):
        """
        Get the local path to where the directory is and/or should be cloned.
        :return: the local path to where the directory is and/or should be cloned.
        """
        return self._local_directory_path

    # Representation and Comparison
