# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from ..base import DatabaseTask
from ...app import websight_app
from lib import S3Helper
from lib.parsing import DomainsTextFileWrapper
from lib.sqlalchemy import get_all_domains_for_organization, create_domain_for_organization

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def process_dns_text_file(self, org_uuid=None, file_key=None, file_bucket=None):
    """
    Process the contents of the DNS text file referenced by file_key and add the contents
    of the file to the list of domain names associated with the given organization.
    :param org_uuid: The UUID of the organization to add domain names to.
    :param file_key: The S3 file key where the file resides.
    :param file_bucket: The S3 bucket where the file resides.
    :return: None
    """
    logger.info(
        "Now processing DNS text file at %s for organization %s."
        % (file_key, org_uuid)
    )
    s3_helper = S3Helper.instance()
    contents = s3_helper.get_file(file_key=file_key, bucket=file_bucket)
    file_wrapper = DomainsTextFileWrapper(contents)
    org_domains = get_all_domains_for_organization(db_session=self.db_session, org_uuid=org_uuid)
    logger.info(
        "Now processing a total of %s domains for organization %s. Organization already has %s domains."
        % (len(file_wrapper.rows), org_uuid, len(org_domains))
    )
    new_domains = skipped_domains = 0
    for row in file_wrapper.rows:
        if row in org_domains:
            skipped_domains += 1
        else:
            new_domain = create_domain_for_organization(org_uuid=org_uuid, name=row)
            self.db_session.add(new_domain)
            new_domains += 1
    logger.info(
        "Done processing domains for organization %s. %s new domains will be created, %s were skipped, and %s "
        "rows in the file were erroneous. Committing now."
        % (org_uuid, new_domains, skipped_domains, len(file_wrapper.errored_rows))
    )
    self.commit_session()
    logger.info(
        "Domain names added to database from file %s for organization %s."
        % (file_key, org_uuid)
    )
