# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group
from celery.utils.log import get_task_logger

from lib import S3Helper, ConfigManager
from lib.inspection import HttpScreenshotter
from lib.sqlalchemy import get_endpoint_information_for_web_service
from ......app import websight_app
from .....base import ServiceTask

logger = get_task_logger(__name__)
config = ConfigManager.instance()


def get_url_paths_to_screenshot(service_uuid=None, scan_uuid=None, db_session=None):
    """
    Get a list of URL paths to screenshot for the given web service.
    :param service_uuid: The UUID of the service to get URL paths for.
    :param scan_uuid: The UUID of the scan to retrieve URL paths in.
    :param db_session: A SQLAlchemy session.
    :return: A list of URL paths to screenshot for the given web service.
    """
    return ["/"]


def upload_screenshot_to_s3(org_uuid=None, local_file_path=None):
    """
    Upload the screenshot at the given file path to AWS S3 and return data about where the file
    was uploaded to.
    :param org_uuid: The UUID of the organization that owns the screenshot.
    :param local_file_path: The local file path where the screenshot can be found.
    :return: A tuple containing (1) the bucket where the file was uploaded to and (2) the key it was
    uploaded under.
    """
    s3_helper = S3Helper.instance()
    logger.info(
        "Uploading HTTP screenshot at %s to S3."
        % (local_file_path,)
    )
    response, key = s3_helper.upload_screenshot(
        org_uuid=org_uuid,
        local_file_path=local_file_path,
        bucket=config.aws_s3_bucket,
    )
    logger.info(
        "HTTP screenshot at %s successfully uploaded for organization %s. Bucket is %s, key is %s."
        % (local_file_path, org_uuid, config.aws_s3_bucket, key)
    )
    return config.aws_s3_bucket, key


@websight_app.task(bind=True, base=ServiceTask)
def screenshot_web_service(self, web_service_uuid=None, org_uuid=None, web_service_scan_uuid=None):
    """
    Take screenshots of all the relevant endpoints for the given web service.
    :param web_service_uuid: The UUID of the web service to take screenshots for.
    :param org_uuid: The UUID of the organization that owns the web service.
    :param web_service_scan_uuid: The UUID of the scan that this screenshotting is being done in.
    :return: None
    """
    logger.info(
        "Now taking screenshots of all relevant endpoints for web service %s. Organization is %s, scan is %s."
        % (web_service_uuid, org_uuid, web_service_scan_uuid)
    )
    url_paths = get_url_paths_to_screenshot(
        service_uuid=web_service_uuid,
        db_session=self.db_session,
        scan_uuid=web_service_scan_uuid,
    )
    logger.info(
        "A total of %s URL paths remain to be screenshotted for web service %s."
        % (len(url_paths), web_service_uuid)
    )
    task_sigs = []
    for url_path in url_paths:
        task_sigs.append(screenshot_web_service_url.si(
            web_service_uuid=web_service_uuid,
            org_uuid=org_uuid,
            web_service_scan_uuid=web_service_scan_uuid,
            url_path=url_path,
        ))
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=ServiceTask)
def screenshot_web_service_url(self, web_service_uuid=None, org_uuid=None, web_service_scan_uuid=None, url_path=None):
    """
    Record a screenshot for the given web service and the given URL path.
    :param web_service_uuid: The UUID of the web service to screenshot.
    :param org_uuid: The UUID of the organization to collect the screenshot on behalf of.
    :param web_service_scan_uuid: The UUID of the scan that this screenshot is being taken for.
    :param url_path: The URL path to request.
    :return: None
    """
    logger.info(
        "Now screenshotting URL path of %s for web service %s. Organization is %s, scan is %s."
        % (url_path, web_service_uuid, org_uuid, web_service_scan_uuid)
    )
    screenshotter = HttpScreenshotter()
    ip_address, port, hostname, use_ssl = get_endpoint_information_for_web_service(
        web_service_uuid=web_service_uuid,
        db_session=self.db_session,
    )
    file_path, was_successful = screenshotter.screenshot_endpoint(
        ip_address=ip_address,
        port=port,
        use_ssl=use_ssl,
        hostname=hostname,
        in_separate_process=False,
    )
    if not was_successful:
        logger.warning(
            "Screenshotting endpoint for service %s at URL path %s failed."
            % (web_service_uuid, url_path)
        )
        return
    logger.info(
        "Screenshot taken successfully (file path %s). Now uploading to S3."
        % (file_path,)
    )
    bucket, key = upload_screenshot_to_s3(org_uuid=org_uuid, local_file_path=file_path)
    screenshot_model = screenshotter.to_es_model(model_uuid=web_service_scan_uuid, db_session=self.db_session)
    screenshot_model.set_s3_attributes(bucket=bucket, key=key, file_type="http screenshot")
    screenshot_model.save(index=org_uuid)
    screenshotter.clean_up()
    logger.info(
        "Successfully took screenshot of service %s at path %s for organization %s. Scan is %s."
        % (web_service_uuid, url_path, org_uuid, web_service_scan_uuid)
    )
