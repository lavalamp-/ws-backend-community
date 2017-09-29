# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger
import sqlalchemy.orm.exc

from lib import DatetimeHelper
from .base import PubSubTask
from ...app import websight_app
from datetime import datetime
from lib.sqlalchemy import Organization, Order, get_or_create_domain_name_for_organization, OrderDomainName, \
    OrderNetwork, get_or_create_network_for_organization, update_last_scanning_times_for_order
from lib import RegexLib, ConfigManager
from ..scanning import handle_placed_order

logger = get_task_logger(__name__)
config = ConfigManager.instance()


def get_time_since_scanned(to_check):
    """
    Get the amount of time in seconds that has passed since the given object has been scanned.
    :param to_check: The object to check the last scanning time of.
    :return: The amount of time in seconds that has passed since the given object has been scanned.
    """
    if not to_check.last_scan_time:
        return 999999999
    now = datetime.now().replace(tzinfo=to_check.last_scan_time.tzinfo)
    return (now - to_check.last_scan_time).total_seconds()


@websight_app.task(bind=True, base=PubSubTask)
def handle_scanning_order_from_pubsub(self, org_uuid=None, targets=None):
    """
    Create and kick off an order based on the contents of the UUID of the given organization
    and the list of targets to scan.
    :param org_uuid: The UUID of the organization to create the scan for.
    :param targets: A list of the targets to perform the scan on.
    :return: None
    """
    logger.error(
        "HERE WE ARE CHIPPY CHAP: %s, %s"
        % (org_uuid, targets)
    )
    try:
        organization = Organization.by_uuid(uuid=org_uuid, db_session=self.db_session)
    except sqlalchemy.orm.exc.NoResultFound:
        self.pubsub_manager.send_scan_error_message(
            "No organization was found for the UUID %s."
            % (org_uuid,)
        )
        return
    if not organization.scan_config:
        self.pubsub_manager.send_scan_error_message(
            "There was no scanning configuration associated with the organization %s."
            % (org_uuid,)
        )
        return
    self.db_session.execute("begin;")
    self.db_session.begin_nested()

    # Create the order

    admin_group = filter(lambda x: x.name == "org_admin", organization.auth_groups)[0]
    admin_user = admin_group.users[0]
    new_order = Order.new(
        started_at=datetime.now(),
        user_email=admin_user.email,
        scoped_domains_count=0,
        scoped_endpoints_count=0,
        scoped_endpoints_size=0,
        has_been_placed=True,
        organization_id=org_uuid,
        user_id=admin_user.uuid,
    )
    self.db_session.add(new_order)

    # Duplicate the ScanConfig and associate it with the order

    scan_config, new_models = organization.scan_config.duplicate()
    scan_config.order_id = new_order.uuid
    for new_model in new_models:
        self.db_session.add(new_model)

    # Process all of the targets for the order

    skipped_targets = []
    too_soon_targets = []
    domains = []
    networks = []

    for target in targets:
        target = target.strip()
        if RegexLib.domain_name_regex.match(target):
            domain_name = get_or_create_domain_name_for_organization(
                db_session=self.db_session,
                name=target,
                added_by="quick_scan",
                org_uuid=org_uuid,
            )
            self.db_session.add(domain_name)
            time_since_scan = get_time_since_scanned(domain_name)
            if time_since_scan < config.task_domain_scanning_interval:
                too_soon_targets.append(target)
            else:
                new_order_domain = OrderDomainName.new(
                    name=target,
                    order_id=new_order.uuid,
                    domain_name_id=domain_name.uuid,
                )
                self.db_session.add(new_order_domain)
                domains.append(new_order_domain)
        elif RegexLib.ipv4_cidr_regex.match(target):
            address, mask_length = target.split("/")
            mask_length = int(mask_length)
            network = get_or_create_network_for_organization(
                db_session=self.db_session,
                added_by="quick_scan",
                org_uuid=org_uuid,
                address=address,
                mask_length=mask_length,
            )
            self.db_session.add(network)
            time_since_scan = get_time_since_scanned(network)
            if time_since_scan < config.task_network_scanning_interval:
                too_soon_targets.append(target)
            else:
                new_order_network = OrderNetwork.new(
                    network_cidr=target,
                    order_id=new_order.uuid,
                    network_id=network.uuid,
                )
                self.db_session.add(new_order_network)
                networks.append(new_order_network)
        elif RegexLib.ipv4_address_regex.match(target):
            network = get_or_create_network_for_organization(
                db_session=self.db_session,
                added_by="quick_scan",
                org_uuid=org_uuid,
                address=target,
                mask_length=32,
            )
            self.db_session.add(network)
            time_since_scan = get_time_since_scanned(network)
            if time_since_scan < config.task_network_scanning_interval:
                too_soon_targets.append(target)
            else:
                new_order_network = OrderNetwork.new(
                    network_cidr=target,
                    order_id=new_order.uuid,
                    network_id=network.uuid,
                )
                self.db_session.add(new_order_network)
                networks.append(new_order_network)
        else:
            skipped_targets.append(target)

    # Check that everything is good to go and roll back if it's not

    total_count = len(domains) + len(networks)
    if total_count == 0:
        self.db_session.rollback()
        self.pubsub_manager.send_scan_error_message("There were no targets defined for the scan.")
        return

    # Update all of the last scan times for the targets

    self.db_session.commit()
    update_last_scanning_times_for_order(
        order_uuid=new_order.uuid,
        db_session=self.db_session,
        scan_time=DatetimeHelper.now(),
    )

    # Send success message to PubSub

    self.pubsub_manager.send_scan_success_message(
        org_uuid=org_uuid,
        order_uuid=str(new_order.uuid),
        skipped_targets=skipped_targets,
        too_soon_targets=too_soon_targets,
        domains=[x.name for x in domains],
        networks=[x.network_cidr for x in networks],
    )

    # Kick off the order

    # handle_placed_order.delay(order_uuid=unicode(new_order.uuid))
    self.db_session.execute("end;")

