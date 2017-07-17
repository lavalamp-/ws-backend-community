# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models
from django.db.models import Count, Sum, F
from django.utils import timezone
from datetime import timedelta

from rest_framework.exceptions import ValidationError

from .base import BaseWsModel
from lib import ConfigManager, FilesystemHelper

config = ConfigManager.instance()


class OrganizationManager(models.Manager):
    """
    This is a manager class for handling operations around creation of organization models.
    """

    def create(self, **kwargs):
        """
        Create the organization and all of the necessary related objects.
        :param kwargs: Keyword arguments to pass to the create method.
        :return: The newly-created organization.
        """
        organization = super(OrganizationManager, self).create(**kwargs)
        organization.auth_groups.set(self.__create_auth_groups())
        organization.scan_ports.set(self.__create_scan_ports())
        organization.org_config = self.__create_organization_config()
        return organization

    def __create_auth_groups(self):
        """
        Create the WsAuthGroup objects to associate with newly-created organizations and return them.
        :return: A list of WsAuthGroup objects.
        """
        from .auth import WsAuthGroup
        return [
            WsAuthGroup.objects.create(name="org_read"),
            WsAuthGroup.objects.create(name="org_write"),
            WsAuthGroup.objects.create(name="org_scan"),
            WsAuthGroup.objects.create(name="org_admin"),
        ]

    def __create_organization_config(self):
        """
        Create and return the default organization configuration object to associate with the
        organization.
        :return: The default config object to associate with the organization.
        """
        return OrganizationConfig()

    def __create_scan_ports(self):
        """
        Get a list of ScanPort objects representing the default ports that should be scanned for
        this organization.
        :return: A list of ScanPort objects representing the default ports that should be scanned for
        this organization.
        """
        contents = FilesystemHelper.get_file_contents(path=config.files_default_scan_ports_path)
        contents = [x.strip() for x in contents.strip().split("\n")]
        ports = []
        for line in contents:
            line_split = [x.strip() for x in line.split(",")]
            ports.append((int(line_split[0]), line_split[1]))
        to_return = []
        for port_number, protocol in ports:
            to_return.append(ScanPort.objects.create(
                port_number=port_number,
                protocol=protocol,
            ))
        return to_return


class Organization(BaseWsModel):
    """
    This is a class for representing an organization that is being scanned.
    """

    # Management

    objects = OrganizationManager()

    # Columns

    name = models.CharField(max_length=32)
    description = models.CharField(max_length=256, null=True)

    SCANNING_STATUS_TYPES = (
        ('on', 'On'),
        ('off', 'Off'),
        ('ton', 'Turning On'),
        ('toff', 'Turning Off'),
    )

    scanning_status = models.CharField(max_length=64, default='off', choices=SCANNING_STATUS_TYPES, null=False, blank=False)

    # Foreign Keys

    # Class Meta

    # Methods

    def add_read_user(self, user):
        """
        Give the given user read permissions for this organization.
        :param user: The user to set permissions for.
        :return: None
        """
        self.read_group.users.add(user)

    def add_write_user(self, user):
        """
        Give the given user write permissions for this organization.
        :param user: The user to set permissions for.
        :return: None
        """
        self.add_read_user(user)
        self.write_group.users.add(user)

    def add_scan_user(self, user):
        """
        Give the given user scan permissions for this organization.
        :param user: The user to set permissions for.
        :return: None
        """
        self.add_write_user(user)
        self.scan_group.users.add(user)

    def add_admin_user(self, user):
        """
        Give the given user administrative permissions for this organization.
        :param user: The user to set permissions for.
        :return: None
        """
        self.add_scan_user(user)
        self.admin_group.users.add(user)

    def can_user_admin(self, user):
        """
        Check to see if the given user can administer this organization.
        :param user: The user to check for.
        :return: True if the given user can administer this organization, False otherwise.
        """
        return self.admin_group.users.filter(uuid=user.uuid).count() > 0

    def can_user_read(self, user):
        """
        Check to see if the given user can read data from this organization.
        :param user: The user to check for.
        :return: True if the given user can read data from this organization, False otherwise.
        """
        return self.read_group.users.filter(uuid=user.uuid).count() > 0

    def can_user_scan(self, user):
        """
        Check to see if the given user can run scans on behalf of this organization.
        :param user: The user to check for.
        :return: True if the given user can run scans on behalf of this organization, False otherwise.
        """
        return self.scan_group.users.filter(uuid=user.uuid).count() > 0

    def can_user_write(self, user):
        """
        Check to see if the given user can write data to this organization.
        :param user: The user to check for.
        :return: True if the given user can write data to this organization, False otherwise.
        """
        return self.write_group.users.filter(uuid=user.uuid).count() > 0

    def is_only_auth_user(self, user):
        """
        Check to see whether the given user is the only user associated with all of the authorization
        groups owned by this organization.
        :param user: The user to check.
        :return: True if the given user is the only user associated with all authorization groups owned
        by this organization, False otherwise.
        """
        auth_users = self.auth_users
        return user in auth_users and len(auth_users) == 1

    def is_user_only_admin(self, user):
        """
        Check to see whether the given user is the only administrative user associated with this
        organization.
        :param user: The user to check against.
        :return: True if the given user is the only administrative user for this organization,
        False otherwise.
        """
        return self.can_user_admin(user) and self.admin_group.users.count() == 1

    def remove_user(self, user):
        """
        Remove the given user from all authorization groups associated with this organization.
        :param user: The user to remove.
        :return: None
        """
        self.read_group.users.remove(user)
        self.write_group.users.remove(user)
        self.admin_group.users.remove(user)
        self.scan_group.users.remove(user)

    def set_user_permissions(self, user=None, permission_level=None):
        """
        Set the permissions for the given user to the given permission level.
        :param user: The user to set permissions for.
        :param permission_level: The permission level to associate the user with.
        :return: None
        """
        if permission_level not in ["read", "write", "scan", "admin"]:
            raise ValidationError(
                "%s is not a valid permission level (expected read, write, scan, or admin)."
                % (permission_level,)
            )
        self.remove_user(user)
        if permission_level == "read":
            self.add_read_user(user)
        elif permission_level == "write":
            self.add_write_user(user)
        elif permission_level == "scan":
            self.add_scan_user(user)
        elif permission_level == "admin":
            self.add_admin_user(user)

    def update_monitored_times_scanned(self):
        """
        Update all of the objects currently monitored by this organization to show that
        they have been scanned one more time and that the current time is their most recent scan
        time.
        :return: None
        """
        self.monitored_domains.update(
            last_scan_time=timezone.now(),
            times_scanned=F("times_scanned") + 1,
        )
        self.monitored_networks.update(
            last_scan_time=timezone.now(),
            times_scanned=F("times_scanned") + 1,
        )

    # Properties

    @property
    def admin_group(self):
        """
        Get the WsAuthGroup associated with this Organization that contains users that have administrative
         permissions.
        :return: the WsAuthGroup associated with this Organization that contains users that have
        administrative permissions.
        """
        return self.auth_groups.filter(name="org_admin").get()

    @property
    def available_scan_credits_count(self):
        """
        Get the number of scan credits that are currently available to use to scan this organization.
        :return: the number of scan credits that are currently available to use to scan this organization.
        """
        return max(0, config.scan_credits_per_period - self.time_period_invocations.count())

    @property
    def auth_users(self):
        """
        Get a list containing all of the users found in any of the authorization groups associated
        with this organization.
        :return: a list containing all of the users found in any of the authorization groups associated
        with this organization.
        """
        to_return = []
        to_return.extend(self.admin_group.users.all())
        to_return.extend(self.read_group.users.all())
        to_return.extend(self.write_group.users.all())
        to_return.extend(self.scan_group.users.all())
        return list(set(to_return))

    @property
    def domains_count(self):
        """
        Get the number of domains owned by this organization.
        :return: the number of domains owned by this organization.
        """
        return self.domain_names.count()

    @property
    def ip_addresses(self):
        """
        Get a QuerySest containing all of the IP addresses associated with this organization.
        :return: A QuerySest containing all of the IP addresses associated with this organization.
        """
        from .networks import IpAddress
        return IpAddress.objects.filter(network__organization__uuid=self.uuid).all()

    @property
    def last_scan_invocation(self):
        """
        Get the most recent scan invocation associated with this organization.
        :return: the most recent scan invocation associated with this organization.
        """
        return self.scan_invocations.order_by("-created").first()

    @property
    def last_scan_time(self):
        """
        Get the time at which the most recent scan for this organization was started.
        :return: the time at which the most recent scan for this organization was started.
        """
        return self.last_scan_invocation.created if self.last_scan_invocation else None

    @property
    def monitored_domains(self):
        """
        Get the domain names owned by this organization that are in-scope for scanning.
        :return: the domain names owned by this organization that are in-scope for scanning.
        """
        return self.domain_names.filter(scanning_enabled=True).all()

    @property
    def monitored_domains_count(self):
        """
        Get the number of domains owned by this organization that are currently enabled for scanning.
        :return: the number of domains owned by this organization that are currently enabled for scanning.
        """
        return self.monitored_domains.count()

    @property
    def monitored_networks(self):
        """
        Get the networks owned by this organization that are currently configured to be monitored.
        :return: the networks owned by this organization that are currently configured to be monitored.
        """
        return self.networks.filter(added_by="user").filter(scanning_enabled=True).all()

    @property
    def monitored_networks_count(self):
        """
        Get the number of networks owned by this organization that are currently configured to be monitored.
        :return: the number of networks owned by this organization that are currently configured to be monitored.
        """
        return self.monitored_networks.count()

    @property
    def monitored_networks_size(self):
        """
        Get the total number of IP addresses within all of the networks currently configured to be
        monitored in this organization.
        :return: the total number of IP addresses within all of the networks currently configured to
        be monitored in this organization.
        """
        if self.monitored_networks_count == 0:
            return 0
        else:
            return self.monitored_networks.aggregate(Sum("endpoint_count"))["endpoint_count__sum"]

    @property
    def monitored_network_service_count(self):
        """
        Get the number of network services associated with this organization that are
        currently being monitored.
        :return: the number of network services associated with this organization that are
        currently being monitored.
        """
        return self.networks\
            .filter(ip_addresses__network_services__is_monitored=True)\
            .values("ip_addresses__network_services__uuid")\
            .count()

    @property
    def networks_count(self):
        """
        Get the number of networks associated with this organization.
        :return: the number of networks associated with this organization.
        """
        return self.networks.filter(added_by="user").count()

    @property
    def network_services(self):
        """
        Get a QuerySet containing all of the network services associated with this organization.
        :return: a QuerySet containing all of the network services associated with this organization.
        """
        from .services import NetworkService
        return NetworkService.objects.filter(ip_address__network__organization__uuid=self.uuid).all()

    @property
    def networks_size(self):
        """
        Get the total number of endpoints across all networks owned by this organization.
        :return: the total number of endpoints across all networks owned by this organization.
        """
        if self.networks_count == 0:
            return 0
        else:
            return self.networks.filter(added_by="user").aggregate(Sum("endpoint_count"))["endpoint_count__sum"]

    @property
    def network_service_count(self):
        """
        Get the number of network services associated with this organization.
        :return: the number of network services associated with this organization.
        """
        return self.networks.values("ip_addresses__network_services__uuid").count()

    @property
    def next_credit_available_time(self):
        """
        Get the time at which the next scanning credit associated with this organization
        will be available.
        :return: the time at which the next scanning credit associated with this organization
        will be available.
        """
        if self.available_scan_credits_count > 0:
            return timezone.now()
        else:
            time_diff = timedelta(seconds=config.scan_credit_period)
            return self.last_scan_invocation.created + time_diff

    @property
    def read_group(self):
        """
        Get the WsAuthGroup associated with this Organization that contains users that have read permissions.
        :return: the WsAuthGroup associated with this Organization that contains users that have read permissions.
        """
        return self.auth_groups.filter(name="org_read").get()

    @property
    def ready_for_scan(self):
        """
        Get whether or not this Organization is currently ready to be scanned.
        :return: whether or not this Organization is currently ready to be scanned.
        """
        return (self.monitored_networks_count > 0 and self.monitored_networks_size > 0) \
            or self.monitored_domains_count > 0

    @property
    def scan_group(self):
        """
        Get the WsAuthGroup associated with this Organization that contains users that have scan permissions.
        :return: the WsAuthGroup associated with this Organization that contains users that have scan permissions.
        """
        return self.auth_groups.filter(name="org_scan").get()

    @property
    def time_period_invocations(self):
        """
        Get a list of the ScanInvocations owned by this organization that were created within the
        configured scan credit time period.
        :return: a list of the ScanInvocations owned by this organization that were created within
        the configured scan credit time period.
        """
        start_time = timezone.now() - timedelta(seconds=config.scan_credit_period)
        return self.scan_invocations.filter(created__range=(start_time, timezone.now()))

    @property
    def unmonitored_network_service_count(self):
        """
        Get the number of network services associated with this organization that are
        not currently being monitored.
        :return: the number of network services associated with this organization that are
        not currently being monitored.
        """
        return self.networks \
            .filter(ip_addresses__network_services__is_monitored=False) \
            .values("ip_addresses__network_services__uuid") \
            .count()

    @property
    def web_services(self):
        """
        Get a list of the WebService objects that are owned by this organization.
        :return: A list of the WebService objects that are owned by this organization.
        """
        from .web import WebService
        return WebService.objects.filter(network_service__ip_address__network__organization__uuid=self.uuid).all()

    @property
    def write_group(self):
        """
        Get the WsAuthGroup associated with this Organization that contains users that have write permissions.
        :return: the WsAuthGroup associated with this Organization that contains users that have write permissions.
        """
        return self.auth_groups.filter(name="org_write").get()

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.name, self.uuid)


class OrganizationConfig(BaseWsModel):
    """
    This is a class for configuration details about a particular organization.
    """

    # Columns

    name = models.CharField(max_length=32)
    network_scan_interval = models.IntegerField(default=86400)
    network_service_scan_interval = models.IntegerField(default=7200)

    # Foreign Keys

    organization = models.OneToOneField(
        Organization,
        related_name="org_config",
        on_delete=models.CASCADE,
        null=True,
    )


class OrganizationNetworkScan(BaseWsModel):
    """
    This is a class for representing a scan of all the networks associated with a given
    organization.
    """

    # Columns

    started_at = models.DateTimeField(null=False)
    ended_at = models.DateTimeField(null=True)

    # Foreign Keys

    organization = models.ForeignKey(
        Organization,
        related_name="network_scans",
        on_delete=models.CASCADE,
        null=True,
    )


class ScanPort(BaseWsModel):
    """
    This is a class for representing the ports that are being monitored for a given organization.
    """

    # Columns

    port_number = models.IntegerField(null=False)
    protocol = models.CharField(max_length=5, null=False)
    added_by = models.CharField(max_length=16, default="default")
    included = models.BooleanField(null=False, default=True)

    # Foreign Keys

    organization = models.ForeignKey(
        Organization,
        related_name="scan_ports",
        on_delete=models.CASCADE,
        null=True,
    )

