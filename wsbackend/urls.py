"""wsbackend URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from rest_framework import routers
from rest_framework.schemas import get_schema_view
from rest_framework_swagger.views import get_swagger_view

from rest import views

schema_view = get_schema_view(title="Web Sight REST API")
swagger_view = get_swagger_view(title="Web Sight REST API")

handler404 = views.custom404

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [

    # Organization URLs

    url(r'^organizations/(?P<pk>[-\w]+)/orders/?$', views.OrdersByOrganizationView.as_view(), name="organizationorder-list"), #TESTED
    url(r'^organizations/(?P<pk>[-\w]+)/es/domain-names/analytics/?$', views.OrganizationDomainNameReportAnalyticsAPIView.as_view(), name="organizationdomainnamereport-analytics"),
    url(r'^organizations/(?P<pk>[-\w]+)/es/domain-names/?$', views.OrganizationDomainNameReportListAPIView.as_view(), name="organizationdomainnamereport-list"),
    url(r'^organizations/(?P<pk>[-\w]+)/es/ssl-support/analytics/?$', views.OrganizationSslSupportReportAnalyticsAPIView.as_view(), name="organizationsslsupport-analytics"),
    url(r'^organizations/(?P<pk>[-\w]+)/es/ssl-support/?$', views.OrganizationSslSupportReportListAPIView.as_view(), name="organizationsslsupport-list"),
    url(r'^organizations/(?P<pk>[-\w]+)/permissions/?$', views.organization_permissions, name="organizationpermission-details"),
    url(r'^organizations/(?P<pk>[-\w]+)/users/?$', views.OrganizationUserAdminAPIView.as_view(), name="organizationuser-admin"),
    url(r'^organizations/(?P<pk>[-\w]+)/networks/upload/?$', views.upload_networks_file, name="orgnetworks-upload"),
    url(r'^organizations/(?P<pk>[-\w]+)/networks/?$', views.NetworksByOrganizationView.as_view(), name="orgnetworks-list"),
    url(r'^organizations/(?P<pk>[-\w]+)/domain-names/upload/?$', views.DomainsUploadAPIView.as_view(), name="orgdomainnames-upload"),
    url(r'^organizations/(?P<pk>[-\w]+)/domain-names/?$', views.DomainNamesByOrganizationView.as_view(), name="orgdomainnames-list"),
    # url(r'^organizations/(?P<pk>[-\w]+)/es/web-tech-reports/analytics/?$', views.OrganizationWebTechReportAnalyticsAPIView.as_view(), name="organizationwebtechreport-analytics"),
    # url(r'^organizations/(?P<pk>[-\w]+)/es/web-tech-reports/?$', views.OrganizationWebTechReportListAPIView.as_view(), name="organizationwebtechreport-list"),
    # url(r'^organizations/(?P<pk>[-\w]+)/es/web-transactions/analytics/?$', views.OrganizationWebTransactionAnalyticsAPIView.as_view(), name="organizationwebtransaction-analytics"),
    # url(r'^organizations/(?P<pk>[-\w]+)/es/web-transactions/?$', views.OrganizationWebTransactionListAPIView.as_view(), name="organizationwebtransaction-list"),
    # url(r'^organizations/(?P<pk>[-\w]+)/es/web-screenshots/?$', views.OrganizationWebScreenshotsListAPIView.as_view(), name="organizationwebscreenshot-list"),
    url(r'^organizations/(?P<pk>[-\w]+)/es/web-services/analytics/?$', views.OrganizationWebServiceReportAnalyticsAPIView.as_view(), name="organizationwebreport-analytics"),
    url(r'^organizations/(?P<pk>[-\w]+)/es/web-services/?$', views.OrganizationWebServiceReportListAPIView.as_view(), name="organizationwebreport-list"),
    url(r'^organizations/(?P<pk>[-\w]+)/?$', views.OrganizationDetailView.as_view(), name="organization-detail"),
    url(r'^organizations/?$', views.OrganizationListView.as_view(), name="organization-list"),

    # Order URLs

    url(r'^orders/(?P<pk>[-\w]+)/scan-config/?$', views.OrderScanConfigDetailView.as_view(), name="order-scan-config-detail"),
    url(r'^orders/(?P<pk>[-\w]+)/place/?$', views.place_order, name="order-place"),
    url(r'^orders/(?P<pk>[-\w]+)/?$', views.OrderDetailView.as_view(), name="order-detail"),
    url(r'^orders/?$', views.OrderListView.as_view(), name="order-list"),

    # Web Service URLs

    url(r'^web-services/(?P<pk>[-\w]+)/es/resources/analytics/?$', views.WebServiceResourceAnalyticsAPIView.as_view(), name="webserviceresource-analytics"),
    url(r'^web-services/(?P<pk>[-\w]+)/es/resources/?$', views.WebServiceResourceListAPIView.as_view(), name="webserviceresource-list"),
    url(r'^web-services/(?P<pk>[-\w]+)/es/http-screenshots/?$', views.WebServiceScreenshotListAPIView.as_view(), name="webservicescreenshot-list"),
    # url(r'^web-services/(?P<pk>[-\w]+)/es/http-transactions/analytics/?$', views.WebServiceHttpTransactionAnalyticsAPIView.as_view(), name="webservicetransaction-analytics"),
    # url(r'^web-services/(?P<pk>[-\w]+)/es/http-transactions/?$', views.WebServiceHttpTransactionListAPIView.as_view(), name="webservicetransaction-list"),
    url(r'^web-services/(?P<pk>[-\w]+)/?$', views.WebServiceReportDetailAPIView.as_view(), name="webservice-detail"),

    # SSL Support URLs

    url(r'^ssl-support/(?P<pk>[-\w]+)/related-services/?$', views.NetworkServiceSslSupportRelatedAPIView.as_view(), name="sslsupportrelation-list"),
    url(r'^ssl-support/(?P<pk>[-\w]+)/?$', views.SslSupportReportDetailAPIView.as_view(), name="sslsupport-detail"),

    # Pre-authentication URLs

    url(r'^api-token-auth/?$', views.WsObtainAuthToken.as_view()),
    url(r'^api-check-token-auth/?$', views.WsCheckAuthTokenStatus.as_view()),
    url(r'^verify-email/?$', views.VerifyEmailView.as_view()),
    url(r'^forgot-password/?$', views.ForgotPasswordView.as_view()),
    url(r'^verify-forgot-password/?$', views.VerifyForgotPasswordView.as_view()),
    url(r'^log-out/?$', views.LogoutView.as_view()),
    url(r'^setup-account/?$', views.SetupAccountView.as_view()),
    url(r'^users/?$', views.UserCreateView.as_view()),

    url('^docs/?$', views.SwaggerSchemaView.as_view(), name="swagger-detail"),

    # Admin URLs

    url(r'^admin/manage-users/?$', views.AdminManageUsersView.as_view()),
    url(r'^admin/manage-users/enable-disable/?$', views.AdminManageUsersEnableDisableView.as_view()),
    url(r'^admin/manage-users/delete-user/?$', views.AdminManageUsersDeleteUserView.as_view()),
    url(r'^admin/manage-users/resend-verification-email/?$', views.AdminManageUsersResendVerificationEmailView.as_view()),

    # Network URLs

    url(r'^networks/(?P<pk>[-\w]+)/?$', views.NetworkDetailView.as_view(), name="network-detail"),
    url(r'^networks/?$', views.NetworkListView.as_view(), name="network-list"),

    # Domain Name URLs

    url(r'^domain-names/(?P<pk>[-\w]+)/es/report/?$', views.DomainNameReportDetailAPIView.as_view(), name="domainreport-detail"),
    url(r'^domain-names/(?P<pk>[-\w]+)/?$', views.DomainNameDetailView.as_view(), name="domain-detail"),
    url(r'^domain-names/?$', views.DomainNameListView.as_view(), name="domain-list"),

    # Account URLs

    url(r'^account/change-password/?$', views.AccountChangePasswordView.as_view()),

    ### ABOVE HERE CONFIRMED NECESSARY

    # organization urls
    # url(r'^organizations/(?P<pk>[-\w]+)/networks/upload-range/$', views.OrganizationNetworkRangeFileUploadView.as_view(),
    #     name="organizationnetwork-upload-range"),
    # url(r'^organizations/(?P<pk>[-\w]+)/domain-names/upload-range/$', views.OrganizationDomainNameRangeFileUploadView.as_view(),
    #     name="organization-domain-name-upload-range"),
    # url(r'^organizations/(?P<pk>[-\w]+)/domain-names/$', views.DomainNamesByOrganizationView.as_view(),
    #     name="domainnamesbyorganization-list"),

    # url(r'^web-services/$', views.WebServiceListView.as_view(), name="webservice-list"),

    # Web Service Scan URLs

    # url(r'^web-service-scans/(?P<pk>[-\w]+)/transactions/analytics/$', views.WebServiceScanTransactionAnalyticsAPIView.as_view(), name="webservicescantransactions-analytics"),
    # url(r'^web-service-scans/(?P<pk>[-\w]+)/transactions/$', views.WebServiceScanTransactionListAPIView.as_view(), name="webservicescantransactions-list"),
    # url(r'^web-service-scans/(?P<pk>[-\w]+)/screenshots/$', views.WebServiceScanScreenshotsListAPIView.as_view(), name="webservicescanscreenshots-list"),
    # url(r'^web-service-scans/(?P<pk>[-\w]+)/header-report/$', views.WebServiceScanHeaderReportAPIView.as_view(), name="webservicescanheaderreport-detail"),
    # url(r'^web-service-scans/(?P<pk>[-\w]+)/tech-report/$', views.WebServiceScanTechReportAPIView.as_view(), name="webservicescantechreport-detail"),
    # url(r'^web-service-scans/(?P<pk>[-\w]+)/$', views.WebServiceScanDetailView.as_view(), name="webservicescan-detail"),

    # network urls
    # url(r'^networks/include/$', views.OrganizationNetworkIncludeView.as_view(), name="organizationnetwork-include"),
    # url(r'^networks/(?P<pk>[-\w]+)/$', views.OrganizationNetworkDetailView.as_view(), name="organizationnetwork-detail"),
    # url(r'^networks/$', views.OrganizationNetworkListView.as_view(), name="organizationnetwork-list"),

    # domain name urls
    # url(r'^domain-names/include/$', views.OrganizationDomainNameIncludeView.as_view(), name="organization-domain-name-include"),
    # url(r'^domain-names/(?P<pk>[-\w]+)/$', views.OrganizationDomainNameDetailView.as_view(),
    #     name="organization-domain-name-detail"),
    # url(r'^domain-names/$', views.OrganizationDomainNameListView.as_view(), name="organization-domain-name-list"),

    # account urls


    # public urls
    # url('^schema/$', schema_view),


    url(r'^sa/', include(admin.site.urls)),
]
