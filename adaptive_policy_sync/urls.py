"""adaptive_policy_sync URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import include
from rest_framework import routers
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.schemas import get_schema_view
from rest_framework.renderers import JSONOpenAPIRenderer
from sync import views
from . import views as apsyncviews
from scripts.dashboard_webhook_handler import process_webhook
from scripts.dashboard_simulator import parse_url as meraki_parse_url
from scripts.ise_ers_simulator import parse_url as ise_parse_url
# import adaptive_policy_sync.tasks   # noqa: F401
from django.contrib.staticfiles.urls import staticfiles_urlpatterns


router = routers.DefaultRouter()
router.register(r'uploadzip', views.UploadZipViewSet)
router.register(r'upload', views.UploadViewSet)
router.register(r'organization', views.OrganizationViewSet)
router.register(r'dashboard', views.DashboardViewSet)
router.register(r'iseserver', views.ISEServerViewSet)
# router.register(r'isematrix', views.ISEMatrixViewSet)
# router.register(r'syncsession', views.SyncSessionViewSet)
# router.register(r'tag', views.TagViewSet)
# router.register(r'acl', views.ACLViewSet)
# router.register(r'policy', views.PolicyViewSet)
# router.register(r'tagdata', views.TagDataViewSet)
# router.register(r'acldata', views.ACLDataViewSet)
# router.register(r'policydata', views.PolicyDataViewSet)
router.register(r'task', views.TaskViewSet)

schema_view = get_schema_view(title="Adaptive Policy Sync API", renderer_classes=[JSONOpenAPIRenderer])

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    path('api/v0/schema/', schema_view),
    path('webhook/', process_webhook),
    path(r'api/v0/', include(router.urls)),
    path('', apsyncviews.dolanding, name='landing'),
    path('adaptivepolicy/', apsyncviews.dolanding, name='landing'),
    path('login/', apsyncviews.MyLoginView.as_view(), name='login'),
    path('logout/', apsyncviews.MyLogoutView.as_view(), name='logout'),
    re_path(r'^orgs/$', apsyncviews.getmerakiorgs, name='getmerakiorgs'),
    re_path(r'^isecheck/$', apsyncviews.doisecheck, name='isecheck'),
    re_path(r'^resync/$', apsyncviews.startresync, name='startresync'),
    re_path(r'^del/', apsyncviews.delobject, name='delobject'),
    re_path(r'^setup/$', apsyncviews.setup, name='setup'),
    re_path(r'^setup/ise$', apsyncviews.setupise, name='setupise'),
    re_path(r'^setup/isenext$', apsyncviews.setupisenext, name='setupisenext'),
    re_path(r'^setup/isecert$', apsyncviews.setupcert, name='setupisecert'),
    re_path(r'^setup/isepxgrid$', apsyncviews.setuppxgrid, name='setupisepxgrid'),
    re_path(r'^setup/meraki$', apsyncviews.setupmeraki, name='setupmeraki'),
    re_path(r'^setup/sync$', apsyncviews.setupsync, name='setupsync'),
    re_path(r'^setup/done$', apsyncviews.setupdone, name='setupdone'),
    # re_path(r'^home$', apsyncviews.home, name='home'),
    path('home/', apsyncviews.home, name='home'),
    re_path(r'^home/status-obj$', apsyncviews.objstatus, name='objstatus'),
    # re_path(r'^home/status-sgt$', apsyncviews.sgtstatus, name='sgtstatus'),
    # re_path(r'^home/sgtsave$', apsyncviews.sgtsave, name='sgtsave'),
    re_path(r'^home/objsave$', apsyncviews.objsave, name='objsave'),
    re_path(r'^home/status-elm-sync$', apsyncviews.elmsyncstatus, name='elmsyncstatus'),
    # re_path(r'^home/status-sync$', apsyncviews.syncstatus, name='syncstatus'),
    # re_path(r'^home/status-sgacl$', apsyncviews.sgaclstatus, name='sgaclstatus'),
    # re_path(r'^home/status-policy$', apsyncviews.policystatus, name='policystatus'),
    re_path(r'^home/status-obj-data$', apsyncviews.objdata, name='objdata'),
    # re_path(r'^home/status-sgt-data$', apsyncviews.sgtdata, name='sgtdata'),
    # re_path(r'^home/status-sgacl-data$', apsyncviews.sgacldata, name='sgacldata'),
    # re_path(r'^home/status-policy-data$', apsyncviews.policydata, name='policydata'),
    re_path(r'^home/upload-cert$', apsyncviews.certupload, name='certupload'),
    re_path(r'^home/config-cert$', apsyncviews.certconfig, name='certconfig'),
    re_path(r'^home/config-ise$', apsyncviews.iseconfig, name='iseconfig'),
    re_path(r'^home/config-meraki$', apsyncviews.merakiconfig, name='merakiconfig'),
    re_path(r'^home/config-elm-sync$', apsyncviews.elmsyncconfig, name='elmsyncconfig'),
    # re_path(r'^home/config-sync$', apsyncviews.syncconfig, name='syncconfig'),
    re_path(r'^home/backup-restore$', apsyncviews.backuprestore, name='backuprestore'),
    re_path(r'^meraki/api/v1/organizations', meraki_parse_url, name='dashboardorgs'),
    re_path(r'^ise/ers/config/', ise_parse_url, name='isetrustsec'),
    re_path(r'api/v0/backup', views.Backup.as_view()),
    re_path(r'api/v0/restore', views.Restore.as_view()),
    re_path(r'^home/trbl-data$', apsyncviews.trbl_data, name='trbldata'),
    re_path(r'^home/trbl-logs$', apsyncviews.trbl_logs, name='trbllogs'),
    re_path(r'^home/trbl-admin$', apsyncviews.trbl_admin, name='trbladmin'),
    re_path(r'^home/trbl-tech$', apsyncviews.trbl_tech, name='trbltech'),
    re_path(r'^home/trbl-load$', apsyncviews.trbl_load, name='trblload'),
]

urlpatterns += staticfiles_urlpatterns()
