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
from django.urls import path
from django.conf.urls import url, include
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


router = routers.DefaultRouter()
router.register(r'uploadzip', views.UploadZipViewSet)
router.register(r'upload', views.UploadViewSet)
router.register(r'organization', views.OrganizationViewSet)
router.register(r'dashboard', views.DashboardViewSet)
router.register(r'iseserver', views.ISEServerViewSet)
# router.register(r'isematrix', views.ISEMatrixViewSet)
router.register(r'syncsession', views.SyncSessionViewSet)
router.register(r'tag', views.TagViewSet)
router.register(r'acl', views.ACLViewSet)
router.register(r'policy', views.PolicyViewSet)
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
    path('login/', apsyncviews.MyLoginView.as_view(), name='login'),
    path('logout/', apsyncviews.MyLogoutView.as_view(), name='logout'),
    url(r'^orgs/$', apsyncviews.getmerakiorgs, name='getmerakiorgs'),
    url(r'^resync/$', apsyncviews.startresync, name='startresync'),
    url(r'^del/', apsyncviews.delobject, name='delobject'),
    url(r'^setup/$', apsyncviews.setup, name='setup'),
    url(r'^setup/ise$', apsyncviews.setupise, name='setupise'),
    url(r'^setup/isenext$', apsyncviews.setupisenext, name='setupisenext'),
    url(r'^setup/isecert$', apsyncviews.setupcert, name='setupisecert'),
    url(r'^setup/isepxgrid$', apsyncviews.setuppxgrid, name='setupisepxgrid'),
    url(r'^setup/meraki$', apsyncviews.setupmeraki, name='setupmeraki'),
    url(r'^setup/sync$', apsyncviews.setupsync, name='setupsync'),
    url(r'^setup/done$', apsyncviews.setupdone, name='setupdone'),
    # url(r'^home$', apsyncviews.home, name='home'),
    path('home/', apsyncviews.home, name='home'),
    url(r'^home/status-sgt$', apsyncviews.sgtstatus, name='sgtstatus'),
    url(r'^home/sgtsave$', apsyncviews.sgtsave, name='sgtsave'),
    url(r'^home/status-sgacl$', apsyncviews.sgaclstatus, name='sgaclstatus'),
    url(r'^home/status-policy$', apsyncviews.policystatus, name='policystatus'),
    url(r'^home/config-cert$', apsyncviews.certconfig, name='certconfig'),
    url(r'^home/config-ise$', apsyncviews.iseconfig, name='iseconfig'),
    url(r'^home/config-meraki$', apsyncviews.merakiconfig, name='merakiconfig'),
    url(r'^home/config-sync$', apsyncviews.syncconfig, name='syncconfig'),
    url(r'^home/backup-restore$', apsyncviews.backuprestore, name='backuprestore'),
    url(r'^meraki/api/v1/organizations', meraki_parse_url, name='dashboardorgs'),
    url(r'^ise/ers/config/', ise_parse_url, name='isetrustsec'),
    url(r'api/v0/backup', views.Backup.as_view()),
    url(r'api/v0/restore', views.Restore.as_view()),
]
