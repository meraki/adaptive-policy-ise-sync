from rest_framework import viewsets
from sync.serializers import UploadZipSerializer, UploadSerializer, DashboardSerializer, ISEServerSerializer, \
    SyncSessionSerializer, TagSerializer, ACLSerializer, PolicySerializer, TaskSerializer
from sync.models import UploadZip, Upload, Dashboard, ISEServer, SyncSession, Tag, ACL, Policy, Task
from django.db.models import Q
from rest_framework.views import APIView
from scripts.db_backup import backup
from scripts.db_restore import restore
from django.http import JsonResponse
import os


class UploadZipViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Uploaded ZIP files to be viewed, edited or deleted.

    retrieve:
    Return an Uploaded ZIP File instance.

    list:
    Return all Uploaded ZIP files.
    """
    queryset = UploadZip.objects.all().order_by('description')
    serializer_class = UploadZipSerializer


class UploadViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Uploaded files to be viewed, edited or deleted.

    retrieve:
    Return an Uploaded File instance.

    list:
    Return all Uploaded files.
    """
    queryset = Upload.objects.all().order_by('description')
    serializer_class = UploadSerializer


class DashboardViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Meraki Dashboard instances to be viewed, edited or deleted.

    retrieve:
    Return a Meraki Dashboard instance.

    list:
    Return all Meraki Dashboard instances.
    """
    queryset = Dashboard.objects.all().order_by('last_update')
    serializer_class = DashboardSerializer


class ISEServerViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows ISE Server instances to be viewed, edited or deleted.

    retrieve:
    Return an ISE Server instance.

    list:
    Return all ISE Server instances.
    """
    queryset = ISEServer.objects.all().order_by('last_update')
    serializer_class = ISEServerSerializer


# class ISEMatrixViewSet(viewsets.ModelViewSet):
#     """
#     API endpoint that allows ISE Matrix instances to be viewed, edited or deleted.
#
#     retrieve:
#     Return an ISE Matrix instance.
#
#     list:
#     Return all ISE Matrix instances.
#     """
#     queryset = ISEMatrix.objects.all()
#     serializer_class = ISEMatrixSerializer


class SyncSessionViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Sync Session instances to be viewed, edited or deleted.

    retrieve:
    Return a Sync Session instance.

    list:
    Return all Sync Session instances.
    """
    queryset = SyncSession.objects.all().order_by('last_update')
    serializer_class = SyncSessionSerializer


class TagViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows tags (SGTs) to be viewed, edited or deleted.

    retrieve:
    Return a tag (SGT).

    list:
    Return all tags (SGTs).
    """
    queryset = Tag.objects.all().order_by('last_update')
    serializer_class = TagSerializer

    def get_queryset(self):
        """
        Optionally restricts the returned elements
        """
        queryset = Tag.objects.all()
        parm0 = self.request.query_params.get('tag', None)
        if parm0 is not None:
            queryset = queryset.filter(tag_number__iexact=parm0)

        return queryset


class ACLViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows ACLs (SGACLs) to be viewed, edited or deleted.

    retrieve:
    Return an ACL (SGACL).

    list:
    Return all ACLs (SGACLs).
    """
    queryset = ACL.objects.all().order_by('last_update')
    serializer_class = ACLSerializer


class PolicyViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows TrustSec policies to be viewed, edited or deleted.

    retrieve:
    Return a policy.

    list:
    Return all policies.
    """
    queryset = Policy.objects.all().order_by('last_update')
    serializer_class = PolicySerializer

    def get_queryset(self):
        """
        Optionally restricts the returned elements
        """
        queryset = Policy.objects.all()
        parm0 = self.request.query_params.get('tag', None)
        if parm0 is not None:
            rq1 = "^" + parm0 + "-"
            rq2 = "-" + parm0 + "$"
            queryset = queryset.filter(Q(mapping__iregex=rq1) | Q(mapping__iregex=rq2))

        return queryset


class TaskViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows System Tasks to be viewed.

    retrieve:
    Return a task.

    list:
    Return all tasks.
    """
    queryset = Task.objects.all().order_by('last_update')
    serializer_class = TaskSerializer


class Backup(APIView):
    def post(self, request):
        ret = backup()
        return JsonResponse({"filename": ret})


class Restore(APIView):
    def post(self, request):
        fn = request.data.get('filename', None)
        if not fn:
            return JsonResponse({"success": False, "error": "You must POST the filename in JSON format. Example: {"
                                                            "'filename': '20200703-220624.json'}"})
        try:
            filepath = os.path.join("config", fn)
            restore(filepath)
            return JsonResponse({"success": True})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})
