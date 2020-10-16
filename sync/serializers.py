from rest_framework import serializers
from sync.models import UploadZip, Upload, Dashboard, ISEServer, SyncSession, Tag, ACL, Policy, Task, Organization


class UploadZipSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadZip
        fields = ('id', 'url', 'description', 'file', 'uploaded_at')


class UploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Upload
        fields = ('id', 'url', 'description', 'file', 'filename', 'systemcert', 'uploaded_at')


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ('id', 'url', 'orgid', 'raw_data', 'force_rebuild', 'skip_sync',
                  'last_update', 'last_sync')
        read_only_fields = ('id', 'url', 'raw_data', 'last_update', 'last_sync')

    def __init__(self, *args, **kwargs):
        super(OrganizationSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("raw_data")


class DashboardSerializer(serializers.ModelSerializer):
    organization_detail = OrganizationSerializer(source='organization', many=True, read_only=True)

    class Meta:
        model = Dashboard
        fields = ('id', 'url', 'description', 'baseurl', 'apikey', 'organization', 'organization_detail',
                  'force_rebuild', 'last_update', 'last_sync', 'webhook_enable', 'webhook_ngrok', 'webhook_url')
        read_only_fields = ('id', 'url', 'raw_data', 'last_update', 'last_sync')

    def __init__(self, *args, **kwargs):
        super(DashboardSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("organization_detail")


class ISEServerSerializer(serializers.ModelSerializer):
    class Meta:
        model = ISEServer
        fields = ('id', 'url', 'description', 'ipaddress', 'username', 'password', 'raw_data', 'force_rebuild',
                  'skip_sync', 'last_update', 'last_sync', 'pxgrid_enable', 'pxgrid_ip', 'pxgrid_cliname',
                  'pxgrid_clicert', 'pxgrid_clikey', 'pxgrid_clipw', 'pxgrid_isecert')
        read_only_fields = ('id', 'url', 'raw_data', 'last_update', 'last_sync')

    def __init__(self, *args, **kwargs):
        super(ISEServerSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("raw_data")


# class ISEMatrixSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = ISEMatrix
#         fields = ('id', 'url', 'ise_id', 'name', 'iseserver')


class SyncSessionSerializer(serializers.ModelSerializer):
    dashboard = serializers.PrimaryKeyRelatedField(queryset=Dashboard.objects.all(), allow_null=False, required=True)
    iseserver = serializers.PrimaryKeyRelatedField(queryset=ISEServer.objects.all(), allow_null=False, required=True)

    class Meta:
        model = SyncSession
        fields = ('id', 'url', 'description', 'dashboard', 'iseserver', 'ise_source', 'force_rebuild', 'sync_enabled',
                  'apply_changes', 'sync_interval', 'last_update')
        read_only_fields = ('id', 'url', 'last_update', 'last_sync')

    def __init__(self, *args, **kwargs):
        super(SyncSessionSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() != "false":
                self.fields['dashboard_detail'] = DashboardSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, source='dashboard',
                                                                      context={"request": request})
                self.fields['iseserver_detail'] = ISEServerSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, source='iseserver',
                                                                      context={"request": request})


class TagSerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)

    class Meta:
        model = Tag
        fields = ('id', 'url', 'name', 'description', 'do_sync', 'syncsession', 'tag_number', 'meraki_id', 'ise_id',
                  'meraki_data', 'ise_data', 'last_update', 'last_update_data', 'push_delete', 'in_sync',
                  'match_report', 'update_dest', 'needs_update')
        read_only_fields = ('id', 'url', 'meraki_id', 'ise_id', 'meraki_data', 'ise_data', 'last_update',
                            'last_update_data', 'push_delete', 'in_sync', 'match_report', 'update_dest',
                            'cleaned_name', 'needs_update')

    def __init__(self, *args, **kwargs):
        super(TagSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() != "false":
                self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                          required=False, source='syncsession',
                                                                          context={"request": request})
            if include_detail.lower() == "false":
                self.fields.pop("ise_data")
                self.fields.pop("meraki_data")
                self.fields.pop("last_update_data")
                self.fields.pop("match_report")
                self.fields.pop("update_dest")
                self.fields.pop("push_delete")


class ACLSerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)

    class Meta:
        model = ACL
        fields = ('id', 'url', 'name', 'description', 'syncsession', 'meraki_id', 'ise_id', 'meraki_data', 'ise_data',
                  'last_update', 'last_update_data', 'push_delete', 'in_sync', 'match_report', 'is_valid_config',
                  'update_dest', 'visible', 'needs_update')
        read_only_fields = ('id', 'url', 'meraki_id', 'ise_id', 'meraki_data', 'ise_data', 'last_update',
                            'last_update_data', 'push_delete', 'in_sync', 'match_report', 'is_valid_config',
                            'update_dest', 'visible', 'needs_update')

    def __init__(self, *args, **kwargs):
        super(ACLSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() != "false":
                self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                          required=False, source='syncsession',
                                                                          context={"request": request})
            if include_detail.lower() == "false":
                self.fields.pop("ise_data")
                self.fields.pop("meraki_data")
                self.fields.pop("last_update_data")
                self.fields.pop("match_report")
                self.fields.pop("update_dest")
                self.fields.pop("push_delete")


class PolicySerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)

    class Meta:
        model = Policy
        fields = ('id', 'url', 'mapping', 'name', 'syncsession', 'meraki_id', 'ise_id', 'meraki_data', 'ise_data',
                  'last_update', 'last_update_data', 'push_delete', 'in_sync', 'match_report', 'update_dest',
                  'needs_update')
        read_only_fields = ('id', 'url', 'meraki_id', 'ise_id', 'meraki_data', 'ise_data', 'last_update',
                            'last_update_data', 'push_delete', 'in_sync', 'match_report', 'update_dest',
                            'needs_update')

    def __init__(self, *args, **kwargs):
        super(PolicySerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() != "false":
                self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                          required=False, source='syncsession',
                                                                          context={"request": request})
            if include_detail.lower() == "false":
                self.fields.pop("ise_data")
                self.fields.pop("meraki_data")
                self.fields.pop("last_update_data")
                self.fields.pop("match_report")
                self.fields.pop("update_dest")
                self.fields.pop("push_delete")


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ('id', 'url', 'description', 'task_data', 'last_update')
        read_only_fields = ('id', 'url', 'description', 'task_data', 'last_update')
