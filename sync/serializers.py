from rest_framework import serializers
from sync.models import UploadZip, Upload, Dashboard, ISEServer, SyncSession, Tag, ACL, Policy, Task, Organization,\
    TagData, ACLData, PolicyData


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
            include_raw = request.GET.get('raw_data', "false")
            if include_raw.lower() == "false":
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
            self.fields['organization_detail'] = OrganizationSerializer(source='organization', many=True,
                                                                        read_only=True,
                                                                        context={"request": request})
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
            include_raw = request.GET.get('raw_data', "false")
            if include_raw.lower() == "false":
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


class DataTagSerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)
    origin_ise_detail = ISEServerSerializer(source='origin_ise', many=False, read_only=True)
    origin_org_detail = OrganizationSerializer(source='origin_org', many=False, read_only=True)

    class Meta:
        model = Tag
        fields = ('id', 'url', 'name', 'description', 'do_sync', 'syncsession', 'tag_number', 'origin_ise',
                  'origin_ise_detail', 'origin_org', 'origin_org_detail', 'push_delete')
        read_only_fields = ('id', 'url', 'syncsession', 'tag_number', 'origin_ise', 'origin_org', 'push_delete')

    def __init__(self, *args, **kwargs):
        super(DataTagSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, context={"request": request})
            self.fields['origin_ise_detail'] = ISEServerSerializer(source='origin_ise', many=False, read_only=True,
                                                                   context={"request": request})
            self.fields['origin_org_detail'] = OrganizationSerializer(source='origin_org', many=False, read_only=True,
                                                                      context={"request": request})
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("origin_ise_detail")
                self.fields.pop("origin_org_detail")
                self.fields.pop("push_delete")


class TagDataSerializer(serializers.ModelSerializer):
    iseserver_detail = ISEServerSerializer(source='iseserver', many=False, read_only=True)
    organziation_detail = OrganizationSerializer(source='organization', many=False, read_only=True)
    tag_detail = DataTagSerializer(source='tag', many=False, read_only=True)

    class Meta:
        model = TagData
        fields = ('id', 'tag', 'tag_detail', 'iseserver', 'iseserver_detail', 'organization', 'organziation_detail',
                  'source_id', 'source_data', 'source_ver', 'last_sync', 'update_failed', 'last_update',
                  'last_update_data', 'last_update_state')
        read_only_fields = ('id', 'tag', 'tag_detail', 'iseserver', 'iseserver_detail', 'organization',
                            'organziation_detail', 'source_id', 'source_data', 'source_ver', 'last_sync',
                            'update_failed', 'last_update', 'last_update_data', 'last_update_state')

    def __init__(self, *args, **kwargs):
        super(TagDataSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['iseserver_detail'] = ISEServerSerializer(allow_null=True, many=False, read_only=True,
                                                                  required=False, source='iseserver',
                                                                  context={"request": request})
            self.fields['organziation_detail'] = OrganizationSerializer(allow_null=True, many=False, read_only=True,
                                                                        required=False, source='organization',
                                                                        context={"request": request})
            if "tagdata" not in request.get_full_path():
                self.fields.pop("tag_detail")
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("last_update_data")
                self.fields.pop("iseserver_detail")
                self.fields.pop("organziation_detail")
                if "tag_detail" in self.fields:
                    self.fields.pop("tag_detail")
            include_raw = request.GET.get('raw_data', "false")
            if include_raw.lower() == "false":
                self.fields.pop("source_data")


class TagSerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)
    origin_ise_detail = ISEServerSerializer(source='origin_ise', many=False, read_only=True)
    origin_org_detail = OrganizationSerializer(source='origin_org', many=False, read_only=True)
    tagdata_set = TagDataSerializer(read_only=True, many=True)

    class Meta:
        model = Tag
        fields = ('id', 'url', 'name', 'description', 'do_sync', 'syncsession', 'tag_number', 'origin_ise',
                  'origin_ise_detail', 'origin_org', 'origin_org_detail', 'push_delete', 'tagdata_set')
        read_only_fields = ('id', 'url', 'syncsession', 'tag_number', 'origin_ise', 'origin_org', 'push_delete')

    def __init__(self, *args, **kwargs):
        super(TagSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['tagdata_set'] = TagDataSerializer(allow_null=True, many=True, read_only=True,
                                                           required=False, context={"request": request})
            self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, context={"request": request})
            self.fields['origin_ise_detail'] = ISEServerSerializer(source='origin_ise', many=False, read_only=True,
                                                                   context={"request": request})
            self.fields['origin_org_detail'] = OrganizationSerializer(source='origin_org', many=False, read_only=True,
                                                                      context={"request": request})
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("origin_ise_detail")
                self.fields.pop("origin_org_detail")
                self.fields.pop("push_delete")


class DataACLSerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)
    origin_ise_detail = ISEServerSerializer(source='origin_ise', many=False, read_only=True)
    origin_org_detail = OrganizationSerializer(source='origin_org', many=False, read_only=True)

    class Meta:
        model = ACL
        fields = ('id', 'url', 'name', 'description', 'do_sync', 'syncsession', 'origin_ise',
                  'origin_ise_detail', 'origin_org', 'origin_org_detail', 'push_delete', 'acldata_set', 'visible')
        read_only_fields = ('id', 'url', 'syncsession', 'tag_number', 'origin_ise', 'origin_org', 'push_delete')

    def __init__(self, *args, **kwargs):
        super(DataACLSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, context={"request": request})
            self.fields['origin_ise_detail'] = ISEServerSerializer(source='origin_ise', many=False, read_only=True,
                                                                   context={"request": request})
            self.fields['origin_org_detail'] = OrganizationSerializer(source='origin_org', many=False, read_only=True,
                                                                      context={"request": request})
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("origin_ise_detail")
                self.fields.pop("origin_org_detail")
                self.fields.pop("push_delete")


class ACLDataSerializer(serializers.ModelSerializer):
    iseserver_detail = ISEServerSerializer(source='iseserver', many=False, read_only=True)
    organziation_detail = OrganizationSerializer(source='organization', many=False, read_only=True)
    acl_detail = DataACLSerializer(source='acl', many=False, read_only=True)

    class Meta:
        model = ACLData
        fields = ('id', 'acl', 'acl_detail', 'iseserver', 'iseserver_detail', 'organization', 'organziation_detail',
                  'source_id', 'source_data', 'source_ver', 'last_sync', 'update_failed', 'last_update',
                  'last_update_data', 'last_update_state')
        read_only_fields = ('id', 'acl', 'acl_detail', 'iseserver', 'iseserver_detail', 'organization',
                            'organziation_detail', 'source_id', 'source_data', 'source_ver', 'last_sync',
                            'update_failed', 'last_update', 'last_update_data', 'last_update_state')

    def __init__(self, *args, **kwargs):
        super(ACLDataSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['iseserver_detail'] = ISEServerSerializer(allow_null=True, many=False, read_only=True,
                                                                  required=False, source='iseserver',
                                                                  context={"request": request})
            self.fields['organziation_detail'] = OrganizationSerializer(allow_null=True, many=False, read_only=True,
                                                                        required=False, source='organization',
                                                                        context={"request": request})
            if "acldata" not in request.get_full_path():
                self.fields.pop("acl_detail")
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("last_update_data")
                self.fields.pop("iseserver_detail")
                self.fields.pop("organziation_detail")
                if "acl_detail" in self.fields:
                    self.fields.pop("acl_detail")
            include_raw = request.GET.get('raw_data', "false")
            if include_raw.lower() == "false":
                self.fields.pop("source_data")


class ACLSerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)
    origin_ise_detail = ISEServerSerializer(source='origin_ise', many=False, read_only=True)
    origin_org_detail = OrganizationSerializer(source='origin_org', many=False, read_only=True)
    acldata_set = ACLDataSerializer(read_only=True, many=True)

    class Meta:
        model = ACL
        fields = ('id', 'url', 'name', 'description', 'do_sync', 'syncsession', 'origin_ise',
                  'origin_ise_detail', 'origin_org', 'origin_org_detail', 'push_delete', 'acldata_set', 'visible')
        read_only_fields = ('id', 'url', 'syncsession', 'tag_number', 'origin_ise', 'origin_org', 'push_delete')

    def __init__(self, *args, **kwargs):
        super(ACLSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['acldata_set'] = ACLDataSerializer(allow_null=True, many=True, read_only=True,
                                                           required=False, context={"request": request})
            self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, context={"request": request})
            self.fields['origin_ise_detail'] = ISEServerSerializer(source='origin_ise', many=False, read_only=True,
                                                                   context={"request": request})
            self.fields['origin_org_detail'] = OrganizationSerializer(source='origin_org', many=False,
                                                                      read_only=True,
                                                                      context={"request": request})

            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("origin_ise_detail")
                self.fields.pop("origin_org_detail")
                self.fields.pop("push_delete")


class DataPolicySerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)
    origin_ise_detail = ISEServerSerializer(source='origin_ise', many=False, read_only=True)
    origin_org_detail = OrganizationSerializer(source='origin_org', many=False, read_only=True)

    class Meta:
        model = Policy
        fields = ('id', 'url', 'mapping', 'name', 'source_group', 'dest_group', 'acl', 'description', 'do_sync',
                  'syncsession', 'origin_ise', 'origin_ise_detail', 'origin_org', 'origin_org_detail', 'push_delete',
                  'policydata_set')
        read_only_fields = ('id', 'url', 'syncsession', 'tag_number', 'origin_ise', 'origin_ise_detail', 'origin_org',
                            'origin_org_detail', 'push_delete')

    def __init__(self, *args, **kwargs):
        super(DataPolicySerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, context={"request": request})
            self.fields['origin_ise_detail'] = ISEServerSerializer(source='origin_ise', many=False, read_only=True,
                                                                   context={"request": request})
            self.fields['origin_org_detail'] = OrganizationSerializer(source='origin_org', many=False,
                                                                      read_only=True,
                                                                      context={"request": request})

            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("origin_ise_detail")
                self.fields.pop("origin_org_detail")
                self.fields.pop("push_delete")


class PolicyDataSerializer(serializers.ModelSerializer):
    iseserver_detail = ISEServerSerializer(source='iseserver', many=False, read_only=True)
    organization_detail = OrganizationSerializer(source='organization', many=False, read_only=True)
    policy_detail = DataPolicySerializer(source='policy', many=False, read_only=True)

    class Meta:
        model = PolicyData
        fields = ('id', 'policy', 'policy_detail', 'iseserver', 'iseserver_detail', 'organization',
                  'organization_detail',
                  'source_id', 'source_data', 'source_ver', 'last_sync', 'update_failed', 'last_update',
                  'last_update_data', 'last_update_state')
        read_only_fields = ('id', 'policy', 'policy_detail', 'iseserver', 'iseserver_detail', 'organization',
                            'organziation_detail', 'source_id', 'source_data', 'source_ver', 'last_sync',
                            'update_failed', 'last_update', 'last_update_data', 'last_update_state')

    def __init__(self, *args, **kwargs):
        super(PolicyDataSerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['iseserver_detail'] = ISEServerSerializer(allow_null=True, many=False, read_only=True,
                                                                  required=False, source='iseserver',
                                                                  context={"request": request})
            self.fields['organization_detail'] = OrganizationSerializer(allow_null=True, many=False, read_only=True,
                                                                        required=False, source='organization',
                                                                        context={"request": request})
            if "policydata" not in request.get_full_path():
                self.fields.pop("policy_detail")
            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("last_update_data")
                self.fields.pop("iseserver_detail")
                self.fields.pop("organization_detail")
                if "policy_detail" in self.fields:
                    self.fields.pop("policy_detail")
            include_raw = request.GET.get('raw_data', "false")
            if include_raw.lower() == "false":
                self.fields.pop("source_data")


class PolicySerializer(serializers.ModelSerializer):
    syncsession = serializers.PrimaryKeyRelatedField(queryset=SyncSession.objects.all(), allow_null=False,
                                                     required=True)
    origin_ise_detail = ISEServerSerializer(source='origin_ise', many=False, read_only=True)
    origin_org_detail = OrganizationSerializer(source='origin_org', many=False, read_only=True)
    policydata_set = PolicyDataSerializer(read_only=True, many=True)
    acl_detail = ACLSerializer(source='acl', read_only=True, many=True)
    source_group_detail = TagSerializer(source='source_group', read_only=True, many=False)
    dest_group_detail = TagSerializer(source='dest_group', read_only=True, many=False)

    class Meta:
        model = Policy
        fields = ('id', 'url', 'mapping', 'name', 'source_group', 'source_group_detail', 'dest_group',
                  'dest_group_detail', 'acl', 'acl_detail', 'description', 'do_sync',
                  'syncsession', 'origin_ise', 'origin_ise_detail', 'origin_org', 'origin_org_detail', 'push_delete',
                  'policydata_set')
        read_only_fields = ('id', 'url', 'syncsession', 'tag_number', 'origin_ise', 'origin_ise_detail', 'origin_org',
                            'origin_org_detail', 'push_delete')

    def __init__(self, *args, **kwargs):
        super(PolicySerializer, self).__init__(*args, **kwargs)
        if "context" in kwargs:
            request = kwargs['context']['request']
            self.fields['policydata_set'] = PolicyDataSerializer(allow_null=True, many=True, read_only=True,
                                                                 required=False, context={"request": request})
            self.fields['acl_detail'] = ACLSerializer(source='acl', allow_null=True, many=True, read_only=True,
                                                      required=False, context={"request": request})
            self.fields['source_group_detail'] = TagSerializer(source='source_group', allow_null=True, many=False,
                                                               read_only=True, required=False,
                                                               context={"request": request})
            self.fields['dest_group_detail'] = TagSerializer(source='dest_group', allow_null=True, many=False,
                                                             read_only=True, required=False,
                                                             context={"request": request})
            self.fields['syncsession_detail'] = SyncSessionSerializer(allow_null=True, many=False, read_only=True,
                                                                      required=False, context={"request": request})
            self.fields['origin_ise_detail'] = ISEServerSerializer(source='origin_ise', many=False, read_only=True,
                                                                   context={"request": request})
            self.fields['origin_org_detail'] = OrganizationSerializer(source='origin_org', many=False,
                                                                      read_only=True,
                                                                      context={"request": request})

            include_detail = request.GET.get('detail', "false")
            if include_detail.lower() == "false":
                self.fields.pop("origin_ise_detail")
                self.fields.pop("origin_org_detail")
                self.fields.pop("push_delete")
                self.fields.pop("acl_detail")
                self.fields.pop("source_group_detail")
                self.fields.pop("dest_group_detail")


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ('id', 'url', 'description', 'task_data', 'last_update')
        read_only_fields = ('id', 'url', 'description', 'task_data', 'last_update')
