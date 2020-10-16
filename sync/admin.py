from django.contrib import admin
from sync.models import UploadZip, Upload, Dashboard, ISEServer, SyncSession, Tag, ACL, Policy, Task, Organization,\
    TagData, ACLData, PolicyData


class OrganizationAdmin(admin.ModelAdmin):
    readonly_fields = ('raw_data', 'last_update', 'last_sync')


class ISEServerAdmin(admin.ModelAdmin):
    readonly_fields = ('raw_data', 'last_update', 'last_sync')


class TagAdmin(admin.ModelAdmin):
    readonly_fields = ('cleaned_name', 'objects_desc', 'objects_match', 'objects_in_sync', 'object_update_target',
                       'push_delete')


class ACLAdmin(admin.ModelAdmin):
    readonly_fields = ('objects_desc', 'objects_match', 'objects_in_sync', 'object_update_target', 'push_delete')


class PolicyAdmin(admin.ModelAdmin):
    readonly_fields = ('objects_desc', 'objects_match', 'objects_in_sync', 'object_update_target', 'push_delete')


class SyncSessionAdmin(admin.ModelAdmin):
    readonly_fields = ('last_update', )


class UploadAdmin(admin.ModelAdmin):
    readonly_fields = ('filedata', 'fspath', 'filename', 'systemcert')


class TaskAdmin(admin.ModelAdmin):
    readonly_fields = ('task_data', 'last_update')


class TagDataAdmin(admin.ModelAdmin):
    readonly_fields = ('iseserver', 'organization', 'source_id', 'source_data', 'source_ver', 'last_sync',
                       'update_dest', 'last_update', 'last_update_data', 'last_update_state')


class ACLDataAdmin(admin.ModelAdmin):
    readonly_fields = ('iseserver', 'organization', 'source_id', 'source_data', 'source_ver', 'last_sync',
                       'update_dest', 'last_update', 'last_update_data', 'last_update_state')


class PolicyDataAdmin(admin.ModelAdmin):
    readonly_fields = ('iseserver', 'organization', 'source_id', 'source_data', 'source_ver', 'last_sync',
                       'update_dest', 'last_update', 'last_update_data', 'last_update_state')


admin.site.register(UploadZip)
admin.site.register(Upload, UploadAdmin)
admin.site.register(Dashboard)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(ISEServer, ISEServerAdmin)
# admin.site.register(ISEMatrix)
admin.site.register(SyncSession, SyncSessionAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(TagData, TagDataAdmin)
admin.site.register(ACL, ACLAdmin)
admin.site.register(ACLData, ACLDataAdmin)
admin.site.register(Policy, PolicyAdmin)
admin.site.register(PolicyData, PolicyDataAdmin)
admin.site.register(Task, TaskAdmin)
