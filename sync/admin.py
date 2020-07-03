from django.contrib import admin
from sync.models import UploadZip, Upload, Dashboard, ISEServer, SyncSession, Tag, ACL, Policy, Task


class DashboardAdmin(admin.ModelAdmin):
    readonly_fields = ('raw_data', 'last_update', 'last_sync')


class ISEServerAdmin(admin.ModelAdmin):
    readonly_fields = ('raw_data', 'last_update', 'last_sync')


class TagAdmin(admin.ModelAdmin):
    readonly_fields = ('cleaned_name', 'last_update', 'last_update_data', 'match_report', 'push_delete', 'update_dest',
                       'sourced_from', 'last_update_state', 'meraki_ver', 'ise_ver', 'needs_update')


class ACLAdmin(admin.ModelAdmin):
    readonly_fields = ('last_update', 'last_update_data', 'match_report', 'push_delete', 'update_dest',
                       'visible', 'sourced_from', 'last_update_state', 'meraki_ver', 'ise_ver', 'needs_update')


class PolicyAdmin(admin.ModelAdmin):
    readonly_fields = ('last_update', 'last_update_data', 'match_report', 'push_delete', 'update_dest',
                       'sourced_from', 'last_update_state', 'meraki_ver', 'ise_ver', 'needs_update')


class SyncSessionAdmin(admin.ModelAdmin):
    readonly_fields = ('last_update', )


class UploadAdmin(admin.ModelAdmin):
    readonly_fields = ('filedata', 'fspath', 'filename', 'systemcert')


class TaskAdmin(admin.ModelAdmin):
    readonly_fields = ('task_data', 'last_update')


admin.site.register(UploadZip)
admin.site.register(Upload, UploadAdmin)
admin.site.register(Dashboard, DashboardAdmin)
admin.site.register(ISEServer, ISEServerAdmin)
# admin.site.register(ISEMatrix)
admin.site.register(SyncSession, SyncSessionAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(ACL, ACLAdmin)
admin.site.register(Policy, PolicyAdmin)
admin.site.register(Task, TaskAdmin)
