from django.db import models
import django.utils.timezone
import uuid
import json
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
import datetime
import zipfile
from io import BytesIO
import os
from rest_framework import authentication
import re
import string
from django.db.models import Q
from django.utils.html import format_html
import traceback
from django.db.models.functions import Cast
from scripts.ACEParser import ace_parser
import base64
# from sync import common
from django.db.models.query import QuerySet
from typing import Union, Tuple
from django.utils.timezone import make_aware


def chk_list(lst, exp=None, cst_match=None):
    if cst_match:
        lfind = lst[0]
        lst_comp = [lfind]
        for c in cst_match:
            if lfind in c:
                lst_comp = c
                break
        for litem in lst:
            if litem not in lst_comp:
                return False
        return True
    elif exp:
        return len(set(lst)) == 1 and lst[0] == exp
    else:
        return len(set(lst)) == 1


def htmlprep(json_obj):
    txt = json.dumps(json_obj)
    txt = txt.replace("{", "&#123;").replace("}", "&#125;").replace('"', "&quot;")
    return txt


def json_try_load(strdata, default=None):
    try:
        return json.loads(strdata)
    except Exception:
        return default


def base64encode(value):
    if isinstance(value, dict) or isinstance(value, list):
        message_bytes = json.dumps(value).encode('utf-8')
    elif not isinstance(value, str):
        message_bytes = str(value).encode('utf-8')
    else:
        message_bytes = value.encode('utf-8')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('utf-8')
    return base64_message


class BearerAuthentication(authentication.TokenAuthentication):
    """
    Simple token based authentication using utvsapitoken.

    Clients should authenticate by passing the token key in the 'Authorization'
    HTTP header, prepended with the string 'Bearer '.  For example:

        Authorization: Bearer 1234567890abcdefghijklmnopqrstuvwxyz1234
    """
    keyword = 'Bearer'


class UploadZip(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField(max_length=255, blank=True)
    # file = models.BinaryField(editable=False)
    file = models.FileField(upload_to='upload')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.description

    def filename(self):
        fpath = str(self.file)
        flist = fpath.split(os.path.sep)
        if len(flist) > 0:
            return flist[-1]
        else:
            return str(self.file)

    def base_desc(self):
        fl = self.description.split("-")
        if len(fl) > 0:
            return fl[0]


@receiver(post_save, sender=UploadZip)
def post_save_uploadzip(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_uploadzip, sender=UploadZip)
    if str(instance.file) not in instance.description:
        if instance.description:
            instance.description = instance.description + "-" + str(instance.file)
        else:
            instance.description = "None-" + str(instance.file)

        instance.save()

        unzipped = zipfile.ZipFile(BytesIO(instance.file.read()))
        for libitem in unzipped.namelist():
            if libitem.startswith('__MACOSX/'):
                continue
            fn = "upload/" + libitem
            open(fn, 'wb').write(unzipped.read(libitem))
            i = Upload.objects.create(description=instance.description + "-" + fn, file=fn, uploadzip=instance)
            i.save()

    post_save.connect(post_save_uploadzip, sender=UploadZip)


@receiver(models.signals.post_delete, sender=UploadZip)
def auto_delete_uploadzip_on_delete(sender, instance, **kwargs):
    """
    Deletes file from filesystem
    when corresponding `UploadZip` object is deleted.
    """
    if instance.file:
        if os.path.isfile(instance.file.path):
            os.remove(instance.file.path)


@receiver(models.signals.pre_save, sender=UploadZip)
def auto_delete_uploadzip_on_change(sender, instance, **kwargs):
    """
    Deletes old file from filesystem
    when corresponding `UploadZip` object is updated
    with new file.
    """
    if not instance.pk:
        return False

    try:
        old_file = UploadZip.objects.get(pk=instance.pk).file
    except UploadZip.DoesNotExist:
        return False

    new_file = instance.file
    if not old_file == new_file:
        if os.path.isfile(old_file.path):
            os.remove(old_file.path)


class Upload(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField(max_length=255, blank=True)
    file = models.FileField(upload_to='upload')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploadzip = models.ForeignKey(UploadZip, on_delete=models.CASCADE, null=True, default=None)

    def __str__(self):
        return self.description

    def filedata(self):
        try:
            try:
                return self.file.read().decode("utf-8")
            except Exception:
                return self.file.read()
        except Exception:
            return self.file

    def fspath(self):
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), self.file.name)

    def filename(self):
        fpath = str(self.file)
        flist = fpath.split(os.path.sep)
        if len(flist) > 0:
            return flist[-1]
        else:
            return str(self.file)

    def systemcert(self):
        if "CertificateServices" in str(self.file):
            return True
        else:
            return False

    def base_desc(self):
        fl = self.description.split("-")
        if len(fl) > 0:
            return fl[0]


@receiver(models.signals.post_delete, sender=Upload)
def auto_delete_upload_on_delete(sender, instance, **kwargs):
    """
    Deletes file from filesystem
    when corresponding `Upload` object is deleted.
    """
    if instance.file:
        if os.path.isfile(instance.file.path):
            os.remove(instance.file.path)


@receiver(models.signals.pre_save, sender=Upload)
def auto_delete_upload_on_change(sender, instance, **kwargs):
    """
    Deletes old file from filesystem
    when corresponding `Upload` object is updated
    with new file.
    """
    if not instance.pk:
        return False

    try:
        old_file = Upload.objects.get(pk=instance.pk).file
    except Upload.DoesNotExist:
        return False

    new_file = instance.file
    if not old_file == new_file:
        if os.path.isfile(old_file.path):
            os.remove(old_file.path)


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    orgid = models.CharField("API Organization ID", max_length=32, null=True, blank=True, default=None)
    raw_data = models.JSONField(blank=True, null=False, default=dict)
    force_rebuild = models.BooleanField("Force Dashboard Sync", default=False, editable=True)
    skip_sync = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_sync = models.DateTimeField(null=True, default=None, blank=True)
    last_read = models.DateTimeField(null=True, default=None, blank=True)
    last_processed = models.DateTimeField(null=True, default=None, blank=True)
    manual_dataset = models.BooleanField(default=False)

    def __str__(self):
        dbs = self.dashboard_set.all()
        if len(dbs) == 1:
            return dbs[0].description + " (" + self.orgid + ")"
        return self.orgid

    def get_status(self):
        return "Unknown"

    def base_url(self):
        return self.dashboard_set.first().baseurl


@receiver(post_save, sender=Organization)
def post_save_organization(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_organization, sender=Organization)
    if instance and instance.force_rebuild:
        TagData.objects.filter(organization=instance).update(update_failed=False)
        ACLData.objects.filter(organization=instance).update(update_failed=False)
        PolicyData.objects.filter(organization=instance).update(update_failed=False)
    if instance:
        etype = ElementType.objects.filter(name="MERAKI_ORG").first()
        if created:
            Element.objects.update_or_create(organization=instance,
                                             defaults={"enabled": True,
                                                       "elementtype": etype})
        else:
            Element.objects.update_or_create(organization=instance,
                                             defaults={"enabled": instance.dashboard_set.first().enabled,
                                                       "elementtype": etype})
    post_save.connect(post_save_organization, sender=Organization)


class Dashboard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Dashboard Integration Description", max_length=100, blank=False, null=False)
    baseurl = models.CharField("Base URL", max_length=64, null=False, blank=False,
                               default="https://api.meraki.com/api/v1")
    apikey = models.CharField("API Key", max_length=64, null=True, blank=False)
    enabled = models.BooleanField(default=True, editable=True)
    webhook_enable = models.BooleanField(default=False, editable=True)
    webhook_ngrok = models.BooleanField(default=False, editable=True)
    webhook_url = models.CharField(max_length=200, null=True, blank=True, default=None)
    raw_data = models.JSONField(blank=True, null=False, default=dict)
    organization = models.ManyToManyField(Organization, blank=True)
    force_rebuild = models.BooleanField("Force Dashboard Sync", default=False, editable=True)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_sync = models.DateTimeField(null=True, default=None, blank=True)
    last_read = models.DateTimeField(null=True, default=None, blank=True)
    webhook_reset = models.BooleanField(default=True, editable=True)
    skip_update = models.BooleanField(default=False)

    def __str__(self):
        return self.description

    def is_past_due(self):
        return datetime.date.today() > self.last_sync

    def get_status(self):
        return "Unknown"


@receiver(post_save, sender=Dashboard)
def post_save_dashboard(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_dashboard, sender=Dashboard)
    if instance.force_rebuild:
        Organization.objects.filter(dashboard=instance).update(force_rebuild=True)
        instance.force_rebuild = False
        instance.save()
    if instance:
        if instance.skip_update:
            instance.skip_update = False
        else:
            instance.webhook_reset = True
        instance.save()
        etype = ElementType.objects.filter(name="MERAKI_ORG").first()
        for org in instance.organization.all():
            Element.objects.update_or_create(organization=org,
                                             defaults={"enabled": instance.enabled, "elementtype": etype})

    post_save.connect(post_save_dashboard, sender=Dashboard)


class ISEServer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("ISE Server Description", max_length=100, blank=False, null=False)
    ipaddress = models.CharField("ISE IP or FQDN", max_length=64, null=True, blank=False)
    username = models.CharField(max_length=64, null=True, blank=True, default=None, verbose_name="ERS Username")
    password = models.CharField(max_length=64, null=True, blank=True, default=None, verbose_name="ERS Password")
    raw_data = models.JSONField(blank=True, null=False, default=dict)
    enabled = models.BooleanField(default=True, editable=True)
    force_rebuild = models.BooleanField("Force Server Sync", default=False, editable=True)
    skip_sync = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_sync = models.DateTimeField(null=True, default=None, blank=True)
    pxgrid_enable = models.BooleanField(default=False, editable=True)
    pxgrid_ip = models.CharField("pxGrid Node IP or FQDN", max_length=64, null=True, blank=True, default=None)
    pxgrid_cliname = models.CharField(max_length=64, null=True, blank=True, default=None,
                                      verbose_name="pxGrid Client Name")
    pxgrid_clicert = models.ForeignKey(Upload, on_delete=models.SET_NULL, null=True, blank=True,
                                       verbose_name="pxGrid Client Chain (.cer)", related_name='pxgrid_clicert')
    pxgrid_clikey = models.ForeignKey(Upload, on_delete=models.SET_NULL, null=True, blank=True,
                                      verbose_name="pxGrid Client Key (.key)", related_name='pxgrid_clikey')
    pxgrid_clipw = models.CharField(max_length=64, null=True, blank=True, default=None,
                                    verbose_name="pxGrid Client Key Password")
    pxgrid_isecert = models.ForeignKey(Upload, on_delete=models.SET_NULL, null=True, blank=True,
                                       verbose_name="pxGrid Server Cert (.cer)", related_name='pxgrid_isecert')
    pxgrid_reset = models.BooleanField(default=True, editable=True)
    skip_update = models.BooleanField(default=False)
    last_read = models.DateTimeField(null=True, default=None, blank=True)
    last_processed = models.DateTimeField(null=True, default=None, blank=True)
    manual_dataset = models.BooleanField(default=False)

    class Meta:
        verbose_name = "ISE Server"
        verbose_name_plural = "ISE Servers"

    def __str__(self):
        if self.ipaddress:
            return self.description + " (" + self.ipaddress + ")"
        return self.description

    def base_url(self):
        url = self.ipaddress[:]
        if "http://" not in url and "https://" not in url:
            url = "https://" + url

        if url.count(":") > 1:
            return url
        else:
            return url + ":9060"

    def is_past_due(self):
        return datetime.date.today() > self.last_sync

    def get_status(self):
        return "Unknown"


@receiver(post_save, sender=ISEServer)
def post_save_iseserver(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_iseserver, sender=ISEServer)
    if instance.skip_update:
        instance.skip_update = False
    else:
        instance.pxgrid_reset = True
    instance.save()
    if instance:
        etype = ElementType.objects.filter(name="ISE_SERVER").first()
        Element.objects.update_or_create(iseserver=instance, defaults={"enabled": instance.enabled,
                                                                       "elementtype": etype})
    post_save.connect(post_save_iseserver, sender=ISEServer)


class ISEMatrix(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ise_id = models.CharField(max_length=64, null=False, blank=False)
    name = models.CharField(max_length=64, null=False, blank=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name


# class SyncSession(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     description = models.CharField("Sync Description", max_length=100, blank=False, null=False)
#     # dashboard = models.ForeignKey(Dashboard, on_delete=models.SET_NULL, null=True, blank=True)
#     src_iseserver = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True,
#                                       verbose_name="Source ISE Server")
#     src_organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True,
#                                          verbose_name="Source Meraki Organization")
#     dst_iseserver = models.ManyToManyField(ISEServer, blank=True, verbose_name="Dest. ISE Server",
#                                            related_name="dst_iseserver")
#     dst_organization = models.ManyToManyField(Organization, blank=True, verbose_name="Dest. Meraki Organization",
#                                               related_name="dst_organization")
#     # ise_source = models.BooleanField("Make ISE Config Base", default=True, editable=True)
#     force_rebuild = models.BooleanField("Force All Server Sync", default=False, editable=True)
#     enabled = models.BooleanField("Calculate Sync Requirements", default=True, editable=True)
#     apply_changes = models.BooleanField("Push Changes to Destination(s)", default=True, editable=True)
#     sync_interval = models.IntegerField(blank=False, null=False, default=300)
#     last_update = models.DateTimeField(default=django.utils.timezone.now)
#     reverse_sync = models.BooleanField("Push New Objects in Reverse (dst->src)", default=False, editable=True)
#     last_read = models.DateTimeField(null=True, default=None, blank=True)
#     last_processed = models.DateTimeField(null=True, default=None, blank=True)
#
#     def __str__(self):
#         return self.description
#
#     def get_status(self):
#         return "Unknown"
#
#
# @receiver(pre_save, sender=SyncSession)
# def pre_save_syncsession(sender, instance=None, created=False, **kwargs):
#     pre_save.disconnect(pre_save_syncsession, sender=SyncSession)
#     if instance.src_iseserver and instance.src_organization:
#         return False
#
#     # if instance.force_rebuild:
#     #     instance.force_rebuild = False
#     #     instance.dashboard.force_rebuild = True
#     #     instance.dashboard.save()
#     #     instance.iseserver.force_rebuild = True
#     #     instance.iseserver.save()
#     #     instance.save()
#     pre_save.connect(pre_save_syncsession, sender=SyncSession)
#
#
# @receiver(post_save, sender=SyncSession)
# def post_save_syncsession(sender, instance=None, created=False, **kwargs):
#     post_save.disconnect(post_save_syncsession, sender=SyncSession)
#     # if instance.force_rebuild:
#     #     instance.force_rebuild = False
#     #     instance.dashboard.force_rebuild = True
#     #     instance.dashboard.save()
#     #     instance.iseserver.force_rebuild = True
#     #     instance.iseserver.save()
#     #     instance.save()
#     post_save.connect(post_save_syncsession, sender=SyncSession)
#
#
# class Tag(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     name = models.CharField("Tag Name", max_length=50, blank=False, null=False)
#     description = models.CharField("Tag Description", max_length=200, blank=True, null=False)
#     do_sync = models.BooleanField("Sync this Tag?", default=False, editable=True)
#     syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
#     tag_number = models.IntegerField(blank=False, null=False, default=0)
#     origin_ise = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)
#     origin_org = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
#     push_delete = models.BooleanField(default=False, editable=False)
#
#     class Meta:
#         ordering = ('tag_number',)
#
#     def __str__(self):
#         return self.name + " (" + str(self.tag_number) + ")"
#
#     def get_objects(self):
#         obj_count = 1 + len(self.syncsession.dst_iseserver.all()) + len(self.syncsession.dst_organization.all())
#         return self.tagdata_set.all(), obj_count
#
#     def last_update(self):
#         objs, _ = self.get_objects()
#         lu = None
#         for o in objs:
#             if o.last_update or (lu and o.last_update and o.last_update > lu):
#                 lu = o.last_update
#
#         if not lu:
#             return "Never"
#         return lu
#
#     def objects_desc(self):
#         out = []
#         objects, _ = self.get_objects()
#         for d in objects:
#             out.append(str(d))
#
#         return "\n".join(out)
#
#     def update_success(self):
#         if self.do_sync:
#             if not self.objects_in_sync():
#                 return False
#
#             return True
#
#         return None
#
#     def objects_in_sync(self):
#         return self.objects_match(bool_only=True)
#
#     def object_update_target(self):
#         return self.objects_match(get_target=True)
#
#     def objects_match(self, bool_only=False, get_target=None):
#         full_match = True
#         header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "Pending Delete"]
#         combined_vals = {}
#         f = [""] * len(header)
#         expected_vals = [""] * len(header)
#         match_required = [True] * len(header)
#         for hnum in range(0, len(header)):
#             combined_vals[str(hnum)] = []
#         out = "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
#         objects, cnt = self.get_objects()
#         for o in objects:
#             try:
#                 jo = o.source_data
#                 a0 = o.hyperlink()
#                 a1 = jo.get("name", "UNKNOWN")
#                 a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
#                 a3 = jo.get("description", "UNKNOWN")
#                 a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
#                 a5 = str(o.tag.push_delete)
#
#                 f = [a0, a1, a2, a3, a4, a5]
#                 expected_vals = [None, None, None, None, None, "False"]
#                 match_required = [False, False, True, False, True, True]
#                 for x in range(1, len(header)):
#                     combined_vals[str(x)].append(f[x])
#             except Exception as e:
#                 print("exception", e)
#                 jo = {}
#             out += "<tr><td>" + "</td><td>".join(f) + "</td></tr>"
#
#         out += "<tr><td><i>Matches?</i></td>"
#         for x in range(1, len(header)):
#             matches = chk_list(combined_vals[str(x)], expected_vals[x])
#             if not matches and match_required[x]:
#                 full_match = False
#             out += "<td>" + str(matches) + "</td>"
#         out += "</tr></table>"
#
#         if self.tag_number == 0:
#             out += "<hr><b><u>NOTE:THIS TAG (0) WILL ALWAYS RETURN matches=True. WE DO NOT WANT TO SYNC IT.</b></u>"
#             if bool_only:
#                 return True
#         elif self.tag_number == 2:
#             out += "<hr><b><u>NOTE:THIS TAG (2) WILL ALWAYS RETURN matches=True. WE DO NOT WANT TO SYNC IT.</b></u>"
#             if bool_only:
#                 return True
#
#         if len(objects) != cnt:
#             out += "<hr>ERROR: Expected " + str(cnt) + " objects, found " + str(len(objects)) + " instead!"
#             full_match = False
#
#         if get_target:
#             if not full_match:
#                 if self.origin_ise:
#                     return "meraki"
#                 else:
#                     return "ise"
#             return None
#         elif bool_only:
#             return full_match
#         else:
#             return format_html(out)
#
#     def cleaned_name(self):
#         newname = self.name[:32]
#         newname = re.sub('[^0-9a-zA-Z]+', '_', newname)
#         return newname
#
#     def in_sync(self):
#         return self.objects_match(bool_only=True)
#
#     def is_protected(self):
#         if self.tag_number == 0 or self.tag_number == 2:
#             return True
#         return False
#
#
# @receiver(post_save, sender=Tag)
# def post_save_tag(sender, instance=None, created=False, **kwargs):
#     post_save.disconnect(post_save_tag, sender=Tag)
#     if instance:
#         instance.last_updated = datetime.datetime.now()
#         instance.save()
#
#         policies = Policy.objects.filter(Q(source_group=instance) | Q(dest_group=instance))
#         for p in policies:
#             if p.source_group and p.source_group.do_sync and p.dest_group and p.dest_group.do_sync:
#                 p.do_sync = True
#             else:
#                 p.do_sync = False
#             p.save()
#     post_save.connect(post_save_tag, sender=Tag)
#
#
# class ACL(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     name = models.CharField("Tag Name", max_length=50, blank=False, null=False)
#     description = models.CharField("Tag Description", max_length=100, blank=False, null=False)
#     do_sync = models.BooleanField("Sync this ACL?", default=False, editable=True)
#     syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
#     origin_ise = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)
#     origin_org = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
#     visible = models.BooleanField(default=True, editable=False)
#     push_delete = models.BooleanField(default=False, editable=False)
#
#     class Meta:
#         verbose_name = "ACL"
#         verbose_name_plural = "ACLs"
#
#     def __str__(self):
#         return self.name
#
#     def get_objects(self):
#         obj_count = 1 + len(self.syncsession.dst_iseserver.all()) + len(self.syncsession.dst_organization.all())
#         return self.acldata_set.all(), obj_count
#
#     def last_update(self):
#         objs, _ = self.get_objects()
#         lu = None
#         for o in objs:
#             if o.last_update or (lu and o.last_update and o.last_update > lu):
#                 lu = o.last_update
#
#         if not lu:
#             return "Never"
#         return lu
#
#     def objects_desc(self):
#         out = []
#         objects, _ = self.get_objects()
#         for d in objects:
#             out.append(str(d))
#
#         return "\n".join(out)
#
#     def update_success(self):
#         if self.do_sync and self.visible:
#             if not self.objects_in_sync():
#                 return False
#
#             return True
#
#         return None
#
#     def objects_in_sync(self):
#         return self.objects_match(bool_only=True)
#
#     def object_update_target(self):
#         return self.objects_match(get_target=True)
#
#     def objects_match(self, bool_only=False, get_target=False):
#         full_match = True
#         header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "ACL", "Version",
#                   "Pending Delete"]
#         combined_vals = {}
#         f_show = f_comp = [""] * len(header)
#         expected_vals = [""] * len(header)
#         match_required = [True] * len(header)
#         custom_match_list = [None] * len(header)
#         for hnum in range(0, len(header)):
#             combined_vals[str(hnum)] = []
#         out = "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
#         objects, cnt = self.get_objects()
#         for o in objects:
#             try:
#                 jo = o.source_data
#                 a6 = jo.get("ipVersion", "IP_AGNOSTIC")
#                 a0 = o.hyperlink()
#                 a1 = jo.get("name", "UNKNOWN")
#                 a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
#                 a3 = jo.get("description", "UNKNOWN")
#                 a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
#                 a5_show = htmlprep(jo.get("rules")) if o.organization else jo.get("aclcontent", "")
#                 a5_comp = self.normalize_meraki_rules(jo.get("rules"), mode="convert") if o.organization else \
#                     jo.get("aclcontent")
#                 a7 = str(o.acl.push_delete)
#
#                 f_show = [a0, a1, a2, a3, a4, a5_show, a6, a7]
#                 f_comp = [a0, a1, a2, a3, a4, a5_comp, a6, a7]
#                 expected_vals = [None, None, None, None, None, None, None, "False"]
#                 match_required = [False, False, True, False, True, True, True, True]
#                 custom_match_list[6] = [["agnostic", "IP_AGNOSTIC"], ["ipv4", "IPV4"], ["ipv6", "IPV6"]]
#                 for x in range(1, len(header)):
#                     combined_vals[str(x)].append(f_comp[x])
#             except Exception as e:
#                 print("Exception", e)
#                 jo = {}
#             out += "<tr><td>" + "</td><td>".join(f_show) + "</td></tr>"
#
#         out += "<tr><td><i>Matches?</i></td>"
#         for x in range(1, len(header)):
#             matches = chk_list(combined_vals[str(x)], expected_vals[x], custom_match_list[x])
#             if not matches and match_required[x]:
#                 full_match = False
#             out += "<td>" + str(matches) + "</td>"
#         out += "</tr></table>"
#
#         if not self.visible or self.cleaned_name() in ["Permit_IP", "Permit_IP_Log", "Deny_IP", "Deny_IP_Log"]:
#             out += "<hr><b><u>NOTE:THIS SGACL WILL ALWAYS RETURN matches=True SINCE IT IS BUILT-IN.</b></u>"
#             if bool_only:
#                 return True
#
#         if len(objects) != cnt:
#             out += "<hr>ERROR: Expected " + str(cnt) + " objects, found " + str(len(objects)) + " instead!"
#             full_match = False
#
#         if get_target:
#             if not full_match:
#                 if self.origin_ise:
#                     return "meraki"
#                 else:
#                     return "ise"
#             return None
#         elif bool_only:
#             return full_match
#         else:
#             return format_html(out)
#
#     def cleaned_name(self):
#         newname = self.name[:32]
#         newname = re.sub('[^0-9a-zA-Z]+', '_', newname)
#         return newname
#
#     def in_sync(self):
#         return self.objects_match(bool_only=True)
#
#     def make_port_list(self, port_range):
#         p_list = []
#         if "," in port_range:
#             l_range = port_range.split(",")
#             for l_prt in l_range:
#                 if "-" in l_prt:
#                     r_range = l_prt.split("-")
#                     for x in range(r_range[0], r_range[1]):
#                         p_list.append(x)
#                 else:
#                     p_list.append(l_prt)
#             return "eq " + " ".join(p_list)
#         if "-" in port_range:
#             r_range = port_range.split("-")
#             return "range " + str(r_range[0]) + " " + str(r_range[1])
#
#         return "eq " + str(port_range)
#
#     def normalize_meraki_rules(self, rule_list, mode="compare"):
#         if not rule_list:
#             return ""
#
#         if mode == "compare":
#             outtxt = ""
#             for r in rule_list:
#                 if r["policy"] is None:
#                     return ""
#                 elif r["policy"] == "allow":
#                     outtxt += "permit "
#                 elif r["policy"] == "deny":
#                     outtxt += "deny "
#                 if r["protocol"] == "any":
#                     outtxt += "any"
#                 else:
#                     outtxt += r["protocol"].lower().strip()
#                     if r["srcPort"] != "any":
#                         outtxt += " src " + self.make_port_list(r["srcPort"])
#                     if r["dstPort"] != "any":
#                         outtxt += " dst " + self.make_port_list(r["dstPort"])
#
#                 outtxt = outtxt.strip() + "\n"
#             return outtxt[:-1].strip()
#         elif mode == "convert":
#             outtxt = ""
#             for r in rule_list:
#                 if r["policy"] == "allow":
#                     outtxt += "permit "
#                 elif r["policy"] == "deny":
#                     outtxt += "deny "
#                 if r["protocol"] == "any" or r["protocol"] == "all":
#                     outtxt += "ip"
#                 else:
#                     outtxt += r["protocol"].lower().strip()
#                     if r["srcPort"] != "any":
#                         outtxt += " src " + self.make_port_list(r["srcPort"])
#                     if r["dstPort"] != "any":
#                         outtxt += " dst " + self.make_port_list(r["dstPort"])
#
#                 outtxt = outtxt.strip() + "\n"
#             return outtxt[:-1]
#         return ""
#
#     def normalize_ise_rules(self, rule_str, mode="compare"):
#         if mode == "compare":
#             out_txt = ""
#             out_rule = rule_str.replace(" log", "").strip().replace("ip", "any").replace("all", "any").strip()
#             l_rule = out_rule.split("\n")
#             for l_prt in l_rule:
#                 if "remark" not in l_prt:
#                     out_txt += l_prt + "\n"
#             return out_txt[:-1]
#         elif mode == "convert":
#             outr_list = []
#             lst_rules = rule_str.split("\n")
#             for l_prt in lst_rules:
#                 br_rule = l_prt.split(" ")[1:]
#                 if "permit" in l_prt:
#                     this_pol = "allow"
#                 elif "deny" in l_prt:
#                     this_pol = "deny"
#                 else:
#                     this_pol = None
#
#                 if this_pol and len(br_rule) > 0:
#                     if br_rule[0] == "any" or br_rule[0] == "all" or br_rule[0] == "ip":
#                         this_proto = "any"
#                     else:
#                         this_proto = br_rule[0]
#                     if "src" not in l_prt:
#                         this_src = "any"
#                     else:
#                         s_start = False
#                         s_range = False
#                         the_range = []
#                         for b in br_rule:
#                             if b.lower() == "src":
#                                 s_start = True
#                             elif s_start and b.lower() == "range":
#                                 s_range = True
#                             elif b.lower() == "dst":
#                                 s_start = False
#                             elif s_start and b.lower() != "eq" and b.lower() != "log":
#                                 the_range.append(b)
#                         if s_range and len(the_range) > 1:
#                             this_src = str(the_range[0]) + "-" + str(the_range[1])
#                         else:
#                             this_src = ",".join(the_range)
#                     if "dst" not in l_prt:
#                         this_dst = "any"
#                     else:
#                         d_start = False
#                         d_range = False
#                         the_range = []
#                         for b in br_rule:
#                             if b.lower() == "dst":
#                                 d_start = True
#                             elif d_start and b.lower() == "range":
#                                 d_range = True
#                             elif d_start and b.lower() != "eq" and b.lower() != "log":
#                                 the_range.append(b)
#                         if d_range and len(the_range) > 1:
#                             this_dst = str(the_range[0]) + "-" + str(the_range[1])
#                         else:
#                             this_dst = ",".join(the_range)
#                     outr_list.append({"policy": this_pol, "protocol": this_proto, "srcPort": this_src,
#                                       "dstPort": this_dst})
#             return outr_list
#
#         return ""
#
#     def is_valid_config(self):
#         objs, _ = self.get_objects()
#         for o in objs:
#             if o.iseserver and o.source_data and o.source_id:
#                 idata = o.source_data
#                 test_ise_acl_1 = self.normalize_ise_rules(idata["aclcontent"]).strip().replace("\n", ";")
#                 test_meraki_acl = self.normalize_ise_rules(idata["aclcontent"], mode="convert")
#                 test_ise_acl_2 = self.normalize_meraki_rules(test_meraki_acl,
#                                                              mode="convert").strip().replace("\n", ";")
#                 test_ise_acl_3 = self.normalize_ise_rules(test_ise_acl_2)
#                 ise_valid_config = test_ise_acl_1 == test_ise_acl_3
#                 return ise_valid_config
#         return True
#
#     def is_protected(self):
#         if self.cleaned_name() in ["Permit_IP", "Permit_IP_Log", "Deny_IP", "Deny_IP_Log"] and \
#                 self.acldata_set.all().first().get_data("generationId") in [0, "0"]:
#             return True
#         return False
#
#
# @receiver(post_save, sender=ACL)
# def post_save_acl(sender, instance=None, created=False, **kwargs):
#     post_save.disconnect(post_save_acl, sender=ACL)
#     if instance:
#         instance.last_updated = datetime.datetime.now()
#         instance.save()
#     post_save.connect(post_save_acl, sender=ACL)
#
#
# class Policy(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     mapping = models.CharField("Policy Mapping", max_length=50, blank=False, null=False)
#     name = models.CharField("Policy Name", max_length=100, blank=True, null=True)
#     source_group = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, related_name="source_group")
#     dest_group = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, related_name="dest_group")
#     acl = models.ManyToManyField(ACL, blank=True, related_name="policies")
#     description = models.CharField("Policy Description", max_length=100, blank=True, null=True)
#     do_sync = models.BooleanField("Sync this Policy?", default=False, editable=True)
#     syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
#     origin_ise = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)
#     origin_org = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
#     push_delete = models.BooleanField(default=False, editable=False)
#
#     class Meta:
#         verbose_name_plural = "policies"
#
#     def __str__(self):
#         return str(self.name) + " (" + str(self.mapping) + ")"
#
#     def get_objects(self):
#         obj_count = 1 + len(self.syncsession.dst_iseserver.all()) + len(self.syncsession.dst_organization.all())
#         return self.policydata_set.all(), obj_count
#
#     def last_update(self):
#         objs, _ = self.get_objects()
#         lu = None
#         for o in objs:
#             if o.last_update or (lu and o.last_update and o.last_update > lu):
#                 lu = o.last_update
#
#         if not lu:
#             return "Never"
#         return lu
#
#     def objects_desc(self):
#         out = []
#         objects, _ = self.get_objects()
#         for d in objects:
#             out.append(str(d))
#
#         return "\n".join(out)
#
#     def update_success(self):
#         if self.do_sync:
#             if not self.objects_in_sync():
#                 return False
#
#             return True
#
#         return None
#
#     def objects_in_sync(self):
#         return self.objects_match(bool_only=True)
#
#     def object_update_target(self):
#         return self.objects_match(get_target=True)
#
#     def render_text(self, data, attribute, src_sgt, dst_sgt):
#         txt = data.get(attribute, "UNKNOWN")
#         if txt == "":
#             txt = src_sgt.tag.name + "_" + dst_sgt.tag.name
#         return txt
#
#     def objects_match(self, bool_only=False, get_target=False):
#         full_match = True
#         header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "Source", "Dest",
#                   "Default Rule", "SGACLs", "Pending Delete"]
#         combined_vals = {}
#         f_show = f_comp = [""] * len(header)
#         expected_vals = [""] * len(header)
#         match_required = [True] * len(header)
#         custom_match_list = [None] * len(header)
#         for hnum in range(0, len(header)):
#             combined_vals[str(hnum)] = []
#         out = "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
#         objects, cnt = self.get_objects()
#         for o in objects:
#             try:
#                 jo = o.source_data
#                 src_sgt, dst_sgt = self.lookup_sgts(o)
#                 raw_sgacls = self.lookup_sgacls(o)
#                 sgacls = []
#                 sgacl_ids = []
#                 for a in raw_sgacls or []:
#                     sgacls.append(a.acl.name)
#                     sgacl_ids.append(a.acl.id)
#
#                 a0 = o.hyperlink()
#                 a1 = jo.get("name", "UNKNOWN")
#                 a2 = re.sub('[^0-9a-zA-Z]+', '_', self.render_text(jo, "name", src_sgt, dst_sgt)[:32])
#                 a3 = jo.get("description", "UNKNOWN")
#                 a4 = self.render_text(jo, "description", src_sgt, dst_sgt).translate(str.maketrans('', '', string.punctuation)).lower()
#                 a5 = str(src_sgt.tag.tag_number) if src_sgt else "N/A"
#                 a6 = str(dst_sgt.tag.tag_number) if dst_sgt else "N/A"
#                 a7 = jo.get("catchAllRule", "UNKNOWN") if o.organization else jo.get("defaultRule", "UNKNOWN")
#                 a8 = str(sgacls)
#                 a9 = str(o.policy.push_delete)
#
#                 f_show = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9]
#                 f_comp = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9]
#                 expected_vals = [None, None, None, None, None, None, None, None, None, "False"]
#                 match_required = [False, False, True, False, True, True, True, True, True, True]
#                 custom_match_list[7] = [["global", "NONE"], ["deny all", "DENY_IP"],
#                                         ["allow all", "permit all", "PERMIT_IP"]]
#                 custom_match_list[8] = [["['Permit IP']", "[]"], ["['Deny IP']", "[]"]]
#                 for x in range(1, len(header)):
#                     combined_vals[str(x)].append(f_comp[x])
#             except Exception as e:
#                 print("Exception", e, traceback.format_exc())
#                 jo = {}
#             out += "<tr><td>" + "</td><td>".join(f_show) + "</td></tr>"
#
#         out += "<tr><td><i>Matches?</i></td>"
#         for x in range(1, len(header)):
#             matches = chk_list(combined_vals[str(x)], expected_vals[x], custom_match_list[x])
#             if not matches and match_required[x]:
#                 full_match = False
#             out += "<td>" + str(matches) + "</td>"
#         out += "</tr></table>"
#
#         if len(objects) != cnt:
#             out += "<hr>ERROR: Expected " + str(cnt) + " objects, found " + str(len(objects)) + " instead!"
#             full_match = False
#
#         if get_target:
#             if not full_match:
#                 if self.origin_ise:
#                     return "meraki"
#                 else:
#                     return "ise"
#             return None
#         elif bool_only:
#             return full_match
#         else:
#             return format_html(out)
#
#     def cleaned_name(self):
#         if self.name:
#             newname = self.name[:32]
#         else:
#             newname = "Policy " + self.mapping[:32]
#         newname = re.sub('[^0-9a-zA-Z-]+', '_', newname)
#         return newname
#
#     def lookup_sgts(self, object):
#         if object.source_id and object.source_data:
#             data = object.source_data if object.source_data else {"srcGroupId": "zzz", "dstGroupId": "zzz",
#                                                                   "sourceSgtId": "zzz", "destinationSgtId": "zzz"}
#             if object.organization:
#                 p_src = TagData.objects.filter(organization=object.organization).filter(source_id=data["srcGroupId"])
#                 p_dst = TagData.objects.filter(organization=object.organization).filter(source_id=data["dstGroupId"])
#             else:
#                 p_src = TagData.objects.filter(iseserver=object.iseserver).filter(source_id=data["sourceSgtId"])
#                 p_dst = TagData.objects.filter(iseserver=object.iseserver).filter(source_id=data["destinationSgtId"])
#             if len(p_src) >= 1 and len(p_dst) >= 1:
#                 return p_src[0], p_dst[0]
#
#         return None, None
#
#     def lookup_sgacls(self, object):
#         if object.source_id and object.source_data:
#             data = object.source_data if object.source_data else {"aclIds": [], "sgacls": []}
#             out_acl = []
#             itername = data["aclIds"] if object.organization else data["sgacls"]
#             for s in itername:
#                 if object.organization:
#                     p_acl = ACLData.objects.filter(organization=object.organization).filter(source_id=s)
#                 else:
#                     p_acl = ACLData.objects.filter(iseserver=object.iseserver).filter(source_id=s)
#
#                 if len(p_acl) >= 1:
#                     out_acl.append(p_acl[0])
#             return out_acl
#
#         return None
#
#     def in_sync(self):
#         return self.objects_match(bool_only=True)
#
#     def is_protected(self):
#         if self.cleaned_name() == "ANY-ANY" or self.name == "ANY-ANY" or self.mapping == "ANY-ANY":
#             return True
#         return False
#
#
# @receiver(post_save, sender=Policy)
# def post_save_policy(sender, instance=None, created=False, **kwargs):
#     post_save.disconnect(post_save_policy, sender=Policy)
#     if instance:
#         instance.last_updated = datetime.datetime.now()
#         if instance.source_group and instance.source_group.do_sync and instance.dest_group and \
#                 instance.dest_group.do_sync:
#             instance.do_sync = True
#         instance.save()
#
#         acls = ACL.objects.filter(id__in=instance.acl.all())
#         for a in acls:
#             a.do_sync = True
#             a.save()
#
#         acls = ACL.objects.filter(Q(policies__isnull=True) | Q(policies__do_sync=False))
#         for a in acls:
#             a.do_sync = False
#             a.save()
#
#     post_save.connect(post_save_policy, sender=Policy)


class ElementType(models.Model):
    AUTH_TYPES = [
        (1, 'Bearer/Request Header'),
        (2, 'Basic Auth'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField(max_length=100, blank=True, null=True)
    name = models.CharField(max_length=100, blank=True, null=True)
    auth_type = models.IntegerField(
        choices=AUTH_TYPES,
        default=1,
    )
    token_header_name = models.CharField("(Bearer/Request Header)", max_length=100, blank=True, null=True)
    static_headers = models.JSONField(blank=True, null=False, default=dict)

    def __str__(self):
        return str(self.description)

    def get_auth_name(self):
        for choice in self.AUTH_TYPES:
            if choice[0] == self.auth_type:
                return choice[1]

        return "Unknown"


class Element(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    elementtype = models.ForeignKey(ElementType, on_delete=models.SET_NULL, null=True, blank=True)
    enabled = models.BooleanField(default=True, editable=True)
    force_rebuild = models.BooleanField(default=False, editable=True)
    raw_data = models.JSONField(blank=True, null=False, default=dict)
    last_read = models.DateTimeField(null=True, default=None, blank=True)
    last_processed = models.DateTimeField(null=True, default=None, blank=True)
    manual_dataset = models.BooleanField(default=False)
    sync_interval = models.IntegerField(blank=False, null=False, default=300)

    def __str__(self):
        if self.iseserver:
            out_str = str(self.iseserver)
        elif self.organization:
            out_str = str(self.organization)
        else:
            out_str = str(self.id)
        return out_str      # + " (" + str(self.enabled) + ")"

    def base_url(self):
        if self.organization:
            return self.organization.base_url()
        elif self.iseserver:
            return self.iseserver.base_url()

    def get_api_key(self):
        if self.organization:
            return self.organization.dashboard_set.first().apikey
        return ""

    def get_auth_info(self):
        if self.iseserver:
            return self.iseserver.username, self.iseserver.password
        return "", ""

    def make_url(self, url_template):
        if self.organization:
            return url_template.replace("{{organizationId}}", self.organization.orgid)
        return url_template

    def display_name(self):
        if self.organization:
            return "Meraki Org: " + self.organization.dashboard_set.first().description + " (" +\
                   self.organization.orgid + ")"
        elif self.iseserver:
            return "ISE Server: " + self.iseserver.description

    def needs_resync(self, timer_type, skip_reset=False):
        forced = self.clear_manual_resync(skip_reset)
        if forced is True:
            return True

        due_barrier_time = make_aware(datetime.datetime.now()) - datetime.timedelta(seconds=self.sync_interval)
        if timer_type == "last_read":
            if not self.last_read or self.last_read < due_barrier_time:
                return True
        if timer_type == "last_processed":
            if not self.last_processed or self.last_processed < due_barrier_time:
                return True

        return False

    def clear_manual_resync(self, skip_reset):
        forced = False
        if self.organization:
            forced = self.organization.force_rebuild
            if forced and not skip_reset:
                self.organization.force_rebuild = False
                self.organization.save()
        elif self.iseserver:
            forced = self.iseserver.force_rebuild
            if forced and not skip_reset:
                self.iseserver.force_rebuild = False
                self.iseserver.save()

        if self.force_rebuild:
            forced = True
            if forced and not skip_reset:
                self.force_rebuild = False
                self.save()

        return forced


class ElementSync(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Sync Description", max_length=100, blank=False, null=False)
    src_element = models.ForeignKey(Element, on_delete=models.CASCADE, null=True, blank=True,
                                    verbose_name="Source Element")
    dst_element = models.ManyToManyField(Element, blank=True, verbose_name="Dest. Element",
                                         related_name="dst_element")
    force_rebuild = models.BooleanField("Force All Server Sync", default=False, editable=True)
    enabled = models.BooleanField("Calculate Sync Requirements", default=True, editable=True)
    apply_changes = models.BooleanField("Push Changes to Destination(s)", default=True, editable=True)
    reverse_sync = models.BooleanField("Push New Objects in Reverse (dst->src)", default=False, editable=True)
    auto_sync_new = models.BooleanField("Auto Sync New Objects", default=False, editable=True)
    last_read = models.DateTimeField(null=True, default=None, blank=True)
    last_processed = models.DateTimeField(null=True, default=None, blank=True)
    sync_interval = models.IntegerField(blank=False, null=False, default=300)

    def __str__(self):
        return self.description

    def get_status(self):
        return "Unknown"

    def needs_resync(self, timer_type):
        forced = self.clear_manual_resync()
        if forced is True:
            return True

        due_barrier_time = make_aware(datetime.datetime.now()) - datetime.timedelta(seconds=self.sync_interval)
        if timer_type == "last_read":
            if not self.last_read or self.last_read < due_barrier_time:
                return True
        if timer_type == "last_processed":
            if not self.last_processed or self.last_processed < due_barrier_time:
                return True

        return False

    def clear_manual_resync(self):
        forced = self.force_rebuild
        if forced:
            self.force_rebuild = False
            self.save()

        return forced

    def needs_update(self):
        generics = Generic.objects.filter(elementsync=self).order_by('generictype__type_order', 'key_value')
        change_list = []
        for gen in generics:
            if gen.do_sync:
                m = gen.get_changes(detail=True)
                if m is not None:
                    change_list.append(m)

        # print(change_list)
        if len(change_list) > 0:
            return True, change_list
        else:
            return False, change_list


class Task(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Task Description", max_length=50, blank=False, null=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    # syncsession = models.ForeignKey(SyncSession, on_delete=models.CASCADE, null=True, blank=True)
    element = models.ForeignKey(Element, on_delete=models.CASCADE, null=True, blank=True)
    elementsync = models.ForeignKey(ElementSync, on_delete=models.CASCADE, null=True, blank=True)
    task_data = models.TextField(blank=True, null=True, default=None)
    last_update = models.DateTimeField(default=django.utils.timezone.now)

    def __str__(self):
        if self.iseserver:
            return str(self.last_update) + "::" + self.description + "::" + str(self.iseserver) + "::" + " (" + str(len(
                str(self.task_data))) + ")"
        elif self.organization:
            return str(self.last_update) + "::" + self.description + "::" + str(self.organization) + "::" + " (" + str(
                len(str(self.task_data))) + ")"
        # elif self.syncsession:
        #     return str(self.last_update) + "::" + self.description + "::" + str(self.syncsession) + "::" + " (" + str(
        #         len(str(self.task_data))) + ")"
        elif self.element:
            return str(self.last_update) + "::" + self.description + "::" + str(self.element) + "::" + " (" + str(
                len(str(self.task_data))) + ")"
        elif self.elementsync:
            return str(self.last_update) + "::" + self.description + "::" + str(self.elementsync) + "::" + " (" + str(
                len(str(self.task_data))) + ")"
        else:
            return str(self.last_update) + "::" + self.description + " (" + str(len(str(self.task_data))) + ")"

    class Meta:
        ordering = ('-last_update',)


@receiver(post_save, sender=Task)
def post_save_task(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_task, sender=Task)
    if instance:
        instance.last_updated = datetime.datetime.now()
        instance.save()
    post_save.connect(post_save_task, sender=Task)


# class TagData(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     tag = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, default=None)
#     iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
#     organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
#     source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
#     source_data = models.JSONField(blank=True, null=False, default=dict)
#     source_ver = models.IntegerField(blank=True, null=True, default=None)
#     last_sync = models.DateTimeField(default=None, null=True)
#     update_failed = models.BooleanField(default=False, editable=True)
#     last_update = models.DateTimeField(default=None, null=True)
#     last_update_data = models.TextField(blank=True, null=True, default=None)
#     last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)
#
#     class Meta:
#         verbose_name = "Tag Data"
#         verbose_name_plural = "Tag Data"
#         ordering = ('tag__tag_number', 'organization', 'iseserver')
#
#     def hyperlink(self):
#         # return "<a href='/admin/sync/tagdata/" + str(self.id) + "'>" + str(self) + "</a>"
#         return "<a href='/home/status-sgt-data?id=" + str(self.id) + "'>" + str(self) + "</a>"
#
#     def __str__(self):
#         if self.iseserver:
#             src = str(self.iseserver)
#         elif self.organization:
#             src = str(self.organization)
#         else:
#             src = "Unknown"
#
#         if self.tag:
#             return src + " : " + self.tag.name + " (" + str(self.tag.tag_number) + ")"
#         else:
#             return src + " : " + str(self.get_data("value"))
#
#     def update_dest(self):
#         if self.tag and self.tag.do_sync:
#             if self.tag.push_delete:
#                 if self.tag.syncsession.ise_source:
#                     return "meraki"
#                 else:
#                     return "ise"
#             if self.organization and (self.source_id is None or self.source_id == ""):
#                 return "meraki"
#             if self.iseserver and (self.source_id is None or self.source_id == ""):
#                 return "ise"
#             if not self.tag.in_sync():
#                 if self.tag.syncsession.ise_source:
#                     return "meraki"
#                 else:
#                     return "ise"
#
#         return "none"
#
#     def get_data(self, attrname):
#         if self.source_data:
#             if attrname == "cleaned_name":
#                 return re.sub('[^0-9a-zA-Z]+', '_', self.source_data.get("name", "UNKNOWN")[:32])
#             else:
#                 return self.source_data.get(attrname)
#         return None
#
#     def matches_source(self):
#         full_match = True
#         # header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "Pending Delete"]
#         header = ["Source", "Name", "Description", "Pending Delete"]
#         combined_vals = {}
#         f = [""] * len(header)
#         expected_vals = [""] * len(header)
#         match_required = [True] * len(header)
#         for hnum in range(0, len(header)):
#             combined_vals[str(hnum)] = []
#         out = "<table class='match_table'><tr class='match_tr'><th class='match_th'>" + "</th><th class='match_th'>".join(header) + "</th></tr>"
#
#         objs = []
#         if self.tag and self.tag.origin_org:
#             src_obj = TagData.objects.filter(organization=self.tag.origin_org).\
#                 filter(source_data__value=self.get_data("value")).first()
#             if src_obj:
#                 objs = [self, src_obj]
#         if self.tag and self.tag.origin_ise:
#             src_obj = TagData.objects.filter(iseserver=self.tag.origin_ise).\
#                 filter(source_data__value=self.get_data("value")).first()
#             if src_obj:
#                 objs = [self, src_obj]
#
#         if not objs:
#             return None, "No Source Object Located"
#
#         for o in objs:
#             try:
#                 jo = o.source_data
#                 a0 = o.hyperlink()
#                 # a1 = jo.get("name", "UNKNOWN")
#                 a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
#                 # a3 = jo.get("description", "UNKNOWN")
#                 a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
#                 a5 = str(o.tag.push_delete)
#
#                 f = [a0, a2, a4, a5]
#                 expected_vals = [None, None, None, "False"]
#                 match_required = [False, True, True, True]
#                 for x in range(1, len(header)):
#                     combined_vals[str(x)].append(f[x])
#             except Exception as e:
#                 print("exception", e)
#                 jo = {}
#             out += "<tr class='match_tr'><td class='match_td'>" + "</td><td class='match_td'>".join(f) + "</td></tr>"
#
#         out += "<tr class='match_tr'><td class='match_td'><i>Matches?</i></td>"
#         for x in range(1, len(header)):
#             matches = chk_list(combined_vals[str(x)], expected_vals[x])
#             if not matches and match_required[x]:
#                 full_match = False
#             out += "<td class='match_td'>" + str(matches) + "</td>"
#         out += "</tr></table>"
#
#         if self.get_data("value") == 0:
#             out += "<hr><b><u>NOTE:THIS TAG (0) WILL ALWAYS RETURN matches=True. WE DO NOT WANT TO SYNC IT.</b></u>"
#             return True, format_html(out)
#         elif self.get_data("value") == 2:
#             out += "<hr><b><u>NOTE:THIS TAG (2) WILL ALWAYS RETURN matches=True. WE DO NOT WANT TO SYNC IT.</b></u>"
#             return True, format_html(out)
#
#         # if get_target:
#         #     if not full_match:
#         #         if self.origin_ise:
#         #             return "meraki"
#         #         else:
#         #             return "ise"
#         #     return None
#         # elif bool_only:
#         #     return full_match
#         # else:
#         #     return format_html(out)
#         return full_match, format_html(out)
#
#     def is_protected(self):
#         if self.get_data("value") == 0 or self.get_data("value") == 2:
#             return True
#         return False
#
#     def has_synced(self):
#         if self.tag and self.tag.syncsession.last_processed:
#             return True
#         return False
#
#
# class ACLData(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     acl = models.ForeignKey(ACL, on_delete=models.SET_NULL, null=True, blank=True, default=None)
#     iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
#     organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
#     source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
#     source_data = models.JSONField(blank=True, null=False, default=dict)
#     source_ver = models.IntegerField(blank=True, null=True, default=None)
#     last_sync = models.DateTimeField(default=None, null=True)
#     update_failed = models.BooleanField(default=False, editable=True)
#     last_update = models.DateTimeField(default=None, null=True)
#     last_update_data = models.TextField(blank=True, null=True, default=None)
#     last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)
#
#     class Meta:
#         verbose_name = "ACL Data"
#         verbose_name_plural = "ACL Data"
#
#     def hyperlink(self):
#         # return "<a href='/admin/sync/acldata/" + str(self.id) + "'>" + str(self) + "</a>"
#         return "<a href='/home/status-sgacl-data?id=" + str(self.id) + "'>" + str(self) + "</a>"
#
#     def __str__(self):
#         if self.iseserver:
#             src = str(self.iseserver)
#         elif self.organization:
#             src = str(self.organization)
#         else:
#             src = "Unknown"
#
#         if self.acl:
#             return src + " : " + self.acl.name
#         else:
#             return src + " -- " + self.get_data("name")
#
#     def lookup_version(self, obj):
#         if obj.organization:
#             acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(iseserver=obj.acl.syncsession.iseserver) & Q(source_id__isnull=False))
#             if len(acl) > 0:
#                 source_data = acl[0].source_data
#                 idata = json_try_load(source_data, {})
#                 if "ipVersion" in idata:
#                     return idata["ipVersion"].lower()
#                 else:
#                     return "agnostic"
#         else:
#             acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(organization__in=obj.acl.syncsession.dashboard.organization.all()) & Q(source_id__isnull=False))
#             if len(acl) > 0:
#                 source_data = acl[0].source_data
#                 mdata = json_try_load(source_data, {})
#                 if mdata["ipVersion"] == "agnostic":
#                     return "IP_AGNOSTIC"
#                 else:
#                     return mdata["ipVersion"].upper()
#
#         return None
#
#     def lookup_rules(self, obj):
#         if obj.organization:
#             acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(iseserver=obj.acl.syncsession.iseserver) & Q(source_id__isnull=False))
#             if len(acl) > 0:
#                 source_data = acl[0].source_data
#                 idata = json_try_load(source_data, {})
#                 sgacl = self.acl.normalize_ise_rules(idata["aclcontent"], mode="convert")
#                 return sgacl
#         else:
#             acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(organization__in=obj.acl.syncsession.dashboard.organization.all()) & Q(source_id__isnull=False))
#             if len(acl) > 0:
#                 source_data = acl[0].source_data
#                 mdata = json_try_load(source_data, {})
#                 sgacl = self.acl.normalize_meraki_rules(mdata["rules"], mode="convert")
#                 return sgacl
#
#         return None
#
#     def update_dest(self):
#         if self.acl and self.acl.do_sync:
#             if self.acl.push_delete:
#                 if self.acl.syncsession.ise_source:
#                     return "meraki"
#                 else:
#                     return "ise"
#             if self.organization and (self.source_id is None or self.source_id == ""):
#                 return "meraki"
#             if self.iseserver and (self.source_id is None or self.source_id == ""):
#                 return "ise"
#             if not self.acl.in_sync():
#                 if self.acl.syncsession.ise_source:
#                     return "meraki"
#                 else:
#                     return "ise"
#
#         return "none"
#
#     def get_data(self, attrname):
#         if self.source_data:
#             if attrname == "cleaned_name":
#                 return re.sub('[^0-9a-zA-Z]+', '_', self.source_data.get("name", "UNKNOWN")[:32])
#             else:
#                 return self.source_data.get(attrname)
#         return None
#
#     def matches_source(self):
#         full_match = True
#         header = ["Source", "Name", "Description", "ACL", "Version", "Pending Delete"]
#         combined_vals = {}
#         f_show = f_comp = [""] * len(header)
#         expected_vals = [""] * len(header)
#         match_required = [True] * len(header)
#         custom_match_list = [None] * len(header)
#         for hnum in range(0, len(header)):
#             combined_vals[str(hnum)] = []
#         out = "<table class='match_table'><tr class='match_tr'><th class='match_th'>" + "</th><th class='match_th'>".join(header) + "</th></tr>"
#
#         objs = []
#         src_obj = None
#         if self.acl and self.acl.origin_org:
#             src_objs = ACLData.objects.filter(organization=self.acl.origin_org)
#             for src_obj in src_objs:
#                 if src_obj.cleaned_name() == self.cleaned_name():
#                     break
#
#             if src_obj:
#                 objs = [self, src_obj]
#         if self.acl and self.acl.origin_ise:
#             src_objs = ACLData.objects.filter(iseserver=self.acl.origin_ise)
#             for src_obj in src_objs:
#                 if src_obj.cleaned_name() == self.cleaned_name():
#                     break
#
#             if src_obj:
#                 objs = [self, src_obj]
#
#         if not objs:
#             return None, "No Source Object Located"
#
#         for o in objs:
#             try:
#                 jo = o.source_data
#                 a6 = jo.get("ipVersion", "IP_AGNOSTIC")
#                 a0 = o.hyperlink()
#                 a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
#                 a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
#                 a5_show = htmlprep(jo.get("rules")) if o.organization else jo.get("aclcontent", "")
#                 a5_comp = self.acl.normalize_meraki_rules(jo.get("rules"), mode="convert") if o.organization else \
#                     jo.get("aclcontent")
#                 a7 = str(o.acl.push_delete)
#
#                 f_show = [a0, a2, a4, a5_show, a6, a7]
#                 f_comp = [a0, a2, a4, a5_comp, a6, a7]
#                 expected_vals = [None, None, None, None, None, "False"]
#                 match_required = [False, True, True, True, True, True]
#                 custom_match_list[4] = [["agnostic", "IP_AGNOSTIC"], ["ipv4", "IPV4"], ["ipv6", "IPV6"]]
#                 for x in range(1, len(header)):
#                     combined_vals[str(x)].append(f_comp[x])
#             except Exception as e:
#                 print("Exception", e)
#                 jo = {}
#             out += "<tr class='match_tr'><td class='match_td'>" + "</td><td class='match_td'>".join(f_show) + "</td></tr>"
#
#         out += "<tr class='match_tr'><td class='match_td'><i>Matches?</i></td>"
#         # print(combined_vals)
#         for x in range(1, len(header)):
#             matches = chk_list(combined_vals[str(x)], expected_vals[x], custom_match_list[x])
#             # print(matches, str(x), combined_vals[str(x)], expected_vals[x], custom_match_list[x])
#             if not matches and match_required[x]:
#                 full_match = False
#             out += "<td class='match_td'>" + str(matches) + "</td>"
#         out += "</tr></table>"
#
#         if not self.get_data("generationId") == "0":
#             out = "<hr><b><u>NOTE:THIS SGACL WILL ALWAYS RETURN matches=True SINCE IT IS BUILT-IN.</b></u>"
#             return True, out
#
#         #
#         # if get_target:
#         #     if not full_match:
#         #         if self.origin_ise:
#         #             return "meraki"
#         #         else:
#         #             return "ise"
#         #     return None
#         # elif bool_only:
#         #     return full_match
#         # else:
#         return full_match, format_html(out)
#
#     def cleaned_name(self):
#         if self.source_data:
#             newname = self.get_data("name")
#             if not newname:
#                 return None
#             newname = re.sub('[^0-9a-zA-Z]+', '_', newname[:32])
#             return newname
#         return None
#
#     def is_protected(self):
#         if self.get_data("cleaned_name") in ["Permit_IP", "Permit_IP_Log", "Deny_IP", "Deny_IP_Log"] and \
#                 self.get_data("generationId") in [0, "0"]:
#             return True
#         return False
#
#     def has_synced(self):
#         if self.acl and self.acl.syncsession.last_processed:
#             return True
#         return False
#
#
# class PolicyData(models.Model):
#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     policy = models.ForeignKey(Policy, on_delete=models.SET_NULL, null=True, blank=True, default=None)
#     iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
#     organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
#     source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
#     source_data = models.JSONField(blank=True, null=False, default=dict)
#     source_ver = models.IntegerField(blank=True, null=True, default=None)
#     last_sync = models.DateTimeField(default=None, null=True)
#     update_failed = models.BooleanField(default=False, editable=True)
#     last_update = models.DateTimeField(default=None, null=True)
#     last_update_data = models.TextField(blank=True, null=True, default=None)
#     last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)
#
#     class Meta:
#         verbose_name = "Policy Data"
#         verbose_name_plural = "Policy Data"
#
#     def hyperlink(self):
#         # return "<a href='/admin/sync/policydata/" + str(self.id) + "'>" + str(self) + "</a>"
#         return "<a href='/home/status-policy-data?id=" + str(self.id) + "'>" + str(self) + "</a>"
#
#     def __str__(self):
#         if self.iseserver:
#             src = str(self.iseserver)
#         elif self.organization:
#             src = str(self.organization)
#         else:
#             src = "Unknown"
#
#         if self.policy:
#             return src + " : " + self.policy.mapping
#         else:
#             return src + " -- " + self.get_data("mapping")
#
#     def update_dest(self):
#         if self.policy and self.policy.do_sync:
#             if self.policy.push_delete:
#                 if self.policy.syncsession.ise_source:
#                     return "meraki"
#                 else:
#                     return "ise"
#             if self.organization and (self.source_id is None or self.source_id == ""):
#                 return "meraki"
#             if self.iseserver and (self.source_id is None or self.source_id == ""):
#                 return "ise"
#             if not self.policy.in_sync():
#                 if self.policy.syncsession.ise_source:
#                     return "meraki"
#                 else:
#                     return "ise"
#
#         return "none"
#
#     def lookup_sgacl_data(self, obj):
#         if obj.organization:
#             acl = ACLData.objects.filter(Q(acl__in=obj.policy.acl.all()) & Q(organization=obj.organization) & Q(source_id__isnull=False))
#         else:
#             acl = ACLData.objects.filter(Q(acl__in=obj.policy.acl.all()) & Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
#
#         if len(acl) == len(obj.policy.acl.all()):
#             return acl
#
#         return None
#
#     def lookup_acl_catchall(self, obj, convert=False):
#         if obj.organization or (convert and not obj.organization):
#             src = PolicyData.objects.filter(Q(policy=obj.policy) & Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
#             if len(src) > 0:
#                 source_data = src[0].source_data
#                 idata = json_try_load(source_data, {})
#                 if idata["defaultRule"] == "DENY_IP":
#                     return "deny all"
#                 elif idata["defaultRule"] == "PERMIT_IP":
#                     return "allow all"
#                 elif idata["defaultRule"] == "NONE":
#                     return "global"
#                 else:
#                     return "global"
#         else:
#             src = PolicyData.objects.filter(Q(policy=obj.policy) & Q(organization__in=obj.policy.syncsession.dashboard.organization.all()) & Q(source_id__isnull=False))
#             if len(src) > 0:
#                 source_data = src[0].source_data
#                 mdata = json_try_load(source_data, {})
#                 if mdata["catchAllRule"] == "deny all":
#                     return "DENY_IP"
#                 elif mdata["catchAllRule"] == "allow all" or mdata["catchAllRule"] == "permit all":
#                     return "PERMIT_IP"
#                 elif mdata["catchAllRule"] == "global":
#                     return "NONE"
#                 else:
#                     return "NONE"
#
#         return None
#
#     def lookup_description(self, obj):
#         pdesc = obj.policy.description
#         if not pdesc:
#             pdesc = str(obj.policy.source_group.tag_number) + "-" + str(obj.policy.dest_group.tag_number)
#         return pdesc
#
#     def lookup_sgt_data(self, obj):
#         if obj.organization:
#             src = TagData.objects.filter(Q(tag=obj.policy.source_group) & Q(organization=obj.organization) &
#                                          Q(source_id__isnull=False))
#             dst = TagData.objects.filter(Q(tag=obj.policy.dest_group) & Q(organization=obj.organization) &
#                                          Q(source_id__isnull=False))
#             if len(src) > 0 and len(dst) > 0:
#                 return src[0], dst[0]
#         else:
#             src = TagData.objects.filter(Q(tag=obj.policy.source_group) &
#                                          Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
#             dst = TagData.objects.filter(Q(tag=obj.policy.dest_group) &
#                                          Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
#             if len(src) > 0 and len(dst) > 0:
#                 return src[0], dst[0]
#
#         return None, None
#
#     def get_data(self, attrname):
#         if self.source_data:
#             if attrname == "cleaned_name" or attrname == "cleaned_desc":
#                 nm = self.source_data.get("name") if attrname == "cleaned_name" else self.source_data.get("description")
#                 if not nm:
#                     src = self.get_data("sourcetag")
#                     dst = self.get_data("desttag")
#                     if src and dst:
#                         nm = src.name + "_" + dst.name
#                 return re.sub('[^0-9a-zA-Z]+', '_', nm[:32])
#             elif attrname == "sourcetag":
#                 sid = self.source_data.get("sourceSgtId") if self.iseserver else self.source_data.get("srcGroupId")
#                 if self.iseserver:
#                     srctag = TagData.objects.filter(source_id=sid).filter(iseserver=self.iseserver).first()
#                 else:
#                     srctag = TagData.objects.filter(source_id=sid).filter(organization=self.organization).first()
#                 return srctag.tag if srctag else None
#             elif attrname == "desttag":
#                 did = self.source_data.get("destinationSgtId") if self.iseserver else self.source_data.get("dstGroupId")
#                 if self.iseserver:
#                     dsttag = TagData.objects.filter(source_id=did).filter(iseserver=self.iseserver).first()
#                 else:
#                     dsttag = TagData.objects.filter(source_id=did).filter(organization=self.organization).first()
#                 return dsttag.tag if dsttag else None
#             elif attrname == "mapping":
#                 sid = self.source_data.get("sourceSgtId") if self.iseserver else self.source_data.get("srcGroupId")
#                 did = self.source_data.get("destinationSgtId") if self.iseserver else self.source_data.get("dstGroupId")
#                 if self.iseserver:
#                     srctag = TagData.objects.filter(source_id=sid).filter(iseserver=self.iseserver).first()
#                     dsttag = TagData.objects.filter(source_id=did).filter(iseserver=self.iseserver).first()
#                 else:
#                     srctag = TagData.objects.filter(source_id=sid).filter(organization=self.organization).first()
#                     dsttag = TagData.objects.filter(source_id=did).filter(organization=self.organization).first()
#                 if srctag and dsttag:
#                     return str(srctag.get_data("value")) + "-" + str(dsttag.get_data("value"))
#                 else:
#                     # return str(srctag) + "-" + str(dsttag)
#                     return self.source_data.get("name")
#             elif attrname == "acl":
#                 out_acl = []
#                 lacl = self.source_data.get("sgacls") if self.iseserver else self.source_data.get("aclIds")
#                 for acl in lacl:
#                     if self.iseserver:
#                         acld = ACLData.objects.filter(source_id=acl).filter(iseserver=self.iseserver).first()
#                     else:
#                         acld = ACLData.objects.filter(source_id=acl).filter(organization=self.organization).first()
#                     out_acl.append(acld.acl)
#                 return out_acl
#             return self.source_data.get(attrname)
#         return None
#
#     def matches_source(self):
#         full_match = True
#         header = ["Source", "Name", "Description", "Source", "Dest", "Default Rule", "SGACLs", "Pending Delete"]
#         combined_vals = {}
#         f_show = f_comp = [""] * len(header)
#         expected_vals = [""] * len(header)
#         match_required = [True] * len(header)
#         custom_match_list = [None] * len(header)
#         for hnum in range(0, len(header)):
#             combined_vals[str(hnum)] = []
#         out = "<table class='match_table'><tr class='match_tr'><th class='match_th'>" + "</th><th class='match_th'>".join(header) + "</th></tr>"
#
#         objs = []
#         src_obj = None
#         if self.policy and self.policy.origin_org:
#             src_objs = PolicyData.objects.filter(organization=self.policy.origin_org)
#             for src_obj in src_objs:
#                 if src_obj.get_data("mapping") == self.get_data("mapping"):
#                     break
#
#             if src_obj:
#                 objs = [self, src_obj]
#         if self.policy and self.policy.origin_ise:
#             src_objs = PolicyData.objects.filter(iseserver=self.policy.origin_ise)
#             for src_obj in src_objs:
#                 if src_obj.get_data("mapping") == self.get_data("mapping"):
#                     break
#
#             if src_obj:
#                 objs = [self, src_obj]
#
#         if not objs:
#             return None, "No Source Object Located"
#
#         for o in objs:
#             try:
#                 jo = o.source_data
#                 src_sgt, dst_sgt = self.policy.lookup_sgts(o)
#                 raw_sgacls = self.policy.lookup_sgacls(o)
#                 sgacls = []
#                 sgacl_ids = []
#                 for a in raw_sgacls or []:
#                     sgacls.append(a.acl.name)
#                     sgacl_ids.append(a.acl.id)
#
#                 a0 = o.hyperlink()
#                 # a2 = re.sub('[^0-9a-zA-Z]+', '_', self.render_text(jo, "name", src_sgt, dst_sgt)[:32])
#                 a2 = re.sub('[^0-9a-zA-Z]+', '_', self.get_data("cleaned_name")[:32])
#                 a4 = self.get_data("cleaned_desc").translate(str.maketrans('', '', string.punctuation)).lower()
#                 a5 = str(src_sgt.tag.tag_number) if src_sgt else "N/A"
#                 a6 = str(dst_sgt.tag.tag_number) if dst_sgt else "N/A"
#                 a7 = jo.get("catchAllRule", "UNKNOWN") if o.organization else jo.get("defaultRule", "UNKNOWN")
#                 a8 = str(sgacls)
#                 a9 = str(o.policy.push_delete)
#
#                 f_show = [a0, a2, a4, a5, a6, a7, a8, a9]
#                 f_comp = [a0, a2, a4, a5, a6, a7, a8, a9]
#                 expected_vals = [None, None, None, None, None, None, None, "False"]
#                 match_required = [False, True, True, True, True, True, True, True]
#                 custom_match_list[5] = [["global", "NONE"], ["deny all", "DENY_IP"],
#                                         ["allow all", "permit all", "PERMIT_IP"]]
#                 custom_match_list[6] = [["['Permit IP']", "[]"], ["['Deny IP']", "[]"]]
#                 for x in range(1, len(header)):
#                     combined_vals[str(x)].append(f_comp[x])
#             except Exception as e:
#                 print("Exception", e, traceback.format_exc())
#                 jo = {}
#             out += "<tr class='match_tr'><td class='match_td'>" + "</td><td class='match_td'>".join(f_show) + "</td></tr>"
#
#         out += "<tr class='match_tr'><td class='match_td'><i>Matches?</i></td>"
#         for x in range(1, len(header)):
#             matches = chk_list(combined_vals[str(x)], expected_vals[x], custom_match_list[x])
#             if not matches and match_required[x]:
#                 full_match = False
#             out += "<td class='match_td'>" + str(matches) + "</td>"
#         out += "</tr></table>"
#
#         # if get_target:
#         #     if not full_match:
#         #         if self.origin_ise:
#         #             return "meraki"
#         #         else:
#         #             return "ise"
#         #     return None
#         # elif bool_only:
#         #     return full_match
#         # else:
#         #     return format_html(out)
#         return full_match, format_html(out)
#
#     def is_protected(self):
#         if self.get_data("cleaned_name") == "ANY-ANY" or self.get_data("name") == "ANY-ANY":
#             return True
#         return False
#
#     def has_synced(self):
#         if self.policy and self.policy.syncsession.last_processed:
#             return True
#         return False


class TaskQueue(models.Model):
    STATE_CHOICES = [
        (1, 'New Task'),
        (2, 'Running'),
        (3, 'Task Successfully Ran'),
        (4, 'Task Failed'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Task Description", max_length=50, blank=False, null=False)
    function = models.CharField("App Function", max_length=75, blank=False, null=False)
    data = models.JSONField(blank=True, null=False, default=dict)
    task_data = models.TextField(blank=True, null=True, default=None)
    last_update = models.DateTimeField(auto_now=True)
    priority = models.IntegerField(default=999)
    state = models.IntegerField(
        choices=STATE_CHOICES,
        default=1,
    )
    minimum_interval_secs = models.IntegerField(default=0)
    run_now = models.BooleanField(default=False)

    def __str__(self):
        return str(self.priority) + "::" + str(self.state) + "::" + self.description

    class Meta:
        ordering = ('-last_update',)

    def get_next_run(self):
        return self.last_update + datetime.timedelta(seconds=self.minimum_interval_secs)

    def needs_run(self):
        if django.utils.timezone.now() > self.get_next_run():
            return True
        elif self.run_now:
            return True

        return False


class DataPipeline(models.Model):
    STAGE_CHOICES = [
        (1, 'Ingestion'),
        (2, 'Processing'),
        (3, 'Analysis'),
        (4, 'Synchronization'),
    ]
    STATE_CHOICES = [
        (1, 'N/A'),
        (2, 'Started'),
        (3, 'Skipped'),
        (4, 'Error'),
        (5, 'Success'),
    ]
    STATE_COLOR_MAPPING = [
        (1, 'Gray'),
        (2, 'LightGreen'),
        (3, 'Orange'),
        (4, 'Red'),
        (5, 'Green'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    element = models.ForeignKey(Element, on_delete=models.CASCADE, null=True, blank=True)
    last_update = models.DateTimeField(auto_now=True)
    stage = models.IntegerField(
        choices=STAGE_CHOICES,
        default=1,
    )
    state = models.IntegerField(
        choices=STATE_CHOICES,
        default=1,
    )

    def __str__(self):
        if self.iseserver:
            return str(self.iseserver.description) + "::" + str(self.stage) + "::" + str(self.state)
        elif self.organization:
            return str(self.organization.dashboard_set.first().description) + "::" + str(self.stage) + "::" + str(self.state)
        elif self.element:
            return str(self.element) + "::" + str(self.stage) + "::" + str(self.state)
        else:
            return str(self.id)

    def get_state_name(self):
        for choice in self.STATE_CHOICES:
            if choice[0] == self.state:
                return choice[1]

        return "Unknown"

    def get_state_color(self):
        for choice in self.STATE_COLOR_MAPPING:
            if choice[0] == self.state:
                return choice[1]

        return "Black"


class GenericType(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, blank=False, null=False)
    display_name_key = models.CharField(max_length=50, blank=True, null=True, default=None)
    significant_name_key = models.CharField(max_length=100, blank=True, null=True, default=None)
    significant_key_label = models.CharField(max_length=100, blank=True, null=True, default=None)
    significant_name_restrictions = models.CharField(max_length=100, blank=True, null=True, default=None)
    safe_char_regex = models.CharField(max_length=50, blank=True, null=True, default="[^0-9a-zA-Z]+")
    safe_char_repl = models.CharField(max_length=1, blank=True, null=True, default="_")
    safe_max_len = models.IntegerField(default=32, blank=True)
    safe_max_len_map = models.CharField(max_length=100, blank=True, null=True)
    # linked_fields = models.CharField(max_length=100, blank=True, null=True, default=None)
    has_manual_sync = models.BooleanField(default=False)
    type_order = models.IntegerField(default=0, blank=True)

    def __str__(self):
        return str(self.name)

    def get_max_len(self, key_name=None):
        if not key_name or not self.safe_max_len_map:
            return self.safe_max_len

        mlm_list = self.safe_max_len_map.split(",")
        for mlm in mlm_list:
            ml = mlm.split(":")
            if ml[0] == key_name:
                return int(ml[1])

        return self.safe_max_len


class GenericTypeMatchRule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    generictype = models.ForeignKey(GenericType, on_delete=models.SET_NULL, blank=True, null=True, default=None)
    name = models.CharField(max_length=20, blank=True, null=True, default=None)
    description = models.CharField(max_length=50, blank=True, null=True, default=None)
    # filter_field = models.CharField(max_length=200, blank=False, null=False, default="")
    field = models.CharField(max_length=200, blank=False, null=False)
    match_type = models.CharField(max_length=50, blank=False, null=False)
    equivalence_mapping = models.CharField(max_length=200, blank=True, null=True, default=None)
    match = models.BooleanField(default=True, blank=True)
    source_optional = models.BooleanField(default=False, blank=True)
    default_for_optional = models.CharField(max_length=20, blank=True, null=True, default=None)

    def __str__(self):
        return str(self.generictype) + " -- " + str(self.name) + " -- " + str(self.description)


class GenericTypeTrigger(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    generictype = models.ForeignKey(GenericType, on_delete=models.SET_NULL, blank=True, null=True, default=None)
    description = models.CharField(max_length=50, blank=True, null=True, default=None)
    update_generictype = models.ForeignKey(GenericType, on_delete=models.SET_NULL, blank=True, null=True, default=None,
                                           related_name='update_generictype')
    xref_generictype = models.ForeignKey(GenericType, on_delete=models.SET_NULL, blank=True, null=True, default=None,
                                         related_name='xref_generictype')
    linked_fields = models.CharField(max_length=255, blank=True, null=True, default=None)

    def __str__(self):
        return str(self.description)


class APICallTemplate(models.Model):
    ACTION_CHOICES = [
        (1, 'Create'),
        (2, 'Read'),
        (3, 'Update'),
        (4, 'Delete'),
    ]
    METHOD_CHOICES = [
        (1, 'POST'),
        (2, 'GET'),
        (3, 'PUT'),
        (4, 'DELETE'),
    ]
    PAGINATION_CHOICES = [
        (1, 'None'),
        (2, 'RFC5988 (In Header)'),
        (3, 'In JSON Body'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    action_type = models.IntegerField(
        choices=ACTION_CHOICES,
        default=1,
    )
    elementtype = models.ForeignKey(ElementType, on_delete=models.SET_NULL, default=None, blank=True, null=True)
    generictype = models.ForeignKey(GenericType, on_delete=models.SET_NULL, default=None, blank=True, null=True)
    api_method = models.IntegerField(
        choices=METHOD_CHOICES,
        default=1,
    )
    api_pagination = models.IntegerField(
        choices=PAGINATION_CHOICES,
        default=1,
    )
    api_next_page_path = models.CharField("Next Path (JSON Body)", max_length=200, blank=True, null=True, default=None)
    parse_path = models.CharField("Parse Path (Read Ops)", max_length=200, blank=True, null=True, default=None)
    id_field = models.CharField("ID Key Name (Read Ops)", max_length=200, blank=True, null=True, default=None)
    url_template = models.CharField("API URL", max_length=200, blank=True, null=True, default=None)
    body_template = models.TextField("Body Template", blank=True, null=False, default=dict)
    rerun_list_with_id = models.BooleanField("GET by ID (2nd run)", default=False, editable=True)
    rerun_parse_path = models.CharField("Parse Path (2nd run)", max_length=200, blank=True, null=True, default=None)
    last_update = models.DateTimeField(auto_now=True)
    sequence = models.IntegerField(default=0)

    class Meta:
        ordering = ['elementtype', 'generictype', 'action_type']

    def __str__(self):
        return "[" + str(self.elementtype) + " " + str(self.generictype) + " " + self.get_action_name() + "] -- " +\
               self.get_method_name() + " " + str(self.url_template)

    def generate_url(self, obj, element=None):
        # print(self, obj, element)
        if not obj:
            elm = element
            src_id = None
        else:
            elm = obj.element
            src_id = obj.source_id

        base_url = elm.base_url()
        url = self.url_template
        url = url.replace("{{baseurl}}", base_url)
        url = url.replace("{{id}}", str(src_id))
        url = elm.make_url(url)
        # print(url)
        return url

    def generate_body(self, src_dict, dest_element, gd_obj=None):
        # print(src_dict)
        body_template = self.body_template
        body = body_template
        jbody = {}
        # compile a list of variables {{ }} in the lookup string
        post_replace = False
        post_replace_list = []
        post_delete_keys = []
        if gd_obj:
            body = body.replace("{{source_id}}", str(gd_obj.source_id))
        else:
            body = body.replace("{{source_id}}", "")
        # print(body)
        while "{{" in body:
            v_val = body[body.find("{{") + 2:body.find("}}")]
            repl_val = src_dict.get(v_val)
            # print("**", v_val, repl_val)
            if repl_val and isinstance(repl_val, str):
                repl_val = repl_val.replace("\n", "\\n")

            # if the value is None, we will queue the change to be deleted
            if repl_val is None:
                post_delete_keys.append(v_val)
                repl_val = "<<>>"
            # if the value is a boolean or an integer, queue the change to after the json.loads
            elif isinstance(repl_val, (bool, int)):
                post_replace = True
                post_replace_list.append({"key": v_val, "value": repl_val})
                repl_val = "<<" + str(v_val) + ">>"
            # if the value is a list or dict, convert it back to a string since we will be json.loads'ing it
            elif isinstance(repl_val, (list, dict)):
                repl_val = json.dumps(repl_val)
            # print(type(repl_val), repl_val)
            body = body.replace("{{" + v_val + "}}", repl_val)

        # print(body)
        jbody = json.loads(body)

        # if there are blank keys, we will delete them
        for pd in post_delete_keys:
            if self.parse_path:
                del jbody[self.parse_path][pd]
            else:
                del jbody[pd]

        # if there are boolean or numeric values, we will replace them here in the dict
        if post_replace:
            for pr in post_replace_list:
                if self.parse_path:
                    jbody[self.parse_path][pr["key"]] = pr["value"]
                else:
                    jbody[pr["key"]] = pr["value"]

        return jbody

    # def old_generate_body(self, src_data, dest_element):
    #     body_template = self.body_template
    #     body = body_template
    #     jbody = {}
    #     # compile a list of variables {{ }} in the lookup string
    #     post_replace = False
    #     post_replace_list = []
    #     while "{{" in body:
    #         v_val = body[body.find("{{") + 2:body.find("}}")]
    #         v_lst = v_val.split("||")
    #         v = v_lst[0]
    #         repl_val = src_data.get_data(v)
    #         if v == "name" or v == "description":
    #             repl_val = src_data.generic.get_data(v)
    #         if repl_val is None or isinstance(repl_val, (bool, int)):
    #             if len(v_lst) > 1:
    #                 post_replace = True
    #                 post_replace_list.append({"key": v_lst[1], "value": repl_val})
    #                 repl_val = '"<<' + v + '>>"'
    #             else:
    #                 repl_val = str(repl_val)
    #         if isinstance(repl_val, (list, dict)):
    #             repl_val = json.dumps(repl_val)
    #         # print(type(repl_val), repl_val)
    #         body = body.replace("{{" + v_val + "}}", repl_val)
    #     # print(body)
    #     jbody = json.loads(body)
    #     if post_replace:
    #         for pr in post_replace_list:
    #             if self.parse_path:
    #                 jbody[self.parse_path][pr["key"]] = pr["value"]
    #             else:
    #                 jbody[pr["key"]] = pr["value"]
    #
    #     return jbody

    def get_method_name(self):
        for choice in self.METHOD_CHOICES:
            if choice[0] == self.api_method:
                return choice[1]

        return "Unknown"

    def get_action_name(self):
        for choice in self.ACTION_CHOICES:
            if choice[0] == self.action_type:
                return choice[1]

        return "Unknown"


class Generic(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Item Name", max_length=50, blank=False, null=False)
    key_value = models.CharField("Important Value", max_length=200, blank=True, null=True, default=None)
    description = models.CharField("Item Description", max_length=200, blank=True, null=True, default=None)
    do_sync = models.BooleanField("Sync this Item?", default=False, editable=True)
    err_disabled = models.BooleanField("Disabled from error?", default=False, editable=True)
    elementsync = models.ForeignKey(ElementSync, on_delete=models.CASCADE, null=True, blank=True)
    element = models.ForeignKey(Element, on_delete=models.CASCADE, null=True, blank=True)
    generictype = models.ForeignKey(GenericType, on_delete=models.CASCADE, null=True, blank=True)
    update_history = models.TextField(blank=True, null=True, default=None)
    last_api_push = models.DateTimeField(auto_now_add=False, null=True, default=None)

    class Meta:
        ordering = ('-do_sync', 'generictype', Cast('key_value', models.IntegerField()), 'key_value')

    def __str__(self):
        gt = self.generictype.name if self.generictype else "None"
        # nm = self.get_safe("name")
        return gt + " :: " + str(self.key_value) + " :: " + self.name

    def get_significant_value(self):
        src = self.elementsync.src_element
        fld = self.generictype.significant_name_key
        objs = GenericData.objects.filter(element=src).filter(generic=self)
        src_obj = objs.first()
        if src_obj:
            d = src_obj.get_data(fld)
            return d
        return None

    def is_protected(self):
        # gt_sk = self.generictype.significant_name_key
        gt_skr = self.generictype.significant_name_restrictions
        restr_list = gt_skr.split(",")
        # print(self.get_data(gt_sk), restr_list)
        if str(self.get_significant_value()) in restr_list:
            return True
        return False

    def get_bg_color(self):
        if self.is_protected():
            return "pink"
        if self.do_sync:
            return "lightblue"

        return "white"

    def get_data(self, attr, safe=False):
        attr_val = "None"
        if attr == "name":
            attr_val = self.name
        elif attr == "description":
            attr_val = self.description
        elif attr == "key_value":
            attr_val = self.key_value

        if not self.generictype or not safe:
            return attr_val

        gt = self.generictype
        r = gt.safe_char_regex
        repl = gt.safe_char_repl
        max_len = gt.get_max_len(attr)
        out = re.sub(r, repl, attr_val[:max_len])
        return out

    def get_objects(self):
        obj_count = 1 + len(self.elementsync.dst_element.all())
        out_all = self.genericdata_set.all()
        out_src = list(out_all.filter(element=self.element))
        out_dst = list(out_all.exclude(element=self.element))
        return out_src + out_dst, obj_count

    def match_cell(self):
        bool_stat, out = self.match_report()
        if bool_stat:
            return '<td style="background-color:#55dd55">' + str(bool_stat) + '</td>'
        else:
            return '<td style="background-color:#dd5555">' + str(bool_stat) + '</td>'

    def objects_in_sync(self):
        bool_stat, _ = self.match_report()
        return bool_stat

    def hyperlink(self, data_obj, is_admin=False):
        return "<a href='/home/status-obj-data?type=" + data_obj.generictype.name +\
               "&id=" + str(data_obj.id) + "'>" + str(data_obj) + "</a>"

    def source_match_generic(self):
        result = True
        gen_error = None
        objects, count = self.get_objects()
        if self.get_data("name", safe=True) != objects[0].get_data("name", safe=True):
            result = False
            gen_error = "Name mis-match from base object"
        if self.get_data("description", safe=True) != objects[0].get_data("description", safe=True):
            result = False
            gen_error = "Description mis-match from base object"

        return result, gen_error

    # def normalize_object(self):
    #     out = {}
    #     et_list = []
    #     for et in ElementType.objects.all():
    #         out[et.name] = {}
    #         et_list.append(et.name)
    #     # Get all related records from the GenericTypeMatchRule table
    #     rules = self.generictype.generictypematchrule_set.all()
    #     objects, count = self.get_objects()
    #     rule_analysis = []
    #     # we only care about the source object for this part
    #     obj = objects[0]
    #     src_data = {}
    #     dst_data = {}
    #     for k, v in obj.source_data.items():
    #         if k == "name" or k == "description":
    #             src_data[k] = self.get_data(k, safe=True)
    #             dst_data[k] = self.get_data(k, safe=True)
    #         else:
    #             new_k = k
    #             new_src = obj.get_data(k, safe=False)
    #             k_rule = rules.filter(generictype=obj.generictype).filter(field__contains=k).first()
    #             if k_rule and k_rule.match:
    #                 src_data[k] = new_src
    #                 new_res = self.exec_rule(new_src, k_rule)
    #                 fld_list = k_rule.field.split(",")
    #                 if len(fld_list) == 1:
    #                     new_k = fld_list[0]
    #                 else:
    #                     for fld in fld_list:
    #                         if k in fld:
    #                             fld_list.remove(fld)
    #                     new_k = fld_list[0].split("||")[0]
    #                 # print("~~~", new_res, new_src, k_rule)
    #                 if new_res not in ("None", None):
    #                     dst_data[new_k] = new_res
    #
    #     # print("===")
    #     # print(json.dumps(src_data))
    #     # print(json.dumps(dst_data))
    #     # print("===")
    #     out[objects[0].element.elementtype.name] = src_data
    #     et_list.remove(objects[0].element.elementtype.name)
    #     out[et_list[0]] = dst_data
    #     return out

    # def exec_rule(self, value, rule_obj):
    #     current_comp = None
    #     result = None
    #     if rule_obj.equivalence_mapping:
    #         comp_list = rule_obj.equivalence_mapping.split("||")
    #         # since there can be multiple sets of equivalencies, we need to determine which one to use...
    #         for comp in comp_list:
    #             comp_vals = comp.split("=")
    #             # grp["objs"][0] represents (hopefully?) "source" object, so see if this is the group to use...
    #             if str(value) in comp_vals:
    #                 result = comp_vals.remove(str(value))
    #                 break
    #         #
    #         # # just in case equivalence wasn't needed, do a secondary check to see if values match exactly
    #         # grp_result = all(element == grp["objs"][0] for element in grp["objs"])
    #         # if grp_result:
    #         #     result = True
    #         #     grp["match"] = True
    #     elif rule_obj.match_type == "AdvancedMappingTable":
    #         # Use the AdvancedMappingTable for translation... this is used for ACLs currently
    #         converted_rules, errors = self.exec_mapping_table([value], 1)
    #         # result = converted_rules
    #         out_rules = []
    #         # print(converted_rules)
    #         result = "\n".join(converted_rules)
    #         # for rule in converted_rules:
    #         #     print(rule)
    #
    #     #     if not grp_result:
    #     #         result = False
    #     #         grp["match"] = False
    #     else:
    #         # not using equivalencies makes this process much simpler...
    #         result = value
    #     #     grp_result = all(element == grp["objs"][0] for element in grp["objs"])
    #     #     if not grp_result:
    #     #         result = False
    #     #         grp["match"] = False
    #     return result

    def match_report(self, specific_objects=None, normalized_data=None):
        result = True
        out = ""
        gen_error = None
        # Get all related records from the GenericTypeMatchRule table
        # rules = self.generictype.generictypematchrule_set.filter(match=True)
        if specific_objects:
            # Using specified GenericData objects, verify if they are in sync
            objects = specific_objects
            count = len(specific_objects)
            normalize_objs = objects
        else:
            # Get all related GenericData objects that exist and a count of how many are expected...
            objects, count = self.get_objects()
            normalize_objs = [objects[0]]

        # maps = AdvancedMappingTable.objects.filter(generictype=self.generictype)
        # data_norms = common.normalize_objects(objects, GenericTypeMatchRule.objects.all(), self, ElementType.objects.all(), maps)
        if normalized_data:
            data_norms = normalized_data
        else:
            data_norms = normalize_data_objects(normalize_objs, self.elementsync)
        # print(data_norms)

        # rule_analysis = []
        errors = None
        header = ["Source"]
        # Iterate rules...
        # for rule in rules:
        if True:
            # print(rule, rule.field)
            # header.append(rule.name)
            # rule_objs = []
            # rule_src = []
            rule_dict = {}
            result_count = 0
            # iterate all GenericData objects
            for obj in data_norms:
                # new_obj = obj.normalize_object()
                # print(new_obj)
                if "src" in obj and "dst" in obj:
                    for dest_k, dest_v in obj["src"]["comp"].items():
                        rule_id = str(dest_v["obj"].id)
                        if rule_id not in rule_dict:
                            rule_dict[rule_id] = {"data": [], "orig": [], "elem": [],
                                                  "rule": dest_v["obj"], "match": True}
                        rule_dict[rule_id]["data"].append(dest_v["data"])
                        rule_dict[rule_id]["orig"].append(dest_v["orig"])
                        rule_dict[rule_id]["elem"].append(obj["src"]["obj"])
                        result_count = 1

                    # print("src", obj["src"]["comp"])
                    # iterate all destination keys in the dictionary
                    for k, obj_dest in obj["dst"].items():
                        # print("dst", k, obj["dst"][k]["comp"])
                        # if the object exists (i.e., if this is already in the db)...
                        if obj_dest["obj"]:
                            # iterate all rules in the destination
                            for dest_k, dest_v in obj_dest["comp"].items():
                                # rule_analysis.append({"objs": rule_objs, "equiv": dest_v[obj].equivalence_mapping,
                                #                       "match": True, "type": dest_v[obj].match_type,
                                #                       "fld_name": dest_v[obj].field, "s": obj["src"]["comp"]})
                                rule_id = str(dest_v["obj"].id)
                                if rule_id not in rule_dict:
                                    rule_dict[rule_id] = {"data": [], "orig": [], "elem": [],
                                                          "rule": dest_v["obj"], "match": True}
                                rule_dict[rule_id]["data"].append(dest_v["data"])
                                rule_dict[rule_id]["orig"].append(dest_v["orig"])
                                rule_dict[rule_id]["elem"].append(obj["dst"][k]["obj"])
                                result_count = len(rule_dict[rule_id]["data"])

                # origin_data = obj.get(obj["origin"])
                # src_data = common.search_data_for_fields(origin_data, rule.field)
                # rule_src.append(src_data)
                #
                # comp_obj = obj.get(objects[0].element.elementtype.name)
                # s = common.search_data_for_fields(comp_obj, rule.field)
                # rule_objs.append(s)
                # different elements have different rules on which characters are allowed. if this rule is targeting
                #  data that is subject to one or more of these restricitons, "clean" the data before seeing if it
                #  matches...
                # safe = True if rule.match_type == "cleaned" else False
                # d = obj.get_data(rule.field, safe=safe)
                # rule_objs.append(d)
                # rule_objs.append(comp_obj.get(rule.field))
            # append objects, any equivalence mapping values and a default of match=true for each rule
            # rule_analysis.append({"objs": rule_objs, "equiv": rule.equivalence_mapping, "match": True,
            #                       "type": rule.match_type, "fld_name": rule.field, "s": rule_src})
        # print(rule_dict)
        # current_comp = []
        # iterate back through the compiled list of rules and records
        for grp in rule_dict:
            header.append(rule_dict[grp]["rule"].name)
            # print("match_report=", grp)
            grp_result = all(element == rule_dict[grp]["data"][0] for element in rule_dict[grp]["data"])
            if not grp_result:
                result = False
                rule_dict[grp]["match"] = False

        if False:
            # see if we need to check for equivalency mapping. i.e.
            #  "matrixCellStatus": "ENABLED" is functionally equivalent to "bindingEnabled": True
            #  "matrixCellStatus": "DISABLED" is functionally equivalent to "bindingEnabled": False
            if grp["equiv"]:
                comp_list = grp["equiv"].split("||")
                # since there can be multiple sets of equivalencies, we need to determine which one to use...
                for comp in comp_list:
                    comp_vals = comp.split("=")
                    # grp["objs"][0] represents (hopefully?) "source" object, so see if this is the group to use...
                    if str(grp["objs"][0]) in comp_vals:
                        current_comp = comp
                        break

                # now that we (hopefully) know the group to use, we can look at all objects too see if they match
                for o in grp["objs"]:
                    # str(o) since items in current_comp is a string
                    if str(o) not in current_comp:
                        result = False
                        grp["match"] = False

                # just in case equivalence wasn't needed, do a secondary check to see if values match exactly
                grp_result = all(element == grp["objs"][0] for element in grp["objs"])
                if grp_result:
                    result = True
                    grp["match"] = True
            elif grp["type"] == "AdvancedMappingTable":
                # Use the AdvancedMappingTable for translation... this is used for ACLs currently
                converted_rules, errors = self.exec_mapping_table(grp["objs"])
                grp_result = all(element == converted_rules[0] for element in converted_rules)
                if not grp_result:
                    result = False
                    grp["match"] = False
            else:
                # not using equivalencies makes this process much simpler...
                grp_result = all(element == grp["objs"][0] for element in grp["objs"])
                if not grp_result:
                    result = False
                    grp["match"] = False
                # if grp["fld_name"] == "name" and grp["objs"][0] != objects[0].generic.get_data("name", safe=True):
                #     # print(grp["objs"][0], objects[0].generic.get_data("name"), grp["objs"][0] != objects[0].generic.get_data("name"))
                #     result = False
                #     grp["match"] = False
                #     gen_error = "Name mis-match from base object"
                # if grp["fld_name"] == "description" and grp["objs"][0] != objects[0].generic.get_data("description", safe=True):
                #     # print(grp["objs"][0], objects[0].generic.get_data("description"), grp["objs"][0] != objects[0].generic.get_data("description"))
                #     result = False
                #     grp["match"] = False
                #     gen_error = "Description mis-match from base object"

        # generate html for report
        out += "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
        for o in range(0, result_count):
            # out += "<tr><td>" + self.hyperlink(rule_dict[r]["elem"][o]) + "</td>"
            if o == 0:
                out += "<tr><td>" + self.hyperlink(objects[o]) + "</td>"
            else:
                # TODO: added this iteration... is this right?
                for r in rule_dict:
                    out += "<tr><td>" + self.hyperlink(rule_dict[r]["elem"][o]) + "</td>"
            for r in rule_dict:
                # TODO: it would be nice to have a way to toggle this
                # out += "<td>" + str(rule_dict[r]["data"][o]) + "</td>"
                out += "<td>" + str(rule_dict[r]["orig"][o]) + "</td>"
            out += "</tr>"
        out += "<tr><td><b><i>Matches?</td>"
        for r in rule_dict:
            out += "<td>" + str(rule_dict[r]["match"]) + "</td>"
        out += "</tr></table>"

        # ensure we have the right number of objects... if there is only 1 object, it's going to match itself, but...
        #  there should never be only 1 object...
        if count != len(objects):
            out += "<hr><b><i>Expected " + str(count) + " elements; found " + str(len(objects)) + "!</b></i>"
            result = False
        #  these are built in objects that we shouldn't be messing with
        if self.is_protected():
            out += "<hr><b><i>Protected Element. Will always report 'in-sync'.</b></i>"
            result = True
        gen_res, gen_error = self.source_match_generic()
        if not gen_res:
            out += "<hr><b><i>" + gen_error + "</b></i>"
            result = False
        if errors:
            # out += "<hr>"
            for e in errors:
                out += "<b><i>Warning: " + e.get("error") + " (" + e.get("key") + ")</b></i><br>"

        return result, out

    # def old_match_report(self, specific_objects=None):
    #     # if bool_only and self.is_protected:
    #     #     return True
    #     result = True
    #     out = ""
    #     gen_error = None
    #     # Get all related records from the GenericTypeMatchRule table
    #     rules = self.generictype.generictypematchrule_set.filter(match=True)
    #     if specific_objects:
    #         # Using specified GenericData objects, verify if they are in sync
    #         objects = specific_objects
    #         count = len(specific_objects)
    #     else:
    #         # Get all related GenericData objects that exist and a count of how many are expected...
    #         objects, count = self.get_objects()
    #     rule_analysis = []
    #     errors = None
    #     header = ["Source"]
    #     # Iterate rules...
    #     for rule in rules:
    #         # print(rule, rule.field)
    #         header.append(rule.name)
    #         rule_objs = []
    #         # iterate all GenericData objects
    #         for obj in objects:
    #             # different elements have different rules on which characters are allowed. if this rule is targeting
    #             #  data that is subject to one or more of these restricitons, "clean" the data before seeing if it
    #             #  matches...
    #             safe = True if rule.match_type == "cleaned" else False
    #             d = obj.get_data(rule.field, safe=safe)
    #             rule_objs.append(d)
    #         # append objects, any equivalence mapping values and a default of match=true for each rule
    #         rule_analysis.append({"objs": rule_objs, "equiv": rule.equivalence_mapping, "match": True,
    #                               "type": rule.match_type, "fld_name": rule.field})
    #
    #     current_comp = []
    #     # iterate back through the compiled list of rules and records
    #     for grp in rule_analysis:
    #         # see if we need to check for equivalency mapping. i.e.
    #         #  "matrixCellStatus": "ENABLED" is functionally equivalent to "bindingEnabled": True
    #         #  "matrixCellStatus": "DISABLED" is functionally equivalent to "bindingEnabled": False
    #         if grp["equiv"]:
    #             comp_list = grp["equiv"].split("||")
    #             # since there can be multiple sets of equivalencies, we need to determine which one to use...
    #             for comp in comp_list:
    #                 comp_vals = comp.split("=")
    #                 # grp["objs"][0] represents (hopefully?) "source" object, so see if this is the group to use...
    #                 if str(grp["objs"][0]) in comp_vals:
    #                     current_comp = comp
    #                     break
    #
    #             # now that we (hopefully) know the group to use, we can look at all objects too see if they match
    #             for o in grp["objs"]:
    #                 # str(o) since items in current_comp is a string
    #                 if str(o) not in current_comp:
    #                     result = False
    #                     grp["match"] = False
    #
    #             # just in case equivalence wasn't needed, do a secondary check to see if values match exactly
    #             grp_result = all(element == grp["objs"][0] for element in grp["objs"])
    #             if grp_result:
    #                 result = True
    #                 grp["match"] = True
    #         elif grp["type"] == "AdvancedMappingTable":
    #             # Use the AdvancedMappingTable for translation... this is used for ACLs currently
    #             converted_rules, errors = self.exec_mapping_table(grp["objs"])
    #             grp_result = all(element == converted_rules[0] for element in converted_rules)
    #             if not grp_result:
    #                 result = False
    #                 grp["match"] = False
    #         else:
    #             # not using equivalencies makes this process much simpler...
    #             grp_result = all(element == grp["objs"][0] for element in grp["objs"])
    #             if not grp_result:
    #                 result = False
    #                 grp["match"] = False
    #             # if grp["fld_name"] == "name" and grp["objs"][0] != objects[0].generic.get_data("name", safe=True):
    #             #     # print(grp["objs"][0], objects[0].generic.get_data("name"), grp["objs"][0] != objects[0].generic.get_data("name"))
    #             #     result = False
    #             #     grp["match"] = False
    #             #     gen_error = "Name mis-match from base object"
    #             # if grp["fld_name"] == "description" and grp["objs"][0] != objects[0].generic.get_data("description", safe=True):
    #             #     # print(grp["objs"][0], objects[0].generic.get_data("description"), grp["objs"][0] != objects[0].generic.get_data("description"))
    #             #     result = False
    #             #     grp["match"] = False
    #             #     gen_error = "Description mis-match from base object"
    #
    #     # generate html for report
    #     out += "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
    #     for o in range(0, len(objects)):
    #         if o == 0:
    #             out += "<tr><td>" + self.hyperlink(objects[o]) + "</td>"
    #         else:
    #             out += "<tr><td>" + str(objects[o]) + "</td>"
    #         for r in rule_analysis:
    #             out += "<td>" + str(r["objs"][o]) + "</td>"
    #         out += "</tr>"
    #     out += "<tr><td><b><i>Matches?</td>"
    #     for r in rule_analysis:
    #         out += "<td>" + str(r["match"]) + "</td>"
    #     out += "</tr></table>"
    #
    #     # ensure we have the right number of objects... if there is only 1 object, it's going to match itself, but...
    #     #  there should never be only 1 object...
    #     if count != len(objects):
    #         out += "<hr><b><i>Expected " + str(count) + " elements; found " + str(len(objects)) + "!</b></i>"
    #         result = False
    #     #  these are built in objects that we shouldn't be messing with
    #     if self.is_protected():
    #         out += "<hr><b><i>Protected Element. Will always report 'in-sync'.</b></i>"
    #         result = True
    #     gen_res, gen_error = self.source_match_generic()
    #     if not gen_res:
    #         out += "<hr><b><i>" + gen_error + "</b></i>"
    #         result = False
    #     if errors:
    #         # out += "<hr>"
    #         for e in errors:
    #             out += "<b><i>Warning: " + e.get("error") + " (" + e.get("key") + ")</b></i><br>"
    #
    #     return result, out

    # def exec_mapping_table(self, objects, force_dest_format=None):
    #     # print(objects)
    #     bad_keys = []
    #     maps = AdvancedMappingTable.objects.filter(generictype=self.generictype).\
    #         filter(elementtype=self.element.elementtype)
    #     src_format = 0
    #     out_rules = []
    #     for object_rules in objects:
    #         out_obj_rules = []
    #         for rule in object_rules:
    #             txt_flds = []
    #             sel = None
    #             out_rule = {}
    #             for k, v in rule.items():
    #                 obj = None
    #                 # source and destination are different; need to convert
    #                 rgx_test = maps.filter(json_key_1=str(k)).filter(json_val_1_regex=True)
    #                 if len(rgx_test) > 0:
    #                     for r in rgx_test:
    #                         if re.match(r.json_val_1, str(v)):
    #                             # print(r)
    #                             obj = r
    #                             break
    #                 else:
    #                     # d_k_dict = {"json_key_" + str(src_format): str(k)}           # + "__contains"
    #                     # d_kv_dict = {"json_key_" + str(src_format): str(k) + "=" + str(v)}
    #                     # d_v_dict = {"json_val_" + str(src_format): v}
    #                     obj_kv = maps.filter(json_key_1=str(k)).filter(json_val_1=v)
    #                     obj_eq = maps.filter(json_key_1=str(k) + "=" + str(v))       #Q(**d_k_dict)|Q(**d_kv_dict)
    #                     obj_bs = maps.filter(json_val_1=v)
    #                     # print(k, v, obj_kv, obj_eq, obj_bs)
    #                     # print(k, v, d_k_dict, d_kv_dict, d_v_dict)
    #                     if len(obj_kv) > 0:
    #                         obj = obj_kv.first()
    #                     elif len(obj_eq) > 0:
    #                         obj = obj_eq.first()
    #                     elif len(obj_bs) > 0:
    #                         obj = obj_bs.first()
    #                     else:
    #                         obj = None
    #                         # print("--error--", k, v, len(obj_kv), len(obj_eq), len(obj_bs))
    #                         bad_keys.append({"error": "unrecognized attribute", "rule": rule, "key": k, "value": v})
    #                         continue
    #
    #                 # print(k, v, obj)
    #                 if not obj:
    #                     continue
    #                 if not obj.json_key_1_ignored and not obj.json_key_2_ignored:
    #                     # print(obj)
    #                     # key_data = getattr(obj, "json_key_" + str(dst_format))
    #                     # val_data = getattr(obj, "json_val_" + str(dst_format))
    #                     # val_dst = getattr(obj, "json_val_" + str(dst_format))
    #                     key_data = obj.json_key_2
    #                     val_data = obj.json_val_2
    #                     # print("====================", src_format, dst_format)
    #                     # examples:
    #                     #  dst_port_lower={{v1}},dst_port_upper={{v2}}
    #                     #  src_port={{v1}}
    #                     if obj.use_flat_text:
    #                         val_data = obj.output_flat_text if obj.output_flat_text else ""
    #                         val_list = re.split(obj.json_val_1, str(v))
    #                         if "{{" in val_data:
    #                             for x in range(0, len(val_list)):
    #                                 val_data = val_data.replace("{{v" + str(x) + "}}", str(val_list[x]))
    #                         if val_data != "":
    #                             txt_flds.append(val_data)
    #                     elif "{{" in val_data and "=" in val_data:
    #                         val_list = re.split(obj.json_val_1, str(v))
    #                         for x in range(0, len(val_list)):
    #                             val_data = val_data.replace("{{v" + str(x) + "}}", str(val_list[x]))
    #                         vds = val_data.split(",")
    #                         for vd in vds:
    #                             kd_list = vd.split("=")
    #                             out_rule[kd_list[0]] = kd_list[1]
    #                     elif "{{" in val_data:
    #                         # print(val_dst, val_data)
    #                         val_dst_list = val_data.split(",")
    #                         for v_dst in range(0, len(val_dst_list)):
    #                             repl_search = "{{v" + str(v_dst+1) + "}}"
    #                             repl_subst = rule.get(val_dst_list[v_dst])
    #                             val_data = val_data.replace(repl_search, str(repl_subst))
    #                             # print("---", obj, repl_search, repl_subst, val_dst_list, key_data, val_data, val_dst)
    #                     else:
    #                         out_rule[key_data] = val_data
    #
    #                     # handles case where the key is set to something like dst_oper=eq
    #                     if key_data and "=" in key_data:
    #                         kd_list = key_data.split("=")
    #                         out_rule[kd_list[0]] = kd_list[1]
    #                     else:
    #                         out_rule[key_data] = val_data
    #
    #                     # print(key_data, val_data, val_dst)
    #                     # print("------------------")
    #
    #                 # if getattr(obj, "json_key_" + str(src_format) + "_required"):
    #                 #     print('hi')
    #                 #     out_rule_required[getattr(obj, "json_key_" + str(src_format))] = \
    #                 #         getattr(obj, "json_val_" + str(src_format) + "_default")
    #
    #             # some elements require certain data elements; check for missing required keys and add defaults...
    #             # req_dict = {"json_key_" + str(src_format) + "_required": True}
    #             reqs = maps.filter(json_key_2_required=True)
    #             for req in reqs:
    #                 # req_k = getattr(req, "json_key_" + str(src_format))
    #                 # req_dv = getattr(req, "json_val_" + str(src_format) + "_default")
    #                 req_k = req.json_key_2
    #                 req_dv = req.json_val_2_default
    #                 if req_k not in out_rule:
    #                     out_rule[req_k] = req_dv
    #
    #             if len(txt_flds) > 0:
    #                 acl = " ".join(txt_flds)
    #                 out_rules.append(acl)
    #             else:
    #                 out_obj_rules.append(out_rule)
    #         if out_obj_rules:
    #             out_rules.append(out_obj_rules)
    #     # print("===========")
    #     # print(out_rules)
    #     # print(bad_keys)
    #     # print("===========")
    #     return out_rules, bad_keys

    # def old_exec_mapping_table(self, objects, force_dest_format=None):
    #     # print(objects)
    #     bad_keys = []
    #     maps = AdvancedMappingTable.objects.filter(generictype=self.generictype).\
    #         filter(elementtype=self.element.elementtype)
    #     src_format = 0
    #     out_rules = []
    #     for object_rules in objects:
    #         out_obj_rules = []
    #         for rule in object_rules:
    #             sel = None
    #             dst_format = 0 if not force_dest_format else force_dest_format
    #             out_rule = {}
    #             for k, v in rule.items():
    #                 # first, determine whether our first object (source) matches the '1' or '2' format
    #                 if src_format == 0:
    #                     sel = maps.filter(json_key_1=k).filter(json_val_1=v).filter(is_selector=True)
    #                     # sel2 = maps.filter(json_key_2=k).filter(json_val_2=v).filter(is_selector=True)
    #                     src_format = 1 if len(sel) > 0 else 2
    #                     if not force_dest_format:
    #                         continue
    #                 # next, evaluate whether destination rules match or not
    #                 elif dst_format == 0:
    #                     sel = maps.filter(json_key_1=k).filter(json_val_1=v).filter(is_selector=True)
    #                     # sel2 = maps.filter(json_key_2=k).filter(json_val_2=v).filter(is_selector=True)
    #                     dst_format = 1 if len(sel) > 0 else 2
    #                 # print("--", k, v, src_format, dst_format)
    #
    #                 # ??? I'm not sure if this is the correct logic or not...
    #                 backwards = True if force_dest_format else False
    #                 # source and destination are different; need to convert
    #                 if not src_format == dst_format:
    #                     if backwards:
    #                         d_k_dict = {"json_key_" + str(src_format): str(k)}           # + "__contains"
    #                         d_kv_dict = {"json_key_" + str(src_format): str(k) + "=" + str(v)}
    #                         d_v_dict = {"json_val_" + str(src_format): v}
    #                     else:
    #                         d_k_dict = {"json_key_" + str(dst_format): str(k)}           # + "__contains"
    #                         d_kv_dict = {"json_key_" + str(dst_format): str(k) + "=" + str(v)}
    #                         d_v_dict = {"json_val_" + str(dst_format): v}
    #                     obj_kv = maps.filter(**d_k_dict).filter(**d_v_dict)
    #                     obj_eq = maps.filter(**d_kv_dict)       #Q(**d_k_dict)|Q(**d_kv_dict)
    #                     obj_bs = maps.filter(**d_k_dict)
    #                     # print(k, v, d_k_dict, d_kv_dict, d_v_dict)
    #                     print(k, v, obj_kv, obj_eq, obj_bs)
    #                     if len(obj_kv) > 0:
    #                         obj = obj_kv.first()
    #                     elif len(obj_eq) > 0:
    #                         obj = obj_eq.first()
    #                     elif len(obj_bs) > 0:
    #                         obj = obj_bs.first()
    #                     else:
    #                         obj = None
    #                         # print("--error--", k, v, len(obj_kv), len(obj_eq), len(obj_bs))
    #                         bad_keys.append({"error": "unrecognized attribute", "rule": rule, "key": k, "value": v})
    #                         continue
    #
    #                     # print(k, v, obj)
    #                     if not obj:
    #                         continue
    #                     if not obj.json_key_1_ignored and not obj.json_key_2_ignored:
    #                         # print(obj)
    #                         key_data = getattr(obj, "json_key_" + str(src_format))
    #                         val_data = getattr(obj, "json_val_" + str(src_format))
    #                         val_dst = getattr(obj, "json_val_" + str(dst_format))
    #                         # print("====================", src_format, dst_format)
    #                         # print(key_data, val_data, val_dst)
    #                         if "{{" in val_data:
    #                             # print(val_dst, val_data)
    #                             val_dst_list = val_dst.split(",")
    #                             for v_dst in range(0, len(val_dst_list)):
    #                                 repl_search = "{{v" + str(v_dst+1) + "}}"
    #                                 if backwards:
    #                                     repl_subst = rule.get(key_data)
    #                                 else:
    #                                     repl_subst = rule.get(val_dst_list[v_dst])
    #                                 val_data = val_data.replace(repl_search, str(repl_subst))
    #                                 print(obj, repl_search, repl_subst, val_dst_list, key_data, val_data, val_dst)
    #                             out_rule[key_data] = val_data
    #                         else:
    #                             if backwards:
    #                                 out_rule[key_data] = val_dst
    #                             else:
    #                                 out_rule[key_data] = val_data
    #                         # print(key_data, val_data, val_dst)
    #                         # print("------------------")
    #
    #                     # if getattr(obj, "json_key_" + str(src_format) + "_required"):
    #                     #     print('hi')
    #                     #     out_rule_required[getattr(obj, "json_key_" + str(src_format))] = \
    #                     #         getattr(obj, "json_val_" + str(src_format) + "_default")
    #
    #             # some elements require certain data elements; check for missing required keys and add defaults...
    #             if not src_format == dst_format:
    #                 req_dict = {"json_key_" + str(src_format) + "_required": True}
    #                 reqs = maps.filter(**req_dict)
    #                 for req in reqs:
    #                     req_k = getattr(req, "json_key_" + str(src_format))
    #                     req_dv = getattr(req, "json_val_" + str(src_format) + "_default")
    #                     if req_k not in out_rule:
    #                         out_rule[req_k] = req_dv
    #
    #                 out_obj_rules.append(out_rule)
    #         if out_obj_rules:
    #             out_rules.append(out_obj_rules)
    #     print("===========")
    #     print(out_rules)
    #     print(bad_keys)
    #     print("===========")
    #     return out_rules, bad_keys

    def get_api_auth(self, api_template, element):
        headers = api_template.elementtype.static_headers
        if api_template.elementtype.auth_type == 1:
            headers = {api_template.elementtype.token_header_name: element.get_api_key()}
            user_auth = None
        else:
            username, password = element.get_auth_info()
            user_auth = (username, password)
        return user_auth, headers, api_template.rerun_list_with_id, api_template.rerun_parse_path

    def get_changes(self, detail=False):
        # bool_stat, _ = self.match_report()
        # if not bool_stat:
        outs = []
        objs, _ = self.get_objects()
        normalized_result = objs[0].normalize_object()
        normalized_dict = normalized_result[0]
        # print(normalized_dict)
        elements = [self.elementsync.src_element] + list(self.elementsync.dst_element.all())
        # dst_elem = self.elementsync.dst_element.all()
        for d in elements:
            found_elm = False
            for o_num in range(0, len(objs)):
                o = objs[o_num]
                if d == o.element:
                    found_elm = True
                    # Test to see if the source data object matches the generic sync object
                    if o_num == 0:
                        gen_match, _ = self.source_match_generic()
                    else:
                        gen_match, _ = self.match_report(normalized_data=normalized_result)
                    if not gen_match:
                        api_template = APICallTemplate.objects.filter(action_type=3).\
                            filter(generictype=self.generictype).\
                            filter(elementtype=d.elementtype).first()

                        if api_template:
                            creds, heads, rerun, rerun_path = self.get_api_auth(api_template, d)
                            # b = normalized_dict.get(d.elementtype.name)
                            if d == self.elementsync.src_element:
                                success = True
                                err = None
                                b = normalized_dict["src"].get("data")
                            else:
                                success = normalized_dict["dst"].get(str(d.id), {}).get("success")
                                err = normalized_dict["dst"].get(str(d.id), {}).get("error")
                                b = normalized_dict["dst"].get(str(d.id), {}).get("data")
                            if not success:
                                if detail:
                                    outs.append(("ERROR", None, err, None, None, None, None, self, None, None))
                                else:
                                    outs.append(("ERROR", None, err))
                            else:
                                if detail:
                                    outs.append((api_template.get_method_name(), api_template.generate_url(o),
                                                 api_template.generate_body(b, d, gd_obj=o), creds, heads, rerun,
                                                 rerun_path, self, d, api_template))
                                else:
                                    outs.append((api_template.get_method_name(), api_template.generate_url(o),
                                                 api_template.generate_body(b, d, gd_obj=o)))

            if not found_elm:
                api_template = APICallTemplate.objects.filter(action_type=1).filter(generictype=self.generictype).\
                    filter(elementtype=d.elementtype).first()

                if api_template:
                    creds, heads, rerun, rerun_path = self.get_api_auth(api_template, d)
                    # b = normalized_dict.get(d.elementtype.name)
                    if d == self.elementsync.src_element:
                        success = True
                        err = None
                        b = normalized_dict["src"].get("data")
                    else:
                        success = normalized_dict["dst"].get(str(d.id), {}).get("success")
                        err = normalized_dict["dst"].get(str(d.id), {}).get("error")
                        b = normalized_dict["dst"].get(str(d.id), {}).get("data")
                    # print(json.dumps(normalized_dict))
                    # print(objs[0])
                    if not success:
                        if detail:
                            outs.append(("ERROR", None, err, None, None, None, None, self, None, None))
                        else:
                            outs.append(("ERROR", None, err))
                    else:
                        if detail:
                            outs.append((api_template.get_method_name(), api_template.generate_url(None, element=d),
                                         api_template.generate_body(b, d), creds, heads, rerun, rerun_path, self, d,
                                         api_template))
                        else:
                            outs.append((api_template.get_method_name(), api_template.generate_url(None, element=d),
                                         api_template.generate_body(b, d)))

        if outs:
            return outs
        else:
            return None

    def check_for_update(self):
        sig_key = self.generictype.significant_name_key
        sig_desc = self.generictype.significant_key_label
        sig_val = self.get_data(sig_key)
        def_val = sig_desc + " " + str(sig_val)

        objects, count = self.get_objects()
        source_obj = objects[0]
        self.name = source_obj.get_data("name", default_val=sig_val)
        self.description = source_obj.get_data("description", default_val=def_val)
        self.save()

    def update_success(self):
        return False


@receiver(post_save, sender=Generic)
def post_save_generic(sender, instance=None, created=False, **kwargs):
    if instance:
        instance.last_updated = datetime.datetime.now()
        post_save.disconnect(post_save_generic, sender=Generic)
        instance.save()
        post_save.connect(post_save_generic, sender=Generic)

        # g = Generic.objects.filter(element=instance.element).filter(do_sync=True)
        # print(g)
        qs = instance.generictype.generictypetrigger_set.all()
        # print(instance.generictype.name, qs)
        for q in qs:
            gd_inst = instance.genericdata_set.filter(element=instance.element).first()
            gdos = GenericData.objects.linked_objects(gd_inst, q)
            # print(gd_inst, gdos)
            for gdo in gdos:
                sync_list = [instance.do_sync]
                for gds in gdo.get("source", []):
                    if gds.generic:
                        sync_list.append(gds.generic.do_sync)
                # print(gdo.get("dest"), sync_list)
                dest_obj = gdo.get("dest")
                if dest_obj and dest_obj.generic:
                    # if the next update will potentially update the same record (i.e., the same 'type' of record),
                    #  we need to disconnect the post_save receiver to ensure we don't cause an infinite loop
                    if instance.generictype == dest_obj.generictype:
                        post_save.disconnect(post_save_generic, sender=Generic)

                    # here we are saving a "disable" sync action
                    if not sync_list[0]:
                        dest_obj.generic.do_sync = False
                        dest_obj.generic.save()
                    # otherwise, we will only save an "enable" if all related records are already enabled
                    elif all(ele == sync_list[0] for ele in sync_list):
                        # print(sync_list[0], gdo)
                        dest_obj.generic.do_sync = True
                        dest_obj.generic.save()

                    # reconnect from above
                    if instance.generictype == dest_obj.generictype:
                        post_save.connect(post_save_generic, sender=Generic)

                # else:
                #     print(gdo, dest_obj, sync_list)

        # qs = instance.generictype.generictypetrigger_set.all()
        # for q in qs:
        #     recs = eval(q.query)
            # print(q.query, recs)
            # for rec in recs:
            #     gd_filt = rec.genericdata_set.filter(element=instance.element)
            #     # gd_link = gd_filt.first().objects.linked_objects()
            #     print(gd_link)

        # policies = Policy.objects.filter(Q(source_group=instance) | Q(dest_group=instance))
        # for p in policies:
        #     if p.source_group and p.source_group.do_sync and p.dest_group and p.dest_group.do_sync:
        #         p.do_sync = True
        #     else:
        #         p.do_sync = False
        #     p.save()


class GenericDataManager(models.Manager):
    def linked_objects(self, data_elm, trigger):
        if not data_elm:
            return []
        out_recs = []
        # flt = "|" + data_elm.generictype.name + "|"
        # lnks = GenericType.objects.filter(linked_fields__contains=flt)
        # print(data_elm, flt, lnks)
        # for lnk in lnks:
        if True:
            if trigger.generictype == trigger.update_generictype:
                recs = [data_elm]
            else:
                recs = GenericData.objects.filter(element=data_elm.element).\
                    filter(generictype=trigger.update_generictype)    # lnk

            test_list = trigger.linked_fields.split(",")

            for rec in recs:
                idlist = []
                for tl in test_list:
                    if tl in rec.source_data:
                        if isinstance(rec.source_data[tl], list):
                            idlist += rec.source_data[tl]
                        else:
                            idlist.append(rec.source_data[tl])       # __name=test_source
                out = GenericData.objects.filter(element=data_elm.element).\
                    filter(generictype=trigger.xref_generictype).\
                    filter(source_id__in=idlist)
                # print(rec, test_source, test_list, idlist, out)
                if trigger.generictype == trigger.xref_generictype and data_elm in out:
                    outdict = {"dest": rec, "source_ids": idlist, "source": out}
                # elif trigger.generictype != trigger.xref_generictype:
                else:
                    outdict = {"dest": out.first(), "source_ids": idlist, "source": [rec]}
                out_recs.append(outdict)
        return out_recs


class GenericData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    generic = models.ForeignKey(Generic, on_delete=models.CASCADE, null=True, blank=True, default=None)
    element = models.ForeignKey(Element, on_delete=models.CASCADE, null=True, blank=True)
    source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    source_data = models.JSONField(blank=True, null=False, default=dict)
    generictype = models.ForeignKey(GenericType, on_delete=models.CASCADE, null=True, blank=True)
    objects = GenericDataManager()

    class Meta:
        verbose_name = "Generic Data"
        verbose_name_plural = "Generic Datem"
        ordering = ('generictype', 'source_id')

    def __str__(self):
        gt = self.generictype.name if self.generictype else "None"
        el = str(self.element) if self.element else "None"

        if self.generic:
            return gt + "Data :: " + el + " :: " + self.generic.name

        if self.generictype:
            gval = self.generictype.display_name_key
            if gval:
                return gt + " :: " + el + " :: " + str(self.source_data.get(gval))

        return gt + " :: " + el + " :: " + str(id)

    def get_data(self, key_name, default_val=None, safe=False):
        d_val = None
        if self.source_data:
            # This is the format of a dynamic object
            # _{{srcGroupId}}-{{dstGroupId}}||{{sourceSgtId}}-{{destinationSgtId}}::Tag||name::name
            #                      map_list[0]                                    ::  map_list[1] :: map_list[2]
            #                        fake_id                           map_parm_list[0]||map_parm_list[1]
            #            fake_src[0]        ||           fake_src[1]
            # Here is another example:
            # _{{aclIds}}||{{sgacls}}::ACL||name::name
            if key_name[:1] == "_":
                map_list = key_name[1:].split("::")
                map_parm_list = map_list[1].split("||")
                fake_id = map_list[0]
                n_vars = []
                n_fid = fake_id
                # compile a list of variables {{ }} in the lookup string
                while "{{" in n_fid:
                    v = n_fid[n_fid.find("{{") + 2:n_fid.find("}}")]
                    if v not in n_vars:
                        n_vars.append(v)
                    n_fid = n_fid.replace("{{" + v + "}}", "")

                # Now, grab the id numbers, andd then make the relevant query to cross-reference that to the source
                n_vids = []
                n_vals = []
                for var in n_vars:
                    # an asterisk (*) designates that there no intermediary id lookup; the value retrieved here
                    #  goes straight into the vals list
                    if str(var)[:1] == "*":
                        vid = self.source_data.get(str(var)[1:])
                        n_vids.append(vid)
                        n_vals.append(vid)
                    else:
                        # Look up values in data tables and then add values to the vals list
                        vid = self.source_data.get(var)
                        n_vids.append(vid)
                        if isinstance(vid, list):
                            val = GenericData.objects.filter(source_id__in=vid).filter(element=self.element). \
                                filter(generictype__name=map_parm_list[0]).first()
                        else:
                            val = GenericData.objects.filter(source_id=vid).filter(element=self.element). \
                                filter(generictype__name=map_parm_list[0]).first()
                        n_vals.append(val)
                # print(map_parm_list[0], n_vars, n_vids, n_vals)

                # Now we want to do some variable substitution into the original list of values. this is used so that
                #  you can create distinct new values from multiple looked up values
                for n_subst in range(0, len(n_vars)):
                    if isinstance(n_vals[n_subst], str):
                        subst_val = n_vals[n_subst]
                    else:
                        subst_val = n_vals[n_subst].get_data(map_parm_list[1]) if n_vals[n_subst] else "~"
                    fake_id = fake_id.replace("{{" + n_vars[n_subst] + "}}", subst_val)
                fake_list = fake_id.split("||")
                for f in fake_list:
                    if "~" not in f:
                        d_val = f
                        break
                # If we've not been able to construct anything, fall back to a provided default
                if not d_val:
                    d_val = self.source_data.get(map_list[2])
            # No dynamic objects here, but there are multiple options. Iterate the options and see which one to use
            elif "," in key_name:
                key_list = key_name.split(",")
                for k in key_list:
                    # in this case we are using an extra processing function
                    if "||" in k:
                        k_lst = k.split("||")
                        if k_lst[1] == "ACEParser":
                            p_dat = self.source_data.get(k_lst[0])
                            if p_dat:
                                d_val = []
                                for p in p_dat.split("\n"):
                                    d_val.append(ace_parser.parseString(p).asDict())
                            else:
                                d_val = None
                    else:
                        # otherwise just do a straight lookup
                        d_val = self.source_data.get(k)
                    if d_val:
                        break
            # Simple lookup. Single value from the data source
            else:
                d_val = self.source_data.get(key_name)

        # If we haven't found a value yet, use the default supplied to this function (typically None)
        if d_val is None or d_val == "":
            d_val = default_val

        # If we need to "clean" the output for comparision sake, we do that now
        #  This is used for elements that don't support certain characters, which will still allow us to have a sane
        #  comparision of names and things like that despite them not matching exactly.
        if safe and not isinstance(d_val, int):
            gt = self.generictype
            r = gt.safe_char_regex
            repl = gt.safe_char_repl
            max_len = gt.get_max_len(key_name)
            d_val = re.sub(r, repl, str(d_val)[:max_len])

        return d_val

    def is_protected(self):
        gt_sk = self.generictype.significant_name_key
        gt_skr = self.generictype.significant_name_restrictions
        restr_list = gt_skr.split(",")
        # print(self.get_data(gt_sk), restr_list)
        if str(self.get_data(gt_sk)) in restr_list:
            return True
        return False

    def has_synced(self):
        return False

    def converted_data(self):
        normalized_data = normalize_data_objects([self], self.generic.elementsync, convert_only=True)
        print(normalized_data)
        return None

    def normalize_object(self):
        # Get all related records from the GenericTypeMatchRule table
        # rules = self.generictype.generictypematchrule_set.all()
        # ets = ElementType.objects.all()
        # maps = AdvancedMappingTable.objects.filter(generictype=self.generictype). \
        #     filter(elementtype=self.element.elementtype)

        # return common.normalize_objects([self], GenericTypeMatchRule.objects.all(), self.generic, ets, maps)[0]
        return normalize_data_objects([self], self.generic.elementsync)

    def get_bg_color(self):
        if self.is_protected():
            return "pink"
        if self.generic and self.generic.do_sync:
            return "lightblue"

        return "white"

    def get_cell_content(self):
        if self.is_protected():
            return '<font color="gray">N/A</font>'
        if self.generic and self.generic.elementsync:
            if not self.generic.elementsync.last_processed:
                return '<font color="gray">N/A</font>'
            if self.generic.elementsync.src_element == self.element:
                return '<font color="green">Source</font>'

            # return '<font color="gray">Unknown</font>'
            out_src = self.generic.genericdata_set.filter(element=self.generic.elementsync.src_element).first()
            match, out_html = self.generic.match_report(specific_objects=[out_src, self])
            det = '<i class="md-icon icon icon-info_8" style="font-size:16px" onclick="toggletooltip(\'' + base64encode(
                out_html) + '\')"></i>'
            if match:
                return '<font color="green">Matches Source</font> ' + det
            else:
                return '<font color="red">Update</font> ' + det

        return '<font color="gray">Present</font>'

    def get_significant_value(self):
        fld = self.generictype.significant_name_key
        d = self.get_data(fld)
        return d


class AdvancedMappingTable(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    elementtype = models.ForeignKey(ElementType, on_delete=models.SET_NULL, blank=True, default=None, null=True)
    generictype = models.ForeignKey(GenericType, on_delete=models.CASCADE, null=True, blank=True)
    base_key = models.CharField(max_length=25, blank=True, default=None, null=True)
    description = models.CharField(max_length=100, blank=True, default=None, null=True)
    json_key_1 = models.CharField(max_length=30, blank=True, default=None, null=True)
    json_key_1_ignored = models.BooleanField(default=False)
    json_key_1_required = models.BooleanField(default=False)
    json_val_1_default = models.CharField(max_length=30, blank=True, default=None, null=True)
    json_val_1 = models.CharField(max_length=50, blank=True, default=None, null=True)
    json_val_1_regex = models.BooleanField(default=False)
    json_key_2 = models.CharField(max_length=30, blank=True, default=None, null=True)
    json_key_2_ignored = models.BooleanField(default=False)
    json_key_2_required = models.BooleanField(default=False)
    json_val_2_default = models.CharField(max_length=30, blank=True, default=None, null=True)
    json_val_2 = models.CharField(max_length=50, blank=True, default=None, null=True)
    # is_selector = models.BooleanField("Field that controls whether 1/2 is src", default=False)
    output_flat_text = models.CharField(max_length=50, blank=True, default=None, null=True)
    use_flat_text = models.BooleanField(default=False)

    class Meta:
        ordering = ('generictype', 'elementtype')

    def __str__(self):
        return str(self.generictype) + " -- Source:" + str(self.elementtype) + " -- " + str(self.description)


class BasicMappingTable(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    elementtype = models.ForeignKey(ElementType, on_delete=models.SET_NULL, blank=True, default=None, null=True)
    generictype = models.ForeignKey(GenericType, on_delete=models.CASCADE, null=True, blank=True)
    description = models.CharField(max_length=100, blank=True, default=None, null=True)
    src_keyname = models.CharField(max_length=25, blank=True, default=None, null=True)
    is_excluded = models.BooleanField("Exclude when translating", default=False)
    uses_advanced_mapping = models.BooleanField(default=False)
    dst_keyname = models.CharField(max_length=25, blank=True, default=None, null=True)
    simple_value_map = models.CharField("Basic value map: val1=val2||val3=val4", max_length=255, blank=True, default=None, null=True)
    dst_maxlen = models.IntegerField("Dst. Max Length", blank=True, default=None, null=True)
    dst_regex = models.CharField("Dst. Charset (Regex)", max_length=25, blank=True, default=None, null=True)
    dst_repl_char = models.CharField("Dst. Subst. Char", max_length=25, blank=True, default=None, null=True)
    default_if_blank = models.CharField(max_length=100, blank=True, default=None, null=True)
    requires_lookup = models.BooleanField(default=False)
    lookup_generictype = models.ForeignKey(GenericType, on_delete=models.CASCADE, null=True, blank=True,
                                           related_name='lookup_generictype')

    class Meta:
        ordering = ('generictype', 'elementtype')

    def __str__(self):
        return str(self.generictype) + " -- Source:" + str(self.elementtype) + " -- " + str(self.description)


def normalize_data_objects(data_obj_query: Union[list, QuerySet], element_sync_obj: ElementSync, convert_only=False)\
        -> list:
    """
    This function looks at data objects and a specific sync instance to determine how to 'normalize' those data
     objects for various purposes. That will include determining how to transfer those data attributes from one
     system to another, or to be able to compare them amongst themselves despite them being in different formats

    Parameters:
    data_obj_query          A Django QuerySet (or list) representing the list of GenericData elements that we want to
                             normalize
    element_sync_obj        A Django ElementSync model instance representing the sync relationship that we want to
                             normalize against. This gives us information about how many destination targets there are
                             as well as a potential data source for additional records that we may need to cross
                             reference for substitutions, 'id' lookups, etc.
    convert_only            Used to show conversion result from one system to another

    Output:
    normalized_object_list  A list of dictionaries that represents the 'normalized' data.

    Example:
    [{
        'src': {                                                                <-- input from data_obj_query
            'obj': <GenericData: PolicyData::_snip_>,                           <-- original object that came in
            'data': {                                                           <-- original content from source_data
                'name': '',
                'monitorModeEnabled': False,
                'versionNum': 5,
                'catchAllRule': 'deny all',
                'bindingEnabled': True,
                'aclIds': ['14171'],
                'updatedAt': '2021-06-08T01:13:29.865880Z',
                'description': 'Restrict IoT Servers from access IoT Devices',
                'srcGroupId': '16015',
                'dstGroupId': '16016'
            }
        },
        'dst': {                                                                <-- dict of sync destinations
            'd14d534e-a147-410f-98e9-41aacc13c82f': {                           <-- 'id' from Element model record
                'obj': <Element: ISE 2.7(10.102.172.125)> ,                     <-- Element object
                'data': {                                                       <-- Processed data element
                    'name': '',
                    'defaultRule': 'DENY_IP',
                    'matrixCellStatus': 'ENABLED',
                    'sgacls': None,
                    'description': 'Restrict_IoT_Servers_from_access_IoT_Devices',
                    'sourceSgtId': 'ff63d500-a75a-11eb-8ee9-f26679cccb56',      <-- Notice that we transformed the
                    'destinationSgtId': '181fa5e0-bfc2-11eb-a32f-02669290d4af'  <--  key names and the values
                },
                'success': False,                                               <-- There was a problem on this one
                'error': "X-Ref Lookup Failed for aclIds ['14171']"             <-- A record correlating to
            }                                                                    -- '14171' (a source id) doesn't
        }                                                                        -- exist in the db, so we can't
    }]                                                                           -- fully process this record

    What we can learn from this output is that the record that 'sgacls' is pointing at hasn't been synchronized yet.
     Once we create it, it will then have an 'id' that we can look up in order to substitute here. We will need that
     to happen before we can finish working with this specific record, hence the 'success': False indicator
    """
    n_dict = {}
    normalized_object_list = []
    data_obj = data_obj_query[0]
    # for data_obj in data_obj_query:
    if True:
        # Add source and destination to output dict and add objects
        comp_dict = generate_match_comparison(data_obj, None)
        normalized_object_dict = {"src": {"obj": data_obj, "data": {}, "comp": comp_dict}, "dst": {}}
        all_dests = element_sync_obj.dst_element.all()

        # if 1 object is sent, then look at all destinations since we may need to create non-existant ones
        if len(data_obj_query) == 1:
            dests = all_dests
        else:
            # filter which destinations we will evaluate based on 'data_obj_query' parameter
            dests = []
            for obj in data_obj_query:
                if obj.element in all_dests:
                    dests.append(obj.element)

        for dest in dests:
            # only analyze objects that are part of the input set of objects
            gd = GenericData.objects.filter(generic=data_obj.generic).filter(element=dest).first()
            normalized_object_dict["dst"][str(dest.id)] = {"obj": gd, "data": {}, "comp": {},
                                                           "success": True, "error": None}

        # Iterate all sync destinations to construct output dictionary
        for dest in dests:
            dst_obj = GenericData.objects.filter(generic=data_obj.generic).filter(element=dest).first()
            comp_dict = generate_match_comparison(data_obj, dst_obj)
            normalized_object_dict["dst"][str(dest.id)]["comp"] = comp_dict

        for k, v in data_obj.source_data.items():
            # Iterate all sync destinations to construct output dictionary
            # for dest in dests:
            #     dst_obj = GenericData.objects.filter(generic=data_obj.generic).filter(element=dest).first()
            #     comp_dict = generate_match_comparison(data_obj, dst_obj)
            #     normalized_object_dict["dst"][str(dest.id)]["comp"] = comp_dict

            # if src_gd:
            #     new_src = src_gd.get_data(k, safe=False)
            #     k_rule = GenericTypeMatchRule.objects.filter(generictype=data_obj.generictype).\
            #         filter(field__contains=k).first()
            #     if k_rule and k_rule.match:
            #         adv = AdvancedMappingTable.objects.filter(elementtype=data_obj.element.elementtype).\
            #             filter(base_key=k)
            #         new_res = exec_comparison_rule(new_src, k_rule, adv)
            #         print(new_res)
            #         fld_list = k_rule.field.split(",")
            #         if len(fld_list) == 1:
            #             new_k = fld_list[0]
            #         else:
            #             for fld in fld_list:
            #                 if k in fld:
            #                     fld_list.remove(fld)
            #             new_k = fld_list[0].split("||")[0]
            #
            #         if new_res not in ("None", None):
            #             normalized_object_dict["dst"][str(dest.id)]["comp"][new_k] = new_res

            n_key = data_obj.element.elementtype.name + "_" + data_obj.generictype.name + "_" + k
            if n_key not in n_dict:
                bt = BasicMappingTable.objects.filter(elementtype=data_obj.element.elementtype). \
                    filter(generictype=data_obj.generictype).filter(src_keyname=k)
                n_dict[n_key] = bt
            else:
                bt = n_dict[n_key]

            this_bt = bt.first()

            new_v = v
            # If the data is blank and we are supposed to supply a default, add that default
            if new_v == "" and this_bt.default_if_blank:
                new_v = apply_default(data_obj, this_bt)

            # add source data to output dictionary
            normalized_object_dict["src"]["data"][k] = new_v

            # We will ignore any value marked as excluded
            if not this_bt.is_excluded:
                # Check to see if we need to apply a regex substitution or limit the string length
                new_v = clean_string(new_v, this_bt)

                # If a simple value map has been provided, let's process and make the substition in the map
                if this_bt.simple_value_map:
                    new_v = process_value_map(new_v, this_bt.simple_value_map)

                # Check to see if this element needs to use the Advanced Mapping Table
                if this_bt.uses_advanced_mapping:
                    adv = AdvancedMappingTable.objects.filter(elementtype=data_obj.element.elementtype).\
                        filter(base_key=k)
                    new_v, errors = process_advanced_mapping(v, adv)

                # Iterate all sync destinations to construct output array
                for dest in dests:
                    # If the 'requires_lookup' attribute has been specified, let's perform the x-ref lookup
                    if this_bt.requires_lookup and this_bt.lookup_generictype:
                        new_v = lookup_dest_values(v, this_bt.lookup_generictype, dest)
                        # If we get a None result, it means that our x-ref failed... the object probably doesn't
                        #  exist, so we need to indicate an error has occurred
                        if new_v is None:
                            normalized_object_dict["dst"][str(dest.id)]["success"] = False
                            err = "X-Ref Lookup Failed for " + str(k) + " " + str(v)
                            normalized_object_dict["dst"][str(dest.id)]["error"] = err

                    # If the data is blank and we are supposed to supply a default, add that default
                    if new_v == "" and this_bt.default_if_blank:
                        new_v = apply_default(data_obj, this_bt)

                    # Now, we add the modified object to the output dictionary... unless it's "None"
                    if new_v != "None":
                        normalized_object_dict["dst"][str(dest.id)]["data"][this_bt.dst_keyname] = new_v

        # And we add the output dictionary to the output list...
        normalized_object_list.append(normalized_object_dict)

    # print(normalized_object_list)
    return normalized_object_list


def clean_string(input_string: str, basic_mapping_obj: BasicMappingTable) -> str:
    """
    This function is used to enforce any specific character patterns or lengths. So we look for regex
     substitutions and maximum length constraints and then enforce them.

    Parameters:
    input_string        This is the input string; the string that we want to 'clean'
    basic_mapping_obj   This is a Django BasicMappingTable instance; we will look at the 'dst_regex' and
                         'dst_repl_char' fields to see if we need to perform any type of character substitution,
                         and we will then look at 'dst_maxlen' to determine if we need to truncate the string
                         to a provided maximum length

    Output:
    output_string       This is a 'cleaned' string
    """
    output_string = input_string

    # If a regex value is present, let's run that substitution
    if basic_mapping_obj.dst_regex and basic_mapping_obj.dst_repl_char:
        output_string = re.sub(basic_mapping_obj.dst_regex, basic_mapping_obj.dst_repl_char, output_string)

    # If a value is present for maximum length, let's trim the string
    if basic_mapping_obj.dst_maxlen:
        output_string = str(output_string)[:basic_mapping_obj.dst_maxlen]

    return output_string


def apply_default(data_obj: GenericData, basic_mapping_obj: BasicMappingTable) -> str:
    """
    This function is used to generate a default value to replace a blank value with.

    Parameters:
    data_obj            We will look at 'source_data' in this object and look for substitutions based on
                         each key/value pair. i.e., if your dictionary is {'my_key': 'my_value'}, we will look for
                         a substitution variable named '{{my_key}}' and if we find it, we will replace it with
                         'my_value'
    basic_mapping_obj   This is a Django BasicMappingTable instance; if this specific instance has a default
                         value specified, we will then attempt to perform any variable substitution and return
                         the result (as a string). We also utilize the clean_string function to ensure we don't
                         have any invalid characters or lengths

    Output:
    output_string       A string representing the 'default' value
    """
    data_dict = data_obj.source_data
    output_string = basic_mapping_obj.default_if_blank
    for k, v in data_dict.items():
        output_string = output_string.replace("{{" + str(k) + "}}", str(v))
    output_string = clean_string(output_string, basic_mapping_obj)
    # perform a substitution for key_value if that is required
    output_string = output_string.replace("_key_value_", str(data_obj.generic.key_value))

    return output_string


def process_advanced_mapping(input_list: list, advanced_mapping_query: QuerySet) -> Tuple[Union[list, str], list]:
    """
    This function will evalute all objects in a list against the specified advanced lookup fields
     to derive a modified output result. Currently used to translate ISE aclcontent <-> Meraki ACL rules

    input_list              A list of dicts that we will iterate in an attempt to execute the advanced mapping table
                             rules against
    advanced_mapping_query  A Django QuerySet result of applicable elements from the AdvancedMappingTable model.
                             These records should match the elementtype of the source that provides the input_list,
                             and should be filtered by the base_key that the input_list came from.
    """
    bad_keys = []
    maps = advanced_mapping_query
    flatten_text = False
    out_rules = []
    # Iterate source list (such as 'rules' for meraki or 'aclcontent' for ISE)
    for rule in input_list:
        if not rule:
            return [], [{"error": "no rule provided", "rules": input_list}]
        elif isinstance(rule, str):
            # if this is a string, a text-based ACL was probably sent in...
            return [], [{"error": "invalid rule provided", "rules": input_list}]

        txt_flds = []
        # sel = None
        out_rule = {}
        # Each item in the list should be a dictionary; iterate based on key/value pairs
        for k, v in rule.items():
            obj = None
            # Check to see if we need to perform a regex source match first
            rgx_test = maps.filter(json_key_1=str(k)).filter(json_val_1_regex=True)
            if len(rgx_test) > 0:
                for r in rgx_test:
                    # regex check present; let's see if this value matches the regex...
                    if re.match(r.json_val_1, str(v)):
                        obj = r
                        break
            else:
                # These are the various different ways that we can search for our key/value in the source dataset
                obj_kv = maps.filter(json_key_1=str(k)).filter(json_val_1=v)
                obj_eq = maps.filter(json_key_1=str(k) + "=" + str(v))
                obj_bs = maps.filter(json_val_1=v)
                obj_ls = maps.filter(json_key_1=k)      # last resort
                if len(obj_kv) > 0:
                    obj = obj_kv.first()
                elif len(obj_eq) > 0:
                    obj = obj_eq.first()
                elif len(obj_bs) > 0:
                    obj = obj_bs.first()
                elif len(obj_ls) > 0:
                    obj = obj_ls.first()
                else:
                    obj = None
                    bad_keys.append({"error": "unrecognized attribute", "rule": rule, "key": k, "value": v})
                    continue

            # We didn't get a hit on any of our searches; continue to next element
            if not obj:
                bad_keys.append({"error": "unable to find match", "rule": rule, "key": k, "value": v})
                continue

            # Make sure the value isn't part of the ignored list of attributes
            if not obj.json_key_1_ignored and not obj.json_key_2_ignored:
                key_data = obj.json_key_2
                val_data = obj.json_val_2
                # Output needs to be flat text (i.e., ISE 'aclcontent').
                if obj.use_flat_text:
                    flatten_text = True
                    val_data = obj.output_flat_text if obj.output_flat_text else ""
                    val_list = re.split(obj.json_val_1, str(v))
                    # Variable substitution
                    if "{{" in val_data:
                        for x in range(0, len(val_list)):
                            val_data = val_data.replace("{{v" + str(x) + "}}", str(val_list[x]))
                    if val_data != "":
                        txt_flds.append(val_data)
                # Check for variable substitution and combined key/value mapping
                elif "{{" in val_data and "=" in val_data:
                    val_list = re.split(obj.json_val_1, str(v))
                    for x in range(0, len(val_list)):
                        val_data = val_data.replace("{{v" + str(x) + "}}", str(val_list[x]))
                    vds = val_data.split(",")
                    for vd in vds:
                        kd_list = vd.split("=")
                        out_rule[kd_list[0]] = kd_list[1]
                # Check for variable substitution
                elif "{{" in val_data:
                    val_src_list = obj.json_val_1.split(",")
                    for v_dst in range(0, len(val_src_list)):
                        repl_search = "{{v" + str(v_dst+1) + "}}"
                        repl_subst = rule.get(val_src_list[v_dst])
                        val_data = val_data.replace(repl_search, str(repl_subst))
                # Nothing special; send it through!
                else:
                    out_rule[key_data] = val_data

                # handles case where the key is set to something like dst_oper=eq
                if key_data and "=" in key_data:
                    kd_list = key_data.split("=")
                    out_rule[kd_list[0]] = kd_list[1]
                else:
                    out_rule[key_data] = val_data

        # some elements require certain data elements; check for missing required keys and add defaults...
        reqs = maps.filter(json_key_2_required=True)
        for req in reqs:
            req_k = req.json_key_2
            req_dv = req.json_val_2_default
            if req_k not in out_rule:
                out_rule[req_k] = req_dv

        # Part of the use_flat_text output; transform list back into string
        if len(txt_flds) > 0:
            acl = " ".join(txt_flds)
            out_rules.append(acl)
        else:
            out_rules.append(out_rule)

    # Part of the use_flat_text output; transform list back into string
    if flatten_text:
        return "\n".join(out_rules), bad_keys

    return out_rules, bad_keys


def lookup_dest_values(value: Union[str, list], lookup_generictype_obj: GenericType, dst_element_obj: Element) -> \
        Union[None, str, list]:
    """
    This function is used to lookup a record based on another key

    Parameters:
    value                       A string or list of strings that represent 'id'(s) of a/record(s) to look up
    lookup_generictype_obj      A Django GenericType model record that we are going to search against (we will be
                                 searching the source_id field of this type of record using value to attempt to
                                 find a match)
    dst_element_obj             The target element that we want to find the match for. So, we find the source data
                                 object based on the value 'id'. Then, we look at all linked records to find
                                 the record that is attached to this supplied element. Then we will return the
                                 source_id of that record as our output

    Output:
    out_vals                    None, a list of values, or a single value. Single or list value based on whether
                                 the input was a single or a list. If we return None, it means we didn't find a
                                 match
    """
    # if we don't have a list, we will make a list. but we also need to save the state of whether we are working
    #  with a list or not, because we want the output to be in the same format
    if not isinstance(value, list):
        new_v = [value]
        input_list = False
    else:
        new_v = value
        input_list = True

    out_vals = []

    # iterate the list...
    for v in new_v:
        # search for all data records that match the generictype that we supplied, that match the current id in
        #  the list of ids
        gd = GenericData.objects.filter(generictype=lookup_generictype_obj).filter(source_id=v).first()
        # If we found a match, and if that data element is linked to a 'generic' object, we will continue...
        if gd and gd.generic:
            dest_gds = GenericData.objects.filter(generic=gd.generic).filter(element=dst_element_obj)
            # this should only not return results if the referenced object doesn't exist on the source. i.e.,
            #  if this is a policy that references a SGT, that SGT must not have been created yet
            if len(dest_gds) == 0:
                return None

            for d in dest_gds:
                out_vals.append(d.source_id)
        else:
            # print("no match", lookup_generictype_obj, v)
            out_vals.append(None)

    # now we want to match the input format. if we were provided a list, return a list. if we were provided
    #  a string, return a string
    if not input_list:
        if len(out_vals) > 0:
            return out_vals[0]
        else:
            return None
    else:
        return out_vals


def process_value_map(value: str, value_map: str) -> Union[None, str]:
    """
    This function is used to parse a basic value map and return an equivalent value to the one provided

    Parameters:
    value       A value to find the equivalent value of. Example: any
    value_map   A specially format of pairs of equivalent values. Example:
                 ipv4=IPV4||ipv6=IPV6||any=None||agnostic=None

    Output:
    out_value   The equivalent value. In the above example, the return would be None
    """
    value_list = value_map.split("||")
    for value_item in value_list:
        if str(value) in value_item:
            value_item_list = value_item.split("=")
            value_item_list.remove(str(value))
            if len(value_item_list) == 1:
                return value_item_list[0]
    return None


def generate_match_comparison(source_data_obj: GenericData, dest_data_obj: Union[GenericData, None]) -> \
        Union[None, dict]:
    """
    This function looks at a source GenericData object and optionall a destination GenericData object
    and generates the structure to determine whether they match or not

    Parameters:
        source_data_obj     Source GenericData object
        dest_data_obj       Destination GenericData object (optional)

    Output:
        out_r_dict          Dictionary with the comparision rules and data
    """
    # if there is no destination (i.e., we may just be generating comparision results for the source), or
    #  if the source type is the same as the destination type (i.e., Meraki -> Meraki), we need to flag that
    #  and not convert the output
    if not dest_data_obj or source_data_obj.element.elementtype == dest_data_obj.element.elementtype:
        do_conversion = False
        # source_type = source_data_obj.element.elementtype
        # dest_type = None
    else:
        do_conversion = True
        # source_type = source_data_obj.element.elementtype
        # dest_type = dest_data_obj.element.elementtype

    # if there is no destination (i.e., we may just be generating comparision results for the source), we will
    #  store the source data object as our reference data. otherwise, we will use the destination
    if not dest_data_obj:
        data_obj = source_data_obj
    else:
        data_obj = dest_data_obj

    # grab the list of match rules that we will be evaluating to determine comparisions
    match_rules = GenericTypeMatchRule.objects.filter(generictype=source_data_obj.generictype)

    # dead end, we want to iterate the rules, not the k/v pairs
    # now, we iterate all of the key/value pairs in the data of the selected object...
    # for k, v in data_obj.source_data.items():
    #     this_rule = match_rules.filter(filter_field__contains="/"+k+"/")
    #     if len(this_rule) != 1:
    #         print(k, len(match_rules), data_obj.generictype, this_rule)
    #     if len(this_rule) == 1 and this_rule.first().match:
    #         print(k, v, this_rule)
    out_r_dict = {}
    for mr in match_rules:
        if mr.match:
            this_field, this_data, orig_data = get_data_from_obj(data_obj, mr.field, do_conversion, mr.match_type)
            if mr.equivalence_mapping and do_conversion:
                comp_list = mr.equivalence_mapping.split("||")
                # print(this_data, comp_list)
                # since there can be multiple sets of equivalencies, we need to determine which one to use...
                for comp in comp_list:
                    comp_vals = comp.split("=")
                    # grp["objs"][0] represents (hopefully?) "source" object, so see if this is the group to use...
                    if str(this_data) in comp_vals:
                        comp_vals.remove(str(this_data))
                        this_data = comp_vals[0]
                        if this_data == "True":
                            this_data = True
                        if this_data == "False":
                            this_data = False
                        break
            elif mr.match_type == "AdvancedMappingTable" and do_conversion:
                # Use the AdvancedMappingTable for translation... this is used for ACLs currently
                adv = AdvancedMappingTable.objects.filter(elementtype=data_obj.element.elementtype). \
                    filter(base_key=this_field)
                new_v, errors = process_advanced_mapping(this_data, adv)
                this_data = new_v

            if not this_data or this_data == "None":
                bt = BasicMappingTable.objects.filter(elementtype=data_obj.element.elementtype). \
                    filter(generictype=data_obj.generictype).filter(src_keyname=this_field).first()
                if bt:
                    # print("**default", mr, data_obj, this_field, this_data, bt)
                    this_data = apply_default(data_obj, bt)
                # else:
                #     print("**", mr, data_obj, this_field, this_data, bt)

            out_r_dict[str(mr.id)] = {"data": this_data, "obj": mr, "orig": orig_data}

    # print(source_data_obj, dest_data_obj, do_conversion, source_type, dest_type, match_rules)
    return out_r_dict


def get_data_from_obj(data_obj: GenericData, mr_fields: str, do_conversion: bool, match_type: str) -> \
        Tuple[str, Union[None, str, list, dict], Union[None, str, list, dict]]:
    """
    This function takes in a GenericData object and a list of fields and returns the first
    bit of data that it finds in one of those fields

    Parameters:
        data_obj        GenericData object to search
        mr_fields       Comma separated string that has the list of fields that we want to look for in the data_obj
                         Can also include ||ACEParser to convert ISE SGACLs to JSON format
        do_conversion   Boolean that dictates whether we will return the raw data or convert it (specific to
                         ACEParser currently)
        match_type      String that specifies the match type. This is only used to see if we need to clean the
                         output or not.

    Output:
        out_field       A string value of the key that the data came from. Used when d_val is blank to see
                         if a default value needs to be looked up or constructed
        d_val           Any number of potential datatypes with the resultant data.
    """
    d_val = None
    out_field = None
    orig_data = None
    # split the fields, which are comma separated
    mr_field_list = mr_fields.split(",")
    # iterate each one. once we find a match, we will 'break' this loop
    for mr_field in mr_field_list:
        # double tilde (~~) denotes that we need to run a helper function for some type of processing
        if "~~" in mr_field:
            k_lst = mr_field.split("~~")
            # ACEParser is used to parse plain text SGACLs from ISE into JSON friendly format
            if k_lst[1] == "ACEParser":
                p_dat = data_obj.get_data(k_lst[0])
                orig_data = p_dat
                if p_dat:
                    # If we don't need to convert, we just want the text rules
                    if not do_conversion:
                        d_val = p_dat
                        out_field = k_lst[0]
                        break
                    # Otherwise, iterate the list of rules and convert
                    else:
                        d_val = []
                        for p in p_dat.split("\n"):
                            ap_val = ace_parser.parseString(p).asDict()
                            # we always want this output to be a list
                            d_val.append(ap_val)
                        out_field = k_lst[0]
                        break
                else:
                    d_val = None
        else:
            # otherwise just do a straight lookup
            orig_data = data_obj.get_data(mr_field)
            if match_type == "cleaned":
                d_val = data_obj.get_data(mr_field, safe=True)
            else:
                d_val = data_obj.get_data(mr_field)
            # print(mr_field, d_val)
            if d_val:
                if "::" in mr_field:
                    mr_field_list = mr_field.split("::")
                    # print(mr_field_list)
                    out_field = mr_field_list[-1]
                else:
                    out_field = mr_field
                break

    # return the result
    # print(out_field, d_val, data_obj)
    return out_field, d_val, orig_data


# def exec_comparison_rule(value: str, rule_obj: GenericTypeMatchRule, advanced_mapping_query: QuerySet) -> \
#         Union[None, dict, str]:
#     current_comp = None
#     result = None
#     # print(value, rule_obj, rule_obj.equivalence_mapping, rule_obj.match_type)
#     if rule_obj.equivalence_mapping:
#         comp_list = rule_obj.equivalence_mapping.split("||")
#         # since there can be multiple sets of equivalencies, we need to determine which one to use...
#         for comp in comp_list:
#             comp_vals = comp.split("=")
#             # grp["objs"][0] represents (hopefully?) "source" object, so see if this is the group to use...
#             if str(value) in comp_vals:
#                 result = comp_vals.remove(str(value))
#                 break
#         #
#         # # just in case equivalence wasn't needed, do a secondary check to see if values match exactly
#         # grp_result = all(element == grp["objs"][0] for element in grp["objs"])
#         # if grp_result:
#         #     result = True
#         #     grp["match"] = True
#     elif rule_obj.match_type == "AdvancedMappingTable":
#         # Use the AdvancedMappingTable for translation... this is used for ACLs currently
#         # converted_rules, errors = self.exec_mapping_table([value], 1)
#         converted_rules, errors = process_advanced_mapping([value], advanced_mapping_query)
#         # result = converted_rules
#         out_rules = []
#         # print(converted_rules)
#         result = "\n".join(converted_rules)
#         # for rule in converted_rules:
#         #     print(rule)
#
#     #     if not grp_result:
#     #         result = False
#     #         grp["match"] = False
#     else:
#         # not using equivalencies makes this process much simpler...
#         if rule_obj.match_type == "cleaned":
#             bt = BasicMappingTable.objects.filter(elementtype=rule_obj.elementtype). \
#                 filter(generictype=data_obj.generictype).filter(src_keyname=k)
#             result = clean_string(value, BasicMappingTable.objects.all())
#         else:
#             result = value
#     #     grp_result = all(element == grp["objs"][0] for element in grp["objs"])
#     #     if not grp_result:
#     #         result = False
#     #         grp["match"] = False
#     return result
