from django.db import models
import django.utils.timezone
import uuid
import json
from django.db.models.signals import post_save
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
    raw_data = models.TextField(blank=True, null=True, default=None)
    force_rebuild = models.BooleanField("Force Dashboard Sync", default=False, editable=True)
    skip_sync = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_sync = models.DateTimeField(null=True, default=None, blank=True)

    def __str__(self):
        dbs = self.dashboard_set.all()
        if len(dbs) == 1:
            return dbs[0].description + " (" + self.orgid + ")"
        return self.orgid


@receiver(post_save, sender=Organization)
def post_save_organization(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_organization, sender=Organization)
    if instance and instance.force_rebuild:
        TagData.objects.filter(organization=instance).update(update_failed=False)
        ACLData.objects.filter(organization=instance).update(update_failed=False)
        PolicyData.objects.filter(organization=instance).update(update_failed=False)
    post_save.connect(post_save_organization, sender=Organization)


class Dashboard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Dashboard Integration Description", max_length=100, blank=False, null=False)
    baseurl = models.CharField("Base URL", max_length=64, null=False, blank=False,
                               default="https://api.meraki.com/api/v1")
    apikey = models.CharField("API Key", max_length=64, null=False, blank=False)
    webhook_enable = models.BooleanField(default=False, editable=True)
    webhook_ngrok = models.BooleanField(default=False, editable=True)
    webhook_url = models.CharField(max_length=200, null=True, blank=True, default=None)
    raw_data = models.JSONField(blank=True, null=True, default=None)
    organization = models.ManyToManyField(Organization, blank=True)
    force_rebuild = models.BooleanField("Force Dashboard Sync", default=False, editable=True)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_sync = models.DateTimeField(null=True, default=None, blank=True)

    def __str__(self):
        return self.description


@receiver(post_save, sender=Dashboard)
def post_save_dashboard(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_dashboard, sender=Dashboard)
    if instance.force_rebuild:
        Organization.objects.filter(dashboard=instance).update(force_rebuild=True)
        instance.force_rebuild = False
        instance.save()
    post_save.connect(post_save_dashboard, sender=Dashboard)


class ISEServer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("ISE Server Description", max_length=100, blank=False, null=False)
    ipaddress = models.CharField("ISE IP or FQDN", max_length=64, null=False, blank=False)
    username = models.CharField(max_length=64, null=True, blank=True, default=None, verbose_name="ERS Username")
    password = models.CharField(max_length=64, null=True, blank=True, default=None, verbose_name="ERS Password")
    raw_data = models.TextField(blank=True, null=True, default=None)
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


class ISEMatrix(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ise_id = models.CharField(max_length=64, null=False, blank=False)
    name = models.CharField(max_length=64, null=False, blank=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name


class SyncSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Sync Description", max_length=100, blank=False, null=False)
    dashboard = models.ForeignKey(Dashboard, on_delete=models.SET_NULL, null=True, blank=True)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True,
                                  verbose_name="ISE Server")
    ise_source = models.BooleanField("Make ISE Config Base", default=True, editable=True)
    force_rebuild = models.BooleanField("Force All Server Sync", default=False, editable=True)
    sync_enabled = models.BooleanField("Perform Server Sync", default=True, editable=True)
    apply_changes = models.BooleanField("Execute API Changes", default=True, editable=True)
    sync_interval = models.IntegerField(blank=False, null=False, default=300)
    last_update = models.DateTimeField(default=django.utils.timezone.now)

    def __str__(self):
        return self.description


@receiver(post_save, sender=SyncSession)
def post_save_syncsession(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_syncsession, sender=SyncSession)
    if instance.force_rebuild:
        instance.force_rebuild = False
        instance.dashboard.force_rebuild = True
        instance.dashboard.save()
        instance.iseserver.force_rebuild = True
        instance.iseserver.save()
        instance.save()
    post_save.connect(post_save_syncsession, sender=SyncSession)


class Tag(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Tag Name", max_length=50, blank=False, null=False)
    description = models.CharField("Tag Description", max_length=200, blank=True, null=False)
    do_sync = models.BooleanField("Sync this Tag?", default=False, editable=True)
    syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
    tag_number = models.IntegerField(blank=False, null=False, default=0)
    origin_ise = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)
    origin_org = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    push_delete = models.BooleanField(default=False, editable=False)

    class Meta:
        ordering = ('tag_number',)

    def __str__(self):
        return self.name + " (" + str(self.tag_number) + ")"

    def get_objects(self):
        return self.tagdata_set.all()

    def last_update(self):
        objs = self.get_objects()
        lu = None
        for o in objs:
            if o.last_update or (lu and o.last_update and o.last_update > lu):
                lu = o.last_update

        if not lu:
            return "Never"
        return lu

    def objects_desc(self):
        out = []
        for d in self.get_objects():
            out.append(str(d))

        return "\n".join(out)

    def update_success(self):
        if self.do_sync:
            if not self.objects_in_sync():
                return False

            return True

        return None

    def objects_in_sync(self):
        return self.objects_match(bool_only=True)

    def object_update_target(self):
        return self.objects_match(get_target=True)

    def objects_match(self, bool_only=False, get_target=None):
        full_match = True
        header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "Pending Delete"]
        combined_vals = {}
        f = [""] * len(header)
        expected_vals = [""] * len(header)
        match_required = [True] * len(header)
        for hnum in range(0, len(header)):
            combined_vals[str(hnum)] = []
        out = "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
        for o in self.get_objects():
            try:
                if not o.source_data:
                    jo = {}
                else:
                    jo = json_try_load(o.source_data, {})
                a0 = o.hyperlink()
                a1 = jo.get("name", "UNKNOWN")
                a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
                a3 = jo.get("description", "UNKNOWN")
                a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
                a5 = str(o.tag.push_delete)

                f = [a0, a1, a2, a3, a4, a5]
                expected_vals = [None, None, None, None, None, "False"]
                match_required = [False, False, True, False, True, True]
                for x in range(1, len(header)):
                    combined_vals[str(x)].append(f[x])
            except Exception as e:
                print("exception", e)
                jo = {}
            out += "<tr><td>" + "</td><td>".join(f) + "</td></tr>"

        out += "<tr><td><i>Matches?</i></td>"
        for x in range(1, len(header)):
            matches = chk_list(combined_vals[str(x)], expected_vals[x])
            if not matches and match_required[x]:
                full_match = False
            out += "<td>" + str(matches) + "</td>"
        out += "</tr></table>"

        if self.tag_number == 0:
            out += "<hr><b><u>NOTE:THIS TAG (0) WILL ALWAYS RETURN matches=True. WE DO NOT WANT TO SYNC IT.</b></u>"
            if bool_only:
                return True
        elif self.tag_number == 2:
            out += "<hr><b><u>NOTE:THIS TAG (2) WILL ALWAYS RETURN matches=True. WE DO NOT WANT TO SYNC IT.</b></u>"
            if bool_only:
                return True

        if get_target:
            if not full_match:
                if self.origin_ise:
                    return "meraki"
                else:
                    return "ise"
            return None
        elif bool_only:
            return full_match
        else:
            return format_html(out)

    def cleaned_name(self):
        newname = self.name[:32]
        newname = re.sub('[^0-9a-zA-Z]+', '_', newname)
        return newname

    def in_sync(self):
        return self.objects_match(bool_only=True)


@receiver(post_save, sender=Tag)
def post_save_tag(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_tag, sender=Tag)
    if instance:
        instance.last_updated = datetime.datetime.now()
        instance.save()

        policies = Policy.objects.filter(Q(source_group=instance) | Q(dest_group=instance))
        for p in policies:
            if p.source_group and p.source_group.do_sync and p.dest_group and p.dest_group.do_sync:
                p.do_sync = True
            else:
                p.do_sync = False
            p.save()
    post_save.connect(post_save_tag, sender=Tag)


class ACL(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("Tag Name", max_length=50, blank=False, null=False)
    description = models.CharField("Tag Description", max_length=100, blank=False, null=False)
    do_sync = models.BooleanField("Sync this ACL?", default=False, editable=True)
    syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
    origin_ise = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)
    origin_org = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    visible = models.BooleanField(default=True, editable=False)
    push_delete = models.BooleanField(default=False, editable=False)

    class Meta:
        verbose_name = "ACL"
        verbose_name_plural = "ACLs"

    def __str__(self):
        return self.name

    def get_objects(self):
        return self.acldata_set.all()

    def last_update(self):
        objs = self.get_objects()
        lu = None
        for o in objs:
            if o.last_update or (lu and o.last_update and o.last_update > lu):
                lu = o.last_update

        if not lu:
            return "Never"
        return lu

    def objects_desc(self):
        out = []
        for d in self.get_objects():
            out.append(str(d))

        return "\n".join(out)

    def update_success(self):
        if self.do_sync and self.visible:
            if not self.objects_in_sync():
                return False

            return True

        return None

    def objects_in_sync(self):
        return self.objects_match(bool_only=True)

    def object_update_target(self):
        return self.objects_match(get_target=True)

    def objects_match(self, bool_only=False, get_target=False):
        full_match = True
        header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "ACL", "Version",
                  "Pending Delete"]
        combined_vals = {}
        f_show = f_comp = [""] * len(header)
        expected_vals = [""] * len(header)
        match_required = [True] * len(header)
        custom_match_list = [None] * len(header)
        for hnum in range(0, len(header)):
            combined_vals[str(hnum)] = []
        out = "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
        for o in self.get_objects():
            try:
                if not o.source_data:
                    jo = {}
                    a6 = jo.get("ipVersion", "UNKNOWN")
                else:
                    jo = json_try_load(o.source_data, {})
                    a6 = jo.get("ipVersion", "IP_AGNOSTIC")
                a0 = o.hyperlink()
                a1 = jo.get("name", "UNKNOWN")
                a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
                a3 = jo.get("description", "UNKNOWN")
                a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
                a5_show = htmlprep(jo.get("rules")) if o.organization else jo.get("aclcontent", "")
                a5_comp = self.normalize_meraki_rules(jo.get("rules"), mode="convert") if o.organization else \
                    jo.get("aclcontent")
                a7 = str(o.acl.push_delete)

                f_show = [a0, a1, a2, a3, a4, a5_show, a6, a7]
                f_comp = [a0, a1, a2, a3, a4, a5_comp, a6, a7]
                expected_vals = [None, None, None, None, None, None, None, "False"]
                match_required = [False, False, True, False, True, True, True, True]
                custom_match_list[6] = [["agnostic", "IP_AGNOSTIC"], ["ipv4", "IPV4"], ["ipv6", "IPV6"]]
                for x in range(1, len(header)):
                    combined_vals[str(x)].append(f_comp[x])
            except Exception as e:
                print("Exception", e)
                jo = {}
            out += "<tr><td>" + "</td><td>".join(f_show) + "</td></tr>"

        out += "<tr><td><i>Matches?</i></td>"
        for x in range(1, len(header)):
            matches = chk_list(combined_vals[str(x)], expected_vals[x], custom_match_list[x])
            if not matches and match_required[x]:
                full_match = False
            out += "<td>" + str(matches) + "</td>"
        out += "</tr></table>"

        if not self.visible:
            out += "<hr><b><u>NOTE:THIS SGACL WILL ALWAYS RETURN matches=True SINCE IT IS BUILT-IN.</b></u>"
            if bool_only:
                return True

        if get_target:
            if not full_match:
                if self.origin_ise:
                    return "meraki"
                else:
                    return "ise"
            return None
        elif bool_only:
            return full_match
        else:
            return format_html(out)

    def cleaned_name(self):
        newname = self.name[:32]
        newname = re.sub('[^0-9a-zA-Z]+', '_', newname)
        return newname

    def in_sync(self):
        return self.objects_match(bool_only=True)

    def make_port_list(self, port_range):
        p_list = []
        if "," in port_range:
            l_range = port_range.split(",")
            for l_prt in l_range:
                if "-" in l_prt:
                    r_range = l_prt.split("-")
                    for x in range(r_range[0], r_range[1]):
                        p_list.append(x)
                else:
                    p_list.append(l_prt)
            return "eq " + " ".join(p_list)
        if "-" in port_range:
            r_range = port_range.split("-")
            return "range " + str(r_range[0]) + " " + str(r_range[1])

        return "eq " + str(port_range)

    def normalize_meraki_rules(self, rule_list, mode="compare"):
        if not rule_list:
            return ""

        if mode == "compare":
            outtxt = ""
            for r in rule_list:
                if r["policy"] is None:
                    return ""
                elif r["policy"] == "allow":
                    outtxt += "permit "
                elif r["policy"] == "deny":
                    outtxt += "deny "
                if r["protocol"] == "any":
                    outtxt += "any"
                else:
                    outtxt += r["protocol"].lower().strip()
                    if r["srcPort"] != "any":
                        outtxt += " src " + self.make_port_list(r["srcPort"])
                    if r["dstPort"] != "any":
                        outtxt += " dst " + self.make_port_list(r["dstPort"])

                outtxt = outtxt.strip() + "\n"
            return outtxt[:-1].strip()
        elif mode == "convert":
            outtxt = ""
            for r in rule_list:
                if r["policy"] == "allow":
                    outtxt += "permit "
                elif r["policy"] == "deny":
                    outtxt += "deny "
                if r["protocol"] == "any" or r["protocol"] == "all":
                    outtxt += "ip"
                else:
                    outtxt += r["protocol"].lower().strip()
                    if r["srcPort"] != "any":
                        outtxt += " src " + self.make_port_list(r["srcPort"])
                    if r["dstPort"] != "any":
                        outtxt += " dst " + self.make_port_list(r["dstPort"])

                outtxt = outtxt.strip() + "\n"
            return outtxt[:-1]
        return ""

    def normalize_ise_rules(self, rule_str, mode="compare"):
        if mode == "compare":
            out_txt = ""
            out_rule = rule_str.replace(" log", "").strip().replace("ip", "any").strip()
            l_rule = out_rule.split("\n")
            for l_prt in l_rule:
                if "remark" not in l_prt:
                    out_txt += l_prt + "\n"
            return out_txt[:-1]
        elif mode == "convert":
            outr_list = []
            lst_rules = rule_str.split("\n")
            for l_prt in lst_rules:
                br_rule = l_prt.split(" ")[1:]
                if "permit" in l_prt:
                    this_pol = "allow"
                elif "deny" in l_prt:
                    this_pol = "deny"
                else:
                    this_pol = None

                if this_pol and len(br_rule) > 0:
                    if br_rule[0] == "any" or br_rule[0] == "all" or br_rule[0] == "ip":
                        this_proto = "any"
                    else:
                        this_proto = br_rule[0]
                    if "src" not in l_prt:
                        this_src = "any"
                    else:
                        s_start = False
                        s_range = False
                        the_range = []
                        for b in br_rule:
                            if b.lower() == "src":
                                s_start = True
                            elif s_start and b.lower() == "range":
                                s_range = True
                            elif b.lower() == "dst":
                                s_start = False
                            elif s_start and b.lower() != "eq" and b.lower() != "log":
                                the_range.append(b)
                        if s_range and len(the_range) > 1:
                            this_src = str(the_range[0]) + "-" + str(the_range[1])
                        else:
                            this_src = ",".join(the_range)
                    if "dst" not in l_prt:
                        this_dst = "any"
                    else:
                        d_start = False
                        d_range = False
                        the_range = []
                        for b in br_rule:
                            if b.lower() == "dst":
                                d_start = True
                            elif d_start and b.lower() == "range":
                                d_range = True
                            elif d_start and b.lower() != "eq" and b.lower() != "log":
                                the_range.append(b)
                        if d_range and len(the_range) > 1:
                            this_dst = str(the_range[0]) + "-" + str(the_range[1])
                        else:
                            this_dst = ",".join(the_range)
                    outr_list.append({"policy": this_pol, "protocol": this_proto, "srcPort": this_src,
                                      "dstPort": this_dst})
            return outr_list

        return ""

    def is_valid_config(self):
        objs = self.get_objects()
        for o in objs:
            if o.iseserver and o.source_data and o.source_id:
                idata = json_try_load(o.source_data, {})
                test_ise_acl_1 = self.normalize_ise_rules(idata["aclcontent"]).strip().replace("\n", ";")
                test_meraki_acl = self.normalize_ise_rules(idata["aclcontent"], mode="convert")
                test_ise_acl_2 = self.normalize_meraki_rules(test_meraki_acl,
                                                             mode="convert").strip().replace("\n", ";")
                test_ise_acl_3 = self.normalize_ise_rules(test_ise_acl_2)
                ise_valid_config = test_ise_acl_1 == test_ise_acl_3
                return ise_valid_config
        return True


@receiver(post_save, sender=ACL)
def post_save_acl(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_acl, sender=ACL)
    if instance:
        instance.last_updated = datetime.datetime.now()
        instance.save()
    post_save.connect(post_save_acl, sender=ACL)


class Policy(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mapping = models.CharField("Policy Mapping", max_length=50, blank=False, null=False)
    name = models.CharField("Policy Name", max_length=100, blank=True, null=True)
    source_group = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, related_name="source_group")
    dest_group = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, related_name="dest_group")
    acl = models.ManyToManyField(ACL, blank=True, related_name="policies")
    description = models.CharField("Policy Description", max_length=100, blank=True, null=True)
    do_sync = models.BooleanField("Sync this Policy?", default=False, editable=True)
    syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
    origin_ise = models.ForeignKey(ISEServer, on_delete=models.SET_NULL, null=True, blank=True)
    origin_org = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    push_delete = models.BooleanField(default=False, editable=False)

    class Meta:
        verbose_name_plural = "policies"

    def __str__(self):
        return self.name + " (" + self.mapping + ")"

    def get_objects(self):
        return self.policydata_set.all()

    def last_update(self):
        objs = self.get_objects()
        lu = None
        for o in objs:
            if o.last_update or (lu and o.last_update and o.last_update > lu):
                lu = o.last_update

        if not lu:
            return "Never"
        return lu

    def objects_desc(self):
        out = []
        for d in self.get_objects():
            out.append(str(d))

        return "\n".join(out)

    def update_success(self):
        if self.do_sync:
            if not self.objects_in_sync():
                return False

            return True

        return None

    def objects_in_sync(self):
        return self.objects_match(bool_only=True)

    def object_update_target(self):
        return self.objects_match(get_target=True)

    def objects_match(self, bool_only=False, get_target=False):
        full_match = True
        header = ["Source", "Name", "Cleaned Name", "Description", "Fuzzy Description", "Source", "Dest",
                  "Default Rule", "SGACLs", "Pending Delete"]
        combined_vals = {}
        f_show = f_comp = [""] * len(header)
        expected_vals = [""] * len(header)
        match_required = [True] * len(header)
        custom_match_list = [None] * len(header)
        for hnum in range(0, len(header)):
            combined_vals[str(hnum)] = []
        out = "<table><tr><th>" + "</th><th>".join(header) + "</th></tr>"
        for o in self.get_objects():
            try:
                if not o.source_data:
                    jo = {}
                else:
                    jo = json_try_load(o.source_data, {})
                src_sgt, dst_sgt = self.lookup_sgts(o)
                raw_sgacls = self.lookup_sgacls(o)
                sgacls = []
                sgacl_ids = []
                for a in raw_sgacls or []:
                    sgacls.append(a.acl.name)
                    sgacl_ids.append(a.acl.id)

                a0 = o.hyperlink()
                a1 = jo.get("name", "UNKNOWN")
                a2 = re.sub('[^0-9a-zA-Z]+', '_', jo.get("name", "UNKNOWN")[:32])
                a3 = jo.get("description", "UNKNOWN")
                a4 = jo.get("description", "UNKNOWN").translate(str.maketrans('', '', string.punctuation)).lower()
                a5 = str(src_sgt.tag.tag_number) if src_sgt else "N/A"
                a6 = str(dst_sgt.tag.tag_number) if dst_sgt else "N/A"
                a7 = jo.get("catchAllRule", "UNKNOWN") if o.organization else jo.get("defaultRule", "UNKNOWN")
                a8 = str(sgacls)
                a9 = str(o.policy.push_delete)

                f_show = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9]
                f_comp = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9]
                expected_vals = [None, None, None, None, None, None, None, None, None, "False"]
                match_required = [False, False, True, False, True, True, True, True, True, True]
                custom_match_list[7] = [["global", "NONE"], ["deny all", "DENY_IP"],
                                        ["allow all", "permit all", "PERMIT_IP"]]
                custom_match_list[8] = [["['Permit IP']", "[]"], ["['Deny IP']", "[]"]]
                for x in range(1, len(header)):
                    combined_vals[str(x)].append(f_comp[x])
            except Exception as e:
                print("Exception", e, traceback.format_exc())
                jo = {}
            out += "<tr><td>" + "</td><td>".join(f_show) + "</td></tr>"

        out += "<tr><td><i>Matches?</i></td>"
        for x in range(1, len(header)):
            matches = chk_list(combined_vals[str(x)], expected_vals[x], custom_match_list[x])
            if not matches and match_required[x]:
                full_match = False
            out += "<td>" + str(matches) + "</td>"
        out += "</tr></table>"

        if get_target:
            if not full_match:
                if self.origin_ise:
                    return "meraki"
                else:
                    return "ise"
            return None
        elif bool_only:
            return full_match
        else:
            return format_html(out)

    def cleaned_name(self):
        newname = self.name[:32]
        newname = re.sub('[^0-9a-zA-Z-]+', '_', newname)
        return newname

    def lookup_sgts(self, object):
        if object.source_id and object.source_data:
            data = json_try_load(object.source_data, {"srcGroupId": "zzz", "dstGroupId": "zzz", "sourceSgtId": "zzz", "destinationSgtId": "zzz"})
            if object.organization:
                p_src = TagData.objects.filter(organization=object.organization).filter(source_id=data["srcGroupId"])
                p_dst = TagData.objects.filter(organization=object.organization).filter(source_id=data["dstGroupId"])
            else:
                p_src = TagData.objects.filter(iseserver=object.iseserver).filter(source_id=data["sourceSgtId"])
                p_dst = TagData.objects.filter(iseserver=object.iseserver).filter(source_id=data["destinationSgtId"])
            if len(p_src) >= 1 and len(p_dst) >= 1:
                return p_src[0], p_dst[0]

        return None, None

    def lookup_sgacls(self, object):
        if object.source_id and object.source_data:
            data = json_try_load(object.source_data, {"aclIds": [], "sgacls": []})
            out_acl = []
            itername = data["aclIds"] if object.organization else data["sgacls"]
            for s in itername:
                if object.organization:
                    p_acl = ACLData.objects.filter(organization=object.organization).filter(source_id=s)
                else:
                    p_acl = ACLData.objects.filter(iseserver=object.iseserver).filter(source_id=s)

                if len(p_acl) >= 1:
                    out_acl.append(p_acl[0])
            return out_acl

        return None

    def in_sync(self):
        return self.objects_match(bool_only=True)


@receiver(post_save, sender=Policy)
def post_save_policy(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_policy, sender=Policy)
    if instance:
        instance.last_updated = datetime.datetime.now()
        if instance.source_group and instance.source_group.do_sync and instance.dest_group and \
                instance.dest_group.do_sync:
            instance.do_sync = True
        instance.save()

        acls = ACL.objects.filter(id__in=instance.acl.all())
        for a in acls:
            a.do_sync = True
            a.save()

        acls = ACL.objects.filter(Q(policies__isnull=True) | Q(policies__do_sync=False))
        for a in acls:
            a.do_sync = False
            a.save()

    post_save.connect(post_save_policy, sender=Policy)


class Task(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Task Description", max_length=50, blank=False, null=False)
    task_data = models.TextField(blank=True, null=True, default=None)
    last_update = models.DateTimeField(default=django.utils.timezone.now)

    def __str__(self):
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


class TagData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, null=False, blank=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    source_data = models.TextField(blank=True, null=True, default=None)
    source_ver = models.IntegerField(blank=True, null=True, default=None)
    last_sync = models.DateTimeField(default=None, null=True)
    update_failed = models.BooleanField(default=False, editable=True)
    last_update = models.DateTimeField(default=None, null=True)
    last_update_data = models.TextField(blank=True, null=True, default=None)
    last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)

    class Meta:
        verbose_name = "Tag Data"
        verbose_name_plural = "Tag Data"
        ordering = ('tag__tag_number', 'organization', 'iseserver')

    def hyperlink(self):
        # return "<a href='/admin/sync/tagdata/" + str(self.id) + "'>" + str(self) + "</a>"
        return "<a href='/home/status-sgt-data?id=" + str(self.id) + "'>" + str(self) + "</a>"

    def __str__(self):
        if self.iseserver:
            src = str(self.iseserver)
        elif self.organization:
            src = str(self.organization)
        else:
            src = "Unknown"
        return src + " : " + self.tag.name + " (" + str(self.tag.tag_number) + ")"

    def update_dest(self):
        if self.tag and self.tag.do_sync:
            if self.tag.push_delete:
                if self.tag.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"
            if self.organization and (self.source_id is None or self.source_id == ""):
                return "meraki"
            if self.iseserver and (self.source_id is None or self.source_id == ""):
                return "ise"
            if not self.tag.in_sync():
                if self.tag.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"

        return "none"


class ACLData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    acl = models.ForeignKey(ACL, on_delete=models.CASCADE, null=False, blank=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    source_data = models.TextField(blank=True, null=True, default=None)
    source_ver = models.IntegerField(blank=True, null=True, default=None)
    last_sync = models.DateTimeField(default=None, null=True)
    update_failed = models.BooleanField(default=False, editable=True)
    last_update = models.DateTimeField(default=None, null=True)
    last_update_data = models.TextField(blank=True, null=True, default=None)
    last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)

    class Meta:
        verbose_name = "ACL Data"
        verbose_name_plural = "ACL Data"

    def hyperlink(self):
        # return "<a href='/admin/sync/acldata/" + str(self.id) + "'>" + str(self) + "</a>"
        return "<a href='/home/status-sgacl-data?id=" + str(self.id) + "'>" + str(self) + "</a>"

    def __str__(self):
        if self.iseserver:
            src = str(self.iseserver)
        elif self.organization:
            src = str(self.organization)
        else:
            src = "Unknown"
        return src + " : " + self.acl.name

    def lookup_version(self, obj):
        if obj.organization:
            acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(iseserver=obj.acl.syncsession.iseserver) & Q(source_id__isnull=False))
            if len(acl) > 0:
                source_data = acl[0].source_data
                idata = json_try_load(source_data, {})
                if "ipVersion" in idata:
                    return idata["ipVersion"].lower()
                else:
                    return "agnostic"
        else:
            acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(organization__in=obj.acl.syncsession.dashboard.organization.all()) & Q(source_id__isnull=False))
            if len(acl) > 0:
                source_data = acl[0].source_data
                mdata = json_try_load(source_data, {})
                if mdata["ipVersion"] == "agnostic":
                    return "IP_AGNOSTIC"
                else:
                    return mdata["ipVersion"].upper()

        return None

    def lookup_rules(self, obj):
        if obj.organization:
            acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(iseserver=obj.acl.syncsession.iseserver) & Q(source_id__isnull=False))
            if len(acl) > 0:
                source_data = acl[0].source_data
                idata = json_try_load(source_data, {})
                sgacl = self.acl.normalize_ise_rules(idata["aclcontent"], mode="convert")
                return sgacl
        else:
            acl = ACLData.objects.filter(Q(acl=obj.acl) & Q(organization__in=obj.acl.syncsession.dashboard.organization.all()) & Q(source_id__isnull=False))
            if len(acl) > 0:
                source_data = acl[0].source_data
                mdata = json_try_load(source_data, {})
                sgacl = self.acl.normalize_meraki_rules(mdata["rules"], mode="convert")
                return sgacl

        return None

    def update_dest(self):
        if self.acl and self.acl.do_sync:
            if self.acl.push_delete:
                if self.acl.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"
            if self.organization and (self.source_id is None or self.source_id == ""):
                return "meraki"
            if self.iseserver and (self.source_id is None or self.source_id == ""):
                return "ise"
            if not self.acl.in_sync():
                if self.acl.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"

        return "none"


class PolicyData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    policy = models.ForeignKey(Policy, on_delete=models.CASCADE, null=False, blank=False)
    iseserver = models.ForeignKey(ISEServer, on_delete=models.CASCADE, null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    source_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    source_data = models.TextField(blank=True, null=True, default=None)
    source_ver = models.IntegerField(blank=True, null=True, default=None)
    last_sync = models.DateTimeField(default=None, null=True)
    update_failed = models.BooleanField(default=False, editable=True)
    last_update = models.DateTimeField(default=None, null=True)
    last_update_data = models.TextField(blank=True, null=True, default=None)
    last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)

    class Meta:
        verbose_name = "Policy Data"
        verbose_name_plural = "Policy Data"

    def hyperlink(self):
        # return "<a href='/admin/sync/policydata/" + str(self.id) + "'>" + str(self) + "</a>"
        return "<a href='/home/status-policy-data?id=" + str(self.id) + "'>" + str(self) + "</a>"

    def __str__(self):
        if self.iseserver:
            src = str(self.iseserver)
        elif self.organization:
            src = str(self.organization)
        else:
            src = "Unknown"
        return src + " : " + self.policy.mapping

    def update_dest(self):
        if self.policy and self.policy.do_sync:
            if self.policy.push_delete:
                if self.policy.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"
            if self.organization and (self.source_id is None or self.source_id == ""):
                return "meraki"
            if self.iseserver and (self.source_id is None or self.source_id == ""):
                return "ise"
            if not self.policy.in_sync():
                if self.policy.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"

        return "none"

    def lookup_sgacl_data(self, obj):
        if obj.organization:
            acl = ACLData.objects.filter(Q(acl__in=obj.policy.acl.all()) & Q(organization=obj.organization) & Q(source_id__isnull=False))
        else:
            acl = ACLData.objects.filter(Q(acl__in=obj.policy.acl.all()) & Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))

        if len(acl) == len(obj.policy.acl.all()):
            return acl

        return None

    def lookup_acl_catchall(self, obj, convert=False):
        if obj.organization or (convert and not obj.organization):
            src = PolicyData.objects.filter(Q(policy=obj.policy) & Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
            if len(src) > 0:
                source_data = src[0].source_data
                idata = json_try_load(source_data, {})
                if idata["defaultRule"] == "DENY_IP":
                    return "deny all"
                elif idata["defaultRule"] == "PERMIT_IP":
                    return "allow all"
                elif idata["defaultRule"] == "NONE":
                    return "global"
                else:
                    return "global"
        else:
            src = PolicyData.objects.filter(Q(policy=obj.policy) & Q(organization__in=obj.policy.syncsession.dashboard.organization.all()) & Q(source_id__isnull=False))
            if len(src) > 0:
                source_data = src[0].source_data
                mdata = json_try_load(source_data, {})
                if mdata["catchAllRule"] == "deny all":
                    return "DENY_IP"
                elif mdata["catchAllRule"] == "allow all" or mdata["catchAllRule"] == "permit all":
                    return "PERMIT_IP"
                elif mdata["catchAllRule"] == "global":
                    return "NONE"
                else:
                    return "NONE"

        return None

    def lookup_sgt_data(self, obj):
        if obj.organization:
            src = TagData.objects.filter(Q(tag=obj.policy.source_group) & Q(organization=obj.organization) &
                                         Q(source_id__isnull=False))
            dst = TagData.objects.filter(Q(tag=obj.policy.dest_group) & Q(organization=obj.organization) &
                                         Q(source_id__isnull=False))
            if len(src) > 0 and len(dst) > 0:
                return src[0], dst[0]
        else:
            src = TagData.objects.filter(Q(tag=obj.policy.source_group) &
                                         Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
            dst = TagData.objects.filter(Q(tag=obj.policy.dest_group) &
                                         Q(iseserver=obj.policy.syncsession.iseserver) & Q(source_id__isnull=False))
            if len(src) > 0 and len(dst) > 0:
                return src[0], dst[0]

        return None, None
