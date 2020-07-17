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
            i = Upload.objects.create(description=instance.description + "-" + fn, file=fn)
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
    # file = models.BinaryField(editable=False)
    file = models.FileField(upload_to='upload')
    uploaded_at = models.DateTimeField(auto_now_add=True)

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
        return self.orgid


class Dashboard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    description = models.CharField("Dashboard Integration Description", max_length=100, blank=False, null=False)
    baseurl = models.CharField("Base URL", max_length=64, null=False, blank=False,
                               default="https://api.meraki.com/api/v1")
    apikey = models.CharField("API Key", max_length=64, null=False, blank=False)
    # orgid = models.CharField("API Organization ID", max_length=32, null=True, blank=True, default=None)
    # netid = models.CharField(max_length=32, null=True, blank=True, default=None)
    # username = models.CharField(max_length=64, null=True, blank=True, default=None)
    # password = models.CharField(max_length=64, null=True, blank=True, default=None)
    webhook_enable = models.BooleanField(default=False, editable=True)
    webhook_ngrok = models.BooleanField(default=False, editable=True)
    webhook_url = models.CharField(max_length=200, null=True, blank=True, default=None)
    organization = models.ManyToManyField(Organization, blank=True)
    # TODO: Remove these - they belong in Org
    raw_data = models.TextField(blank=True, null=True, default=None)
    force_rebuild = models.BooleanField("Force Dashboard Sync", default=False, editable=True)
    skip_sync = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_sync = models.DateTimeField(null=True, default=None, blank=True)

    def __str__(self):
        return self.description


# @receiver(post_save, sender=Dashboard)
# def post_save_dashboard(sender, instance=None, created=False, **kwargs):
#     post_save.disconnect(post_save_dashboard, sender=Dashboard)
#     if instance.webhook_ngrok:
#
#         instance.save()
#     post_save.connect(post_save_dashboard, sender=Dashboard)


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
    # isematrix = models.ForeignKey(ISEMatrix, on_delete=models.SET_NULL, null=True, blank=True)
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
    description = models.CharField("Tag Description", max_length=100, blank=True, null=False)
    do_sync = models.BooleanField("Sync this Tag?", default=False, editable=True)
    syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
    tag_number = models.IntegerField(blank=False, null=False, default=0)
    meraki_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    ise_id = models.CharField("ISE id", max_length=36, blank=True, null=True, default=None)
    meraki_data = models.TextField(blank=True, null=True, default=None)
    ise_data = models.TextField("ISE data", blank=True, null=True, default=None)
    meraki_ver = models.IntegerField(blank=True, null=True, default=None)
    ise_ver = models.IntegerField(blank=True, null=True, default=None)
    needs_update = models.TextField(blank=True, null=True, default=None)
    update_failed = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_update_data = models.TextField(blank=True, null=True, default=None)
    last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)
    push_delete = models.BooleanField(default=False, editable=False)
    sourced_from = models.CharField(max_length=20, blank=True, null=True, default=None)

    def __str__(self):
        if self.do_sync:
            return self.name + " (" + str(self.tag_number) + ")"    # + " -- Matches:" + str(self.in_sync())
        else:
            return self.name + " (" + str(self.tag_number) + ")"

    def update_success(self):
        if self.last_update_state == "True" and not self.update_failed:
            return True
        elif self.last_update_state == "False" or self.update_failed:
            return False

        return None

    def cleaned_name(self):
        newname = self.name[:32]
        newname = re.sub('[^0-9a-zA-Z]+', '_', newname)
        return newname

    def in_sync(self):
        return self.match_report(bool_only=True)

    def match_report(self, bool_only=False):
        outtxt = ""
        if self.ise_id and self.ise_data and self.meraki_id and self.meraki_data:
            mdata = json.loads(self.meraki_data)
            idata = json.loads(self.ise_data)

            name_match = mdata.get("name", "mdata") == idata.get("name", "idata")
            name_match_cl = self.cleaned_name() == idata.get("name", "idata")
            m_desc = mdata.get("description", "mdata")
            i_desc = idata.get("description", "idata")
            desc_match = m_desc == i_desc
            m_desc = m_desc.translate(str.maketrans('', '', string.punctuation)).lower()
            i_desc = i_desc.translate(str.maketrans('', '', string.punctuation)).lower()
            desc_match_fuzzy = m_desc == i_desc

            outtxt += "name:" + str(name_match) + "\n"
            outtxt += "cleaned name:" + str(name_match_cl) + "\n"
            outtxt += "description:" + str(desc_match) + "\n"
            outtxt += "fuzzy description:" + str(desc_match_fuzzy) + "\n"
            if self.tag_number == 0:
                outtxt += "\n" + "NOTE:THIS TAG (0) WILL ALWAYS RETURN Matches:True. WE DO NOT WANT TO SYNC IT." + "\n"
                if bool_only:
                    return True
            elif self.tag_number == 2:
                outtxt += "\n" + "NOTE:THIS TAG (2) WILL ALWAYS RETURN Matches:True. WE DO NOT WANT TO SYNC IT." + "\n"
                if bool_only:
                    return True
            outtxt += "delete?:" + str(self.push_delete) + "\n"

            if bool_only:
                return (name_match or name_match_cl) and (desc_match or desc_match_fuzzy) and not self.push_delete
            else:
                return outtxt

        if bool_only:
            return False
        else:
            return None

    def update_dest(self):
        if self.do_sync:
            if self.push_delete:
                if self.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"
            if self.meraki_id is None or self.meraki_id == "":
                return "meraki"
            if self.ise_id is None or self.ise_id == "":
                return "ise"
            if not self.in_sync():
                if self.syncsession.ise_source:
                    return "meraki"
                else:
                    return "ise"

        return "none"

    # def push_config(self):
    #     d = self.update_dest()
    #     if d == "ise":
    #         if self.push_delete:
    #             thismeth = "DELETE"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/sgt/" + self.ise_id
    #             return thismeth, url, None
    #         elif self.ise_id is not None and self.ise_id != "":
    #             thismeth = "PUT"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/sgt/" + self.ise_id
    #         else:
    #             thismeth = "POST"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/sgt"
    #
    #         return thismeth, url, json.dumps({"Sgt": {"name": self.cleaned_name(), "description": self.description,
    #                                                   "value": self.tag_number, "propogateToApic": False,
    #                                                   "defaultSGACLs": []}})
    #     elif d == "meraki":
    #         if self.push_delete:
    #             thismeth = "DELETE"
    #             url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #                 "/adaptivePolicy/groups/" + self.meraki_id
    #             return thismeth, url, None
    #         elif self.meraki_id is not None and self.meraki_id != "":
    #             thismeth = "PUT"
    #             url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #                 "/adaptivePolicy/groups/" + self.meraki_id
    #         else:
    #             thismeth = "POST"
    #             url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #                 "/adaptivePolicy/groups"
    #
    #         return thismeth, url, json.dumps({"value": self.tag_number, "name": self.name,
    #                                           "description": self.description})
    #
    #     return "", "", ""


@receiver(post_save, sender=Tag)
def post_save_tag(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_tag, sender=Tag)
    if instance:
        instance.last_updated = datetime.datetime.now()
        instance.save()

        policies = Policy.objects.filter(Q(source_group=instance) | Q(dest_group=instance))
        for p in policies:
            if p.source_group.do_sync and p.dest_group.do_sync:
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
    meraki_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    ise_id = models.CharField("ISE id", max_length=36, blank=True, null=True, default=None)
    meraki_data = models.TextField(blank=True, null=True, default=None)
    ise_data = models.TextField("ISE data", blank=True, null=True, default=None)
    meraki_ver = models.IntegerField(blank=True, null=True, default=None)
    ise_ver = models.IntegerField(blank=True, null=True, default=None)
    needs_update = models.TextField(blank=True, null=True, default=None)
    update_failed = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_update_data = models.TextField(blank=True, null=True, default=None)
    last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)
    push_delete = models.BooleanField(default=False, editable=False)
    sourced_from = models.CharField(max_length=20, blank=True, null=True, default=None)
    visible = models.BooleanField(default=True, editable=False)

    class Meta:
        verbose_name = "ACL"
        verbose_name_plural = "ACLs"

    def __str__(self):
        return self.name    # + " -- Valid:" + str(self.is_valid_config()) + " -- Matches:" + str(self.in_sync())

    def update_success(self):
        if self.last_update_state == "True" and not self.update_failed:
            return True
        elif self.last_update_state == "False" or self.update_failed:
            return False

        return None

    def cleaned_name(self):
        newname = self.name[:32]
        newname = re.sub('[^0-9a-zA-Z]+', '_', newname)
        return newname

    def in_sync(self):
        return self.match_report(bool_only=True)

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
                    # else:
                    #     outtxt += " src any"
                    if r["dstPort"] != "any":
                        outtxt += " dst " + self.make_port_list(r["dstPort"])
                    # else:
                    #     outtxt += " dst any"

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
                    # else:
                    #     outtxt += " src any"
                    if r["dstPort"] != "any":
                        outtxt += " dst " + self.make_port_list(r["dstPort"])
                    # else:
                    #     outtxt += " dst any"

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

    def match_report(self, bool_only=False):
        outtxt = ""
        if self.ise_id and self.ise_data and self.meraki_id and self.meraki_data:
            try:
                mdata = json.loads(self.meraki_data)
                idata = json.loads(self.ise_data)

                name_match = mdata.get("name", "mdata") == idata.get("name", "idata")
                name_match_cl = self.cleaned_name() == idata.get("name", "idata")
                m_desc = mdata.get("description", "mdata")
                i_desc = idata.get("description", "idata")
                desc_match = m_desc == i_desc
                m_desc = m_desc.translate(str.maketrans('', '', string.punctuation)).lower()
                i_desc = i_desc.translate(str.maketrans('', '', string.punctuation)).lower()
                desc_match_fuzzy = m_desc == i_desc

                acl_match = self.normalize_meraki_rules(mdata["rules"]) == self.normalize_ise_rules(idata["aclcontent"])
                if "ipVersion" not in idata and mdata["ipVersion"] == "agnostic":
                    # IP Agnostic
                    ver_match = True
                elif idata.get("ipVersion", "").lower() == mdata.get("ipVersion", ""):
                    # Version matches
                    ver_match = True
                else:
                    ver_match = False

                outtxt += "name:" + str(name_match) + "\n"
                outtxt += "cleaned name:" + str(name_match_cl) + "\n"
                outtxt += "description:" + str(desc_match) + "\n"
                outtxt += "fuzzy description:" + str(desc_match_fuzzy) + "\n"

                test_ise_acl_1 = self.normalize_ise_rules(idata["aclcontent"]).strip().replace("\n", ";")
                test_meraki_acl = self.normalize_ise_rules(idata["aclcontent"], mode="convert")
                test_ise_acl_2 = self.normalize_meraki_rules(test_meraki_acl, mode="convert").strip().replace("\n", ";")
                test_ise_acl_3 = self.normalize_ise_rules(test_ise_acl_2)
                ise_valid_config = test_ise_acl_1 == test_ise_acl_3
                outtxt += "----Filtered ISE Config:\n" + test_ise_acl_1 + "\n----Converted to ISE:\n" +\
                          test_ise_acl_3 + "\n----\n"
                outtxt += "ise_valid_acl?:" + str(ise_valid_config) + "\n"

                outtxt += "meraki_acl:" + self.normalize_meraki_rules(mdata["rules"]) + "\n"
                outtxt += "ise_acl:" + self.normalize_ise_rules(idata["aclcontent"]) + "\n"
                outtxt += "acl:" + str(acl_match) + "\n"
                outtxt += "version:" + str(ver_match) + "\n"
                outtxt += "delete?:" + str(self.push_delete) + "\n"

                if bool_only:
                    return (name_match or name_match_cl) and \
                           (desc_match or desc_match_fuzzy) and acl_match and ver_match and not self.push_delete
                else:
                    return outtxt
            except Exception:
                return False
        elif self.ise_id and self.ise_data:
            if self.visible is False:
                outtxt += "NOTE:THIS SGACL WILL ALWAYS RETURN Matches:True SINCE IT IS BUILT-IN."
                if bool_only:
                    return True
                else:
                    return outtxt

        if bool_only:
            return False
        else:
            return None

    def is_valid_config(self):
        if self.ise_id and self.ise_data and self.meraki_id and self.meraki_data:
            try:
                idata = json.loads(self.ise_data)

                test_ise_acl_1 = self.normalize_ise_rules(idata["aclcontent"]).strip().replace("\n", ";")
                test_meraki_acl = self.normalize_ise_rules(idata["aclcontent"], mode="convert")
                test_ise_acl_2 = self.normalize_meraki_rules(test_meraki_acl, mode="convert").strip().replace("\n", ";")
                test_ise_acl_3 = self.normalize_ise_rules(test_ise_acl_2)
                ise_valid_config = test_ise_acl_1 == test_ise_acl_3
                return ise_valid_config
            except Exception:
                return False

        return True

    def update_dest(self):
        if self.meraki_id is None or self.meraki_id == "":
            return "meraki"
        if self.ise_id is None or self.ise_id == "":
            return "ise"
        if not self.in_sync():
            if self.syncsession.ise_source:
                return "meraki"
            else:
                return "ise"

        return "none"

    def get_version(self, update_dest):
        if update_dest == "ise":
            if self.meraki_id and self.meraki_data:
                mdata = json.loads(self.meraki_data)
                if mdata["ipVersion"] == "agnostic":
                    return "IP_AGNOSTIC"
                else:
                    return mdata["ipVersion"].upper()
        elif update_dest == "meraki":
            if self.ise_id and self.ise_data:
                idata = json.loads(self.ise_data)
                if "ipVersion" in idata:
                    return idata["ipVersion"].lower()
                else:
                    return "agnostic"
        return ""

    def get_rules(self, update_dest):
        if update_dest == "ise":
            if self.meraki_id and self.meraki_data:
                mdata = json.loads(self.meraki_data)
                sgacl = self.normalize_meraki_rules(mdata["rules"], mode="convert")
                return sgacl
        elif update_dest == "meraki":
            if self.ise_id and self.ise_data:
                idata = json.loads(self.ise_data)
                sgacl = self.normalize_ise_rules(idata["aclcontent"], mode="convert")
                return sgacl
        return ""

    # def push_config(self):
    #     d = self.update_dest()
    #     if not self.is_valid_config():
    #         return "", "", ""
    #
    #     if d == "ise":
    #         if self.push_delete:
    #             thismeth = "DELETE"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/sgacl/" + self.ise_id
    #             return thismeth, url, None
    #         elif self.ise_id is not None and self.ise_id != "":
    #             thismeth = "PUT"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/sgacl/" + self.ise_id
    #         else:
    #             thismeth = "POST"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/sgacl"
    #
    #         return thismeth, url, json.dumps({"Sgacl": {"name": self.cleaned_name(), "description": self.description,
    #                                                     "ipVersion": self.get_version(d), "readOnly": False,
    #                                                     "aclcontent": self.get_rules(d)}})  # .replace("\\n", "\n")
    #     elif d == "meraki":
    #         if self.push_delete:
    #             thismeth = "DELETE"
    #             url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #                 "/adaptivePolicy/acls/" + self.meraki_id
    #             return thismeth, url, None
    #         elif self.meraki_id is not None and self.meraki_id != "":
    #             thismeth = "PUT"
    #             url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #                 "/adaptivePolicy/acls/" + self.meraki_id
    #         else:
    #             thismeth = "POST"
    #             url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #                 "/adaptivePolicy/acls"
    #
    #         return thismeth, url, json.dumps({"name": self.name, "description": self.description,
    #                                           "ipVersion": self.get_version(d), "rules": self.get_rules(d)})
    #
    #     return "", "", ""


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
    name = models.CharField("Policy Name", max_length=100, blank=False, null=False)
    source_group = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, related_name="source_group")
    dest_group = models.ForeignKey(Tag, on_delete=models.SET_NULL, null=True, blank=True, related_name="dest_group")
    acl = models.ManyToManyField(ACL, blank=True, related_name="policies")
    description = models.CharField("Policy Description", max_length=100, blank=True, null=True)
    do_sync = models.BooleanField("Sync this Policy?", default=False, editable=True)
    syncsession = models.ForeignKey(SyncSession, on_delete=models.SET_NULL, null=True, blank=True)
    meraki_id = models.CharField(max_length=36, blank=True, null=True, default=None)
    ise_id = models.CharField("ISE id", max_length=36, blank=True, null=True, default=None)
    meraki_data = models.TextField(blank=True, null=True, default=None)
    ise_data = models.TextField("ISE data", blank=True, null=True, default=None)
    meraki_ver = models.IntegerField(blank=True, null=True, default=None)
    ise_ver = models.IntegerField(blank=True, null=True, default=None)
    needs_update = models.TextField(blank=True, null=True, default=None)
    update_failed = models.BooleanField(default=False, editable=False)
    last_update = models.DateTimeField(default=django.utils.timezone.now)
    last_update_data = models.TextField(blank=True, null=True, default=None)
    last_update_state = models.CharField(max_length=20, blank=True, null=True, default=None)
    push_delete = models.BooleanField(default=False, editable=False)
    sourced_from = models.CharField(max_length=20, blank=True, null=True, default=None)

    class Meta:
        verbose_name_plural = "policies"

    def __str__(self):
        return self.name + " (" + self.mapping + ")"    # + " -- Matches:" + str(self.in_sync())

    def update_success(self):
        if self.last_update_state == "True" and not self.update_failed:
            return True
        elif self.last_update_state == "False" or self.update_failed:
            return False

        return None

    def cleaned_name(self):
        newname = self.name[:32]
        newname = re.sub('[^0-9a-zA-Z-]+', '_', newname)
        return newname

    def lookup_ise_sgts(self):
        if self.ise_id and self.ise_data:
            idata = json.loads(self.ise_data)
            p_src = Tag.objects.filter(ise_id=idata["sourceSgtId"])
            p_dst = Tag.objects.filter(ise_id=idata["destinationSgtId"])
            if len(p_src) >= 1 and len(p_dst) >= 1:
                return p_src[0], p_dst[0]

        return None, None

    def lookup_ise_sgacls(self):
        if self.ise_id and self.ise_data:
            idata = json.loads(self.ise_data)
            out_acl = []
            for s in idata["sgacls"]:
                p_acl = ACL.objects.filter(ise_id=s)
                if len(p_acl) >= 1:
                    out_acl.append(p_acl[0])
            return out_acl

        return None

    def lookup_meraki_sgts(self):
        if self.meraki_id and self.meraki_data:
            mdata = json.loads(self.meraki_data)
            p_src = Tag.objects.filter(meraki_id=mdata["srcGroupId"])
            p_dst = Tag.objects.filter(meraki_id=mdata["dstGroupId"])
            if len(p_src) >= 1 and len(p_dst) >= 1:
                return p_src[0], p_dst[0]

        return None, None

    def lookup_meraki_sgacls(self):
        if self.meraki_id and self.meraki_data:
            mdata = json.loads(self.meraki_data)
            out_acl = []
            for s in mdata["aclIds"]:
                p_acl = ACL.objects.filter(meraki_id=s)
                if len(p_acl) >= 1:
                    out_acl.append(p_acl[0])
            return out_acl

        return None

    def in_sync(self):
        return self.match_report(bool_only=True)

    def match_report(self, bool_only=False):
        outtxt = ""
        if self.ise_id and self.ise_data and self.meraki_id and self.meraki_data:
            mdata = json.loads(self.meraki_data)
            idata = json.loads(self.ise_data)
            i_sgt_src, i_sgt_dst = self.lookup_ise_sgts()
            m_sgt_src, m_sgt_dst = self.lookup_meraki_sgts()
            i_sgacls = self.lookup_ise_sgacls()
            i_sgacls_o = []
            for i in i_sgacls:
                i_sgacls_o.append(i.name)
            m_sgacls = self.lookup_meraki_sgacls()
            m_sgacls_o = []
            for m in m_sgacls:
                m_sgacls_o.append(m.name)

            # name_match = mdata.get("name", "mdata") == idata.get("name", "idata")
            ise_single_rule_match = False
            if mdata["catchAllRule"] == "global" and idata["defaultRule"] == "NONE":
                default_match = True
            elif mdata["catchAllRule"] == "deny all" and idata["defaultRule"] == "DENY_IP":
                default_match = True
                if len(i_sgacls_o) == 1 and i_sgacls_o[0] == "Deny IP":
                    ise_single_rule_match = True
            elif (mdata["catchAllRule"] == "allow all" or mdata["catchAllRule"] == "permit all") and \
                    idata["defaultRule"] == "PERMIT_IP":
                default_match = True
                if len(i_sgacls_o) == 1 and i_sgacls_o[0] == "Permit IP":
                    ise_single_rule_match = True
            else:
                default_match = False
            if i_sgt_src == m_sgt_src and i_sgt_dst == m_sgt_dst:
                srcdst_match = True
            else:
                srcdst_match = False

            # Check to see if there are the same number of SGACLs defined in each ACL List
            if len(i_sgacls) == len(m_sgacls):
                sgacl_match = True
                # If so, iterate each list to make sure that the actual ACLs are the same in each list
                for x in range(0, len(i_sgacls)):
                    if i_sgacls[x].id != m_sgacls[x].id:
                        sgacl_match = False
            else:
                # There is one situation where it is ok to have mismatched SGACL Lengths: when you create a policy in
                # ISE that only contains a default Deny or Permit, ISE will also add a Deny or Permit ACL in addition
                # to the default rule - we don't need this on the Meraki side. So if the length is 0 for Meraki, but
                # contains a Deny or Permit rule (in addition to the corresponding Deny or Permit default), it's ok.
                if len(m_sgacls) == 0 and ise_single_rule_match:
                    sgacl_match = True
                else:
                    sgacl_match = False

            outtxt += "name:" + str(mdata["name"] == idata["name"]) + "\n"
            outtxt += "catchAllRule:" + str(default_match) + "\n"
            if i_sgt_src and m_sgt_src:
                outtxt += "src:" + str(i_sgt_src.tag_number) + "," + str(m_sgt_src.tag_number) + "\n"
            if i_sgt_dst and m_sgt_dst:
                outtxt += "dst:" + str(i_sgt_dst.tag_number) + "," + str(m_sgt_dst.tag_number) + "\n"
            outtxt += "src/dst tags:" + str(srcdst_match) + "\n"
            outtxt += "meraki sgacls:" + str(m_sgacls_o) + "\n"
            outtxt += "ise sgacls:" + str(i_sgacls_o) + "\n"
            outtxt += "sgacls:" + str(sgacl_match) + "\n"
            outtxt += "delete?:" + str(self.push_delete) + "\n"

            if bool_only:
                return default_match and srcdst_match and sgacl_match and not self.push_delete
            else:
                return outtxt

        if bool_only:
            return False
        else:
            return None

    def update_dest(self):
        if self.meraki_id is None or self.meraki_id == "":
            return "meraki"
        if self.ise_id is None or self.ise_id == "":
            return "ise"
        if not self.in_sync():
            if self.syncsession.ise_source:
                return "meraki"
            else:
                return "ise"

        return "none"

    def get_catchall(self, update_dest):
        if update_dest == "ise":
            if self.meraki_id and self.meraki_data:
                mdata = json.loads(self.meraki_data)
                if mdata["catchAllRule"] == "deny all":
                    return "DENY_IP"
                elif mdata["catchAllRule"] == "allow all" or mdata["catchAllRule"] == "permit all":
                    return "PERMIT_IP"
                elif mdata["catchAllRule"] == "global":
                    return "NONE"
                else:
                    return "NONE"
        elif update_dest == "meraki":
            if self.ise_id and self.ise_data:
                idata = json.loads(self.ise_data)
                if idata["defaultRule"] == "DENY_IP":
                    return "deny all"
                elif idata["defaultRule"] == "PERMIT_IP":
                    return "allow all"
                elif idata["defaultRule"] == "NONE":
                    return "global"
                else:
                    return "global"
        return ""

    def get_sgts(self, update_dest):
        if update_dest == "ise":
            m_sgt_src, m_sgt_dst = self.lookup_meraki_sgts()
            if m_sgt_src and m_sgt_dst:
                return m_sgt_src.ise_id, m_sgt_dst.ise_id
            else:
                return None, None
        elif update_dest == "meraki":
            i_sgt_src, i_sgt_dst = self.lookup_ise_sgts()
            if i_sgt_src and i_sgt_dst:
                return i_sgt_src.meraki_id, i_sgt_dst.meraki_id
            else:
                return None, None
        return "", ""

    def get_sgacls(self, update_dest):
        if update_dest == "ise":
            m_sgacls = self.lookup_meraki_sgacls()
            outsgacl = []
            for s in m_sgacls:
                outsgacl.append(s.ise_id)
            return outsgacl
        elif update_dest == "meraki":
            i_sgacls = self.lookup_ise_sgacls()
            outsgacl = []
            for s in i_sgacls:
                if s.meraki_id is None:
                    return None
                outsgacl.append(int(s.meraki_id))
            return outsgacl
        return ""

    # def push_config(self):
    #     d = self.update_dest()
    #     src, dst = self.get_sgts(d)
    #     acl = self.get_sgacls(d)
    #     if src is None or dst is None or acl is None:
    #         return "", "", ""
    #     if d == "ise":
    #         if self.push_delete:
    #             thismeth = "DELETE"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/egressmatrixcell"
    #             return thismeth, url, None
    #         elif self.ise_id is not None and self.ise_id != "":
    #             thismeth = "PUT"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/egressmatrixcell"
    #         else:
    #             thismeth = "POST"
    #             url = self.syncsession.iseserver.base_url() + "/ers/config/egressmatrixcell"
    #
    #         return thismeth, url, json.dumps({"EgressMatrixCell": {"sourceSgtId": src, "destinationSgtId": dst,
    #                                                                "matrixCellStatus": "ENABLED",
    #                                                                "defaultRule": self.get_catchall(d), "sgacls": acl,
    #                                                                "name": self.name, "description": self.description}})
    #     elif d == "meraki":
    #         thismeth = "PUT"
    #         url = self.syncsession.dashboard.baseurl + "/organizations/" + str(self.syncsession.dashboard.orgid) +\
    #             "/adaptivePolicy/bindings"
    #
    #         if self.push_delete:
    #             return thismeth, url, json.dumps({
    #                     "description": self.name,
    #                     "name": self.description,
    #                     "monitorModeEnabled": False,
    #                     "catchAllRule": "global",
    #                     "bindingEnabled": True,
    #                     "aclIds": None,
    #                     "srcGroupId": src,
    #                     "dstGroupId": dst
    #                 })
    #         return thismeth, url, json.dumps({
    #                 "description": self.description,
    #                 "name": self.name,
    #                 "monitorModeEnabled": False,
    #                 "catchAllRule": self.get_catchall(d),
    #                 "bindingEnabled": True,
    #                 "aclIds": acl,
    #                 "srcGroupId": src,
    #                 "dstGroupId": dst
    #             })
    #
    #     return "", "", ""


@receiver(post_save, sender=Policy)
def post_save_policy(sender, instance=None, created=False, **kwargs):
    post_save.disconnect(post_save_policy, sender=Policy)
    if instance:
        instance.last_updated = datetime.datetime.now()
        if instance.source_group.do_sync and instance.dest_group.do_sync:
            instance.do_sync = True
        instance.save()

        # ACL.objects.all().update(do_sync=True)
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
