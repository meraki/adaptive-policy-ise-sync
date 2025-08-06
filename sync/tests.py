# import os
import pytest
from django.forms.models import model_to_dict
from .models import ISEServer, Dashboard, Organization, SyncSession, Tag, ACL, Policy, TagData, UploadZip, Upload
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
import sync._config
import meraki
import time
# import copy
from ise import ERS
from scripts.meraki_addons import meraki_read_sgt, meraki_read_sgacl, meraki_read_sgpolicy, meraki_update_sgt, \
    meraki_update_sgacl, meraki_update_sgpolicy, meraki_delete_sgt, meraki_delete_sgacl, meraki_create_sgt, \
    meraki_create_sgacl
from django.conf import settings
import scripts.dashboard_monitor
import scripts.ise_monitor
import json
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
# from selenium.webdriver import Remote
# from pytest_django.live_server_helper import LiveServer
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
# from selenium.webdriver.common.action_chains import ActionChains
# from selenium.webdriver.firefox.webdriver import WebDriver
# import urllib.parse
import requests
# from apscheduler.schedulers.background import BackgroundScheduler
import scripts.px_subscribe
import asyncio
# import threading


# cron = BackgroundScheduler()


def reset_dashboard(db=None, baseurl=None, apikey=None, orgid=None):
    if db:
        dashboard = meraki.DashboardAPI(base_url=db.baseurl, api_key=db.apikey, print_console=False, output_log=False,
                                        caller=settings.CUSTOM_UA, suppress_logging=True)
        dborgid = db.orgid
    elif baseurl and apikey and orgid:
        dashboard = meraki.DashboardAPI(base_url=baseurl, api_key=apikey, print_console=False, output_log=False,
                                        caller=settings.CUSTOM_UA, suppress_logging=True)
        dborgid = orgid
    else:
        assert False

    sgts = meraki_read_sgt(dashboard, dborgid)
    sgacls = meraki_read_sgacl(dashboard, dborgid)
    # sgpolicies = meraki_read_sgpolicy(dashboard, db.orgid)
    for s in sgts:
        if not s["value"] in sync._config.whitelisted_sgts:
            print("Removing SGT", s["value"], "from Meraki Dashboard...")
            meraki_delete_sgt(dashboard, dborgid, s["groupId"])

    for s in sgacls:
        print("Removing SGACL", s["name"], "from Meraki Dashboard...")
        meraki_delete_sgacl(dashboard, dborgid, s["aclId"])

    sgts = meraki_read_sgt(dashboard, dborgid)
    sgacls = meraki_read_sgacl(dashboard, dborgid)
    sgpolicies = meraki_read_sgpolicy(dashboard, dborgid)

    current_vals = [d['value'] for d in sgts]
    for s in sync._config.meraki_default_sgts:
        if not s["value"] in current_vals:
            print("Adding SGT", s["value"], "to Meraki Dashboard...")
            meraki_create_sgt(dashboard, dborgid, name=s["name"], description=s["description"], value=s["value"])

    current_vals = [d['name'] for d in sgacls]
    for s in sync._config.meraki_default_sgacls:
        if not s["name"] in current_vals:
            print("Adding SGACL", s["name"], "to Meraki Dashboard...")
            meraki_create_sgacl(dashboard, dborgid, name=s["name"], description=s["description"],
                                rules=s["aclcontent"], ipVersion=s["version"])

    sgt_list = meraki_read_sgt(dashboard, dborgid)
    sgacl_list = meraki_read_sgacl(dashboard, dborgid)
    current_vals = [d['name'] for d in sgpolicies]
    for pol in sync._config.meraki_default_policies:
        src_sgt_id = dst_sgt_id = None
        if not pol["name"] in current_vals:
            # Look up Policy elements that we are going to be adding in Dashboard...
            for s in sgt_list:
                if s["name"] == pol["src"]:
                    src_sgt_id = s["groupId"]
                if s["name"] == pol["dst"]:
                    dst_sgt_id = s["groupId"]
            acl_id_list = []
            for acl in pol["acls"]:
                for a in sgacl_list:
                    if a["name"] == acl:
                        acl_id_list.append(a["aclId"])

            print("Adding Egress Policy", pol["name"], "to Meraki Dashboard...")
            meraki_update_sgpolicy(dashboard, dborgid, srcGroupId=src_sgt_id, dstGroupId=dst_sgt_id, name=pol["name"],
                                   description=pol["description"], catchAllRule=pol["default"], bindingEnabled=True,
                                   monitorModeEnabled=False, aclIds=acl_id_list)


def reset_ise(db=None, iseip=None, iseuser=None, isepass=None):
    if db:
        ise = ERS(ise_node=db.ipaddress, ers_user=db.username, ers_pass=db.password, verify=False,
                  disable_warnings=True)
    elif iseip and iseuser and isepass:
        ise = ERS(ise_node=iseip, ers_user=iseuser, ers_pass=isepass, verify=False,
                  disable_warnings=True)
    else:
        assert False

    default_sgts = [d['value'] for d in sync._config.ise_default_sgts]
    default_sgt_names = [d['name'] for d in sync._config.ise_default_sgts]
    default_sgacls = [d['name'] for d in sync._config.ise_default_sgacls]
    # default_policies = [d['name'] for d in sync._config.ise_default_policies]

    sgts = ise.get_sgts(detail=True)
    sgacls = ise.get_sgacls(detail=True)
    sgpolicies = ise.get_egressmatrixcells(detail=True)

    if not sgts or "response" not in sgts:
        time.sleep(5)
        sgts = ise.get_sgts(detail=True)
    for s in sgts["response"]:
        if s["value"] in sync._config.whitelisted_sgts or (s["value"] in default_sgts and
                                                           s["name"] in default_sgt_names):
            pass
        else:
            print("Removing SGT", s["value"], "from Cisco ISE...")
            ise.delete_sgt(s["id"])

    if not sgpolicies or "response" not in sgpolicies:
        time.sleep(5)
        sgpolicies = ise.get_egressmatrixcells(detail=True)
    for s in sgpolicies["response"]:
        if not s["name"] in sync._config.whitelisted_policies:
            print("Removing Egress Policy", s["name"], "from Cisco ISE...")
            ise.delete_egressmatrixcell(s["id"])

    if not sgacls or "response" not in sgacls:
        time.sleep(5)
        sgacls = ise.get_sgacls(detail=True)
    for s in sgacls["response"]:
        if not s["name"] in (sync._config.whitelisted_sgacls + default_sgacls):
            print("Removing SGACL", s["name"], "from Cisco ISE...")
            ise.delete_sgacl(s["id"])

    sgts = ise.get_sgts(detail=True)
    sgacls = ise.get_sgacls(detail=True)
    sgpolicies = ise.get_egressmatrixcells(detail=True)

    current_vals = [d['value'] for d in sgts["response"]]
    for s in sync._config.ise_default_sgts:
        if not s["value"] in current_vals:
            print("Adding SGT", s["value"], "to Cisco ISE...")
            ise.add_sgt(s["name"], s["description"], s["value"])

    current_vals = [d['name'] for d in sgacls["response"]]
    for s in sync._config.ise_default_sgacls:
        if not s["name"] in current_vals:
            print("Adding SGACL", s["name"], "to Cisco ISE...")
            ise.add_sgacl(s["name"], s["description"], s["version"], s["aclcontent"])

    current_vals = [d['name'] for d in sgpolicies["response"]]
    for s in sync._config.ise_default_policies:
        if not s["name"] in current_vals:
            print("Adding Egress Policy", s["name"], "to Cisco ISE...")
            ise.add_egressmatrixcell(s["src"], s["dst"], s["default"], acls=s["acls"], description=s["description"])


# @pytest.fixture(scope='session')
# def browser(request):
#     """Provide a selenium webdriver instance."""
#     # SetUp
#     options = webdriver.FirefoxOptions()
#     # options.add_argument('headless')
#
#     browser_ = webdriver.Firefox(options=options)
#
#     yield browser_
#
#     # TearDown
#     browser_.quit()


@pytest.fixture(params=[0])
def arg(request):
    return request.getfixturevalue(request.param)


# @pytest.fixture
@pytest.mark.django_db
def setup_ise24_reset():
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg1_id"])
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg2_id"])
    Dashboard.objects.all().delete()
    Organization.objects.all().delete()
    SyncSession.objects.all().delete()
    ISEServer.objects.all().delete()
    Tag.objects.all().delete()
    ACL.objects.all().delete()
    Policy.objects.all().delete()
    s = sync._config.servers["2.4"]
    reset_ise(iseip=s["ip"], iseuser=s["user"], isepass=s["pass"])
    return s


# @pytest.fixture
@pytest.mark.django_db
def setup_ise26_reset():
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg1_id"])
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg2_id"])
    Dashboard.objects.all().delete()
    Organization.objects.all().delete()
    SyncSession.objects.all().delete()
    ISEServer.objects.all().delete()
    Tag.objects.all().delete()
    ACL.objects.all().delete()
    Policy.objects.all().delete()
    s = sync._config.servers["2.6"]
    reset_ise(iseip=s["ip"], iseuser=s["user"], isepass=s["pass"])
    return s


# @pytest.fixture
@pytest.mark.django_db
def setup_ise27_reset():
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg1_id"])
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg2_id"])
    Dashboard.objects.all().delete()
    Organization.objects.all().delete()
    SyncSession.objects.all().delete()
    ISEServer.objects.all().delete()
    Tag.objects.all().delete()
    ACL.objects.all().delete()
    Policy.objects.all().delete()
    s = sync._config.servers["2.7"]
    reset_ise(iseip=s["ip"], iseuser=s["user"], isepass=s["pass"])
    return s


# @pytest.fixture
@pytest.mark.django_db
def setup_ise30_reset():
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg1_id"])
    reset_dashboard(baseurl="https://api.meraki.com/api/v1", apikey=sync._config.merakiapi["apikey"],
                    orgid=sync._config.merakiapi["testorg2_id"])
    Dashboard.objects.all().delete()
    Organization.objects.all().delete()
    SyncSession.objects.all().delete()
    ISEServer.objects.all().delete()
    Tag.objects.all().delete()
    ACL.objects.all().delete()
    Policy.objects.all().delete()
    s = sync._config.servers["3.0"]
    reset_ise(iseip=s["ip"], iseuser=s["user"], isepass=s["pass"])
    return s


@pytest.fixture
@pytest.mark.django_db
def setup_ise24_i_src():
    # cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
    #                               orgid=sync._config.merakiapi["testorg1_id"],
    #                               baseurl="https://api.meraki.com/api/v1")
    # reset_dashboard(db=cm)
    #
    # ISEServer.objects.all().delete()
    # s = sync._config.servers["2.4"]
    s = setup_ise24_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=True)


@pytest.fixture
@pytest.mark.django_db
def setup_ise26_i_src():
    s = setup_ise26_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=True)


@pytest.fixture
@pytest.mark.django_db
def setup_ise27_i_src():
    s = setup_ise27_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=True)


@pytest.fixture
@pytest.mark.django_db
def setup_ise30_i_src():
    s = setup_ise30_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=True)


@pytest.fixture
@pytest.mark.django_db
def setup_ise24_m_src():
    s = setup_ise24_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=False)


@pytest.fixture
@pytest.mark.django_db
def setup_ise26_m_src():
    s = setup_ise26_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=False)


@pytest.fixture
@pytest.mark.django_db
def setup_ise27_m_src():
    s = setup_ise27_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=False)


@pytest.fixture
@pytest.mark.django_db
def setup_ise30_m_src():
    s = setup_ise30_reset()
    # UploadZip.objects.create(description="unittest", file=s["cert"])
    # u = Upload.objects.all()
    # print(u)

    cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                  baseurl="https://api.meraki.com/api/v1")
    org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
    cm.organization.add(org)
    ci = ISEServer.objects.create(description=s["desc"], ipaddress=s["ip"], username=s["user"],
                                  password=s["pass"])
    # reset_ise(db=ci)
    SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                               ise_source=False)


@pytest.fixture
@pytest.mark.django_db
def setup_ise24_data_i_src(setup_ise24_i_src):
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise26_data_i_src(setup_ise26_i_src):
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise27_data_i_src(setup_ise27_i_src):
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise30_data_i_src(setup_ise30_i_src):
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise24_data_m_src(setup_ise24_m_src):
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise26_data_m_src(setup_ise26_m_src):
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise27_data_m_src(setup_ise27_m_src):
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise30_data_m_src(setup_ise30_m_src):
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise24_data_sync_i_src(setup_ise24_data_i_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise26_data_sync_i_src(setup_ise26_data_i_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise27_data_sync_i_src(setup_ise27_data_i_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise30_data_sync_i_src(setup_ise30_data_i_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.ise_monitor.sync_ise()
    scripts.dashboard_monitor.sync_dashboard()


@pytest.fixture
@pytest.mark.django_db
def setup_ise24_data_sync_m_src(setup_ise24_data_m_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise26_data_sync_m_src(setup_ise26_data_m_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise27_data_sync_m_src(setup_ise27_data_m_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.fixture
@pytest.mark.django_db
def setup_ise30_data_sync_m_src(setup_ise30_data_m_src):
    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            print("Enabling sync for tag", s.tag_number, "...")
            s.do_sync = True
            s.save()
    scripts.dashboard_monitor.sync_dashboard()
    scripts.ise_monitor.sync_ise()


@pytest.mark.parametrize('arg', ['setup_ise24_i_src', 'setup_ise26_i_src', 'setup_ise27_i_src', 'setup_ise30_i_src'],
                         indirect=True)
@pytest.mark.django_db
def test_ise_dashboard_unable_to_sync_first(arg):
    """With ISE set to Authoritative Source, Dashboard should be unable to sync first"""
    msg, log = scripts.dashboard_monitor.sync_dashboard()
    print(msg)
    assert msg == "SYNC_DASHBOARD-ISE_NEEDS_SYNC"


@pytest.mark.parametrize('arg', ['setup_ise24_i_src', 'setup_ise26_i_src', 'setup_ise27_i_src', 'setup_ise30_i_src'],
                         indirect=True)
@pytest.mark.django_db
def test_ise_iseserver_can_sync(arg):
    """With ISE set to Authoritative Source, ISE should be able to sync first"""
    msg, log = scripts.ise_monitor.sync_ise()
    print(msg)
    assert (msg == "SYNC_ISE-ISE_FORCE_REBUILD") or (msg == "SYNC_ISE-CONFIG_SYNC_TIMESTAMP_MISMATCH")


@pytest.mark.parametrize('arg', ['setup_ise24_i_src', 'setup_ise26_i_src', 'setup_ise27_i_src', 'setup_ise30_i_src'],
                         indirect=True)
@pytest.mark.django_db
def test_ise_dashboard_can_sync_next(arg):
    """With ISE set to Authoritative Source, Dashboard should be able to sync after ISE"""
    msg, log = scripts.ise_monitor.sync_ise()
    msg, log = scripts.dashboard_monitor.sync_dashboard()
    print(msg)
    assert (msg == "SYNC_DASHBOARD-DASHBOARD_FORCE_REBUILD") or (msg == "SYNC_DASHBOARD-CONFIG_SYNC_TIMESTAMP_MISMATCH")


@pytest.mark.parametrize('arg', ['setup_ise24_m_src', 'setup_ise26_m_src', 'setup_ise27_m_src', 'setup_ise30_m_src'],
                         indirect=True)
@pytest.mark.django_db
def test_dashboard_ise_unable_to_sync_first(arg):
    """With Meraki Dashboard set to Authoritative Source, ISE should be unable to sync first"""
    msg, log = scripts.ise_monitor.sync_ise()
    print(msg)
    assert msg == "SYNC_ISE-DASHBOARD_NEEDS_SYNC"


@pytest.mark.parametrize('arg', ['setup_ise24_m_src', 'setup_ise26_m_src', 'setup_ise27_m_src', 'setup_ise30_m_src'],
                         indirect=True)
@pytest.mark.django_db
def test_dashboard_can_sync(arg):
    """With Meraki Dashboard set to Authoritative Source, Dashboard should be able to sync first"""
    msg, log = scripts.dashboard_monitor.sync_dashboard()
    print(msg)
    assert (msg == "SYNC_DASHBOARD-DASHBOARD_FORCE_REBUILD") or (msg == "SYNC_DASHBOARD-CONFIG_SYNC_TIMESTAMP_MISMATCH")


@pytest.mark.parametrize('arg', ['setup_ise24_m_src', 'setup_ise26_m_src', 'setup_ise27_m_src', 'setup_ise30_m_src'],
                         indirect=True)
@pytest.mark.django_db
def test_dashboard_ise_can_sync_next(arg):
    """With Meraki Dashboard set to Authoritative Source, ISE should be able to sync after Dashboard"""
    msg, log = scripts.dashboard_monitor.sync_dashboard()
    msg, log = scripts.ise_monitor.sync_ise()
    print(msg)
    assert (msg == "SYNC_ISE-ISE_FORCE_REBUILD") or (msg == "SYNC_ISE-CONFIG_SYNC_TIMESTAMP_MISMATCH")


@pytest.mark.parametrize('arg', ['setup_ise24_data_i_src', 'setup_ise26_data_i_src', 'setup_ise27_data_i_src',
                                 'setup_ise30_data_i_src', 'setup_ise24_data_m_src', 'setup_ise26_data_m_src',
                                 'setup_ise27_data_m_src', 'setup_ise30_data_m_src'], indirect=True)
@pytest.mark.django_db
def test_sgts_in_database(arg):
    """Whitelisted SGTs must have Dashboard and ISE IDs in the DB; Default SGTs must have ISE IDs in the DB"""
    success = True
    default_vals = [d['value'] for d in sync._config.ise_default_sgts]

    sgts = Tag.objects.order_by("tag_number")
    for s in sgts:
        ds = s.tagdata_set.all()
        if s.tag_number in sync._config.whitelisted_sgts:
            for d in ds:
                if d.source_id is None or d.source_id == "":
                    success = False
                    print("1 (FAIL) :", model_to_dict(s))
                else:
                    print("1 (SUCCESS) :", model_to_dict(s))
        if s.tag_number in default_vals:
            for d in ds:
                if d.iseserver and (d.source_id is None or d.source_id == ""):
                    success = False
                    print("2 (FAIL) :", model_to_dict(s))
                else:
                    print("2 (SUCCESS) :", model_to_dict(s))

    if len(sgts) != len(sync._config.whitelisted_sgts + sync._config.ise_default_sgts +
                        sync._config.meraki_default_sgts):
        success = False
        print("3 (FAIL) : ", sgts, (sync._config.whitelisted_sgts + sync._config.ise_default_sgts +
                                    sync._config.meraki_default_sgts))
    else:
        print("3 (SUCCESS) : ", sgts, (sync._config.whitelisted_sgts + sync._config.ise_default_sgts +
                                       sync._config.meraki_default_sgts))

    assert success


@pytest.mark.parametrize('arg', ['setup_ise24_data_i_src', 'setup_ise26_data_i_src', 'setup_ise27_data_i_src',
                                 'setup_ise30_data_i_src', 'setup_ise24_data_m_src', 'setup_ise26_data_m_src',
                                 'setup_ise27_data_m_src', 'setup_ise30_data_m_src'], indirect=True)
@pytest.mark.django_db
def test_sgacls_in_database(arg):
    """Whitelisted SGACLs must have ISE IDs in the DB and be invisible; Default SGACLs must have ISE IDs in the DB"""
    success = True
    default_vals = [d['name'] for d in sync._config.ise_default_sgacls]

    sgacls = ACL.objects.order_by("name")
    for s in sgacls:
        ds = s.acldata_set.all()
        if s.name in sync._config.whitelisted_sgacls:
            for d in ds:
                if d.iseserver and (d.source_id is None or d.source_id == ""):
                    success = False
                    print("1 (FAIL-MISSING) :", model_to_dict(s))
                elif s.visible:
                    success = False
                    print("1 (FAIL-VISIBLE) :", model_to_dict(s))
                else:
                    print("1 (SUCCESS) :", model_to_dict(s))
        if s.name in default_vals:
            for d in ds:
                if d.iseserver and (d.source_id is None or d.source_id == ""):
                    success = False
                    print("2 (FAIL) :", model_to_dict(s))
                else:
                    print("2 (SUCCESS) :", model_to_dict(s))

    if len(sgacls) != len(sync._config.whitelisted_sgacls + sync._config.ise_default_sgacls +
                          sync._config.meraki_default_sgacls):
        success = False
        print("3 (FAIL) : ", sgacls, (sync._config.whitelisted_sgacls + sync._config.ise_default_sgacls +
                                      sync._config.meraki_default_sgacls))
    else:
        print("3 (SUCCESS) : ", sgacls, (sync._config.whitelisted_sgacls + sync._config.ise_default_sgacls +
                                         sync._config.meraki_default_sgacls))

    assert success


@pytest.mark.parametrize('arg', ['setup_ise24_data_i_src', 'setup_ise26_data_i_src', 'setup_ise27_data_i_src',
                                 'setup_ise30_data_i_src', 'setup_ise24_data_m_src', 'setup_ise26_data_m_src',
                                 'setup_ise27_data_m_src', 'setup_ise30_data_m_src'], indirect=True)
@pytest.mark.django_db
def test_policies_in_database(arg):
    """Whitelisted Policies must have ISE IDs in the DB; Default Policies must have ISE IDs in the DB"""
    success = True
    default_vals = [d['name'] for d in sync._config.ise_default_policies]

    sgpolicies = Policy.objects.order_by("name")
    for s in sgpolicies:
        ds = s.policydata_set.all()
        if s.name in sync._config.whitelisted_policies:
            for d in ds:
                if d.iseserver and (d.source_id is None or d.source_id == ""):
                    success = False
                    print("1 (FAIL) :", model_to_dict(s))
                else:
                    print("1 (SUCCESS) :", model_to_dict(s))
        if s.name in default_vals:
            for d in ds:
                if d.iseserver and (d.source_id is None or d.source_id == ""):
                    success = False
                    print("2 (FAIL) :", model_to_dict(s))
                else:
                    print("2 (SUCCESS) :", model_to_dict(s))

    # The default ISE ANY-ANY policy will not be synchronized to the database; subtract one for that
    if len(sgpolicies) != len(sync._config.whitelisted_policies + sync._config.ise_default_policies +
                              sync._config.meraki_default_policies) - 1:
        success = False
        print("3 (FAIL) : ", sgpolicies, (sync._config.whitelisted_policies + sync._config.ise_default_policies +
                                          sync._config.meraki_default_policies))
    else:
        print("3 (SUCCESS) : ", sgpolicies, (sync._config.whitelisted_policies + sync._config.ise_default_policies +
                                             sync._config.meraki_default_policies))

    assert success


@pytest.mark.parametrize('arg', ['setup_ise24_data_sync_i_src', 'setup_ise26_data_sync_i_src',
                                 'setup_ise27_data_sync_i_src', 'setup_ise30_data_sync_i_src',
                                 'setup_ise24_data_sync_m_src', 'setup_ise26_data_sync_m_src',
                                 'setup_ise27_data_sync_m_src', 'setup_ise30_data_sync_m_src'], indirect=True)
@pytest.mark.django_db
def test_ise_sync_success(arg):
    """Perform a full sync and ensure SGTs, SGACLs and Policies have synced correctly"""
    success = True
    sgts = Tag.objects.all()
    if len(sgts) != len(sync._config.whitelisted_sgts + sync._config.ise_default_sgts +
                        sync._config.meraki_default_sgts):
        success = False
        print("1 (FAIL) :", "Incorrect number of objects in DB")
    for s in sgts:
        if s.tag_number in sync._config.sync_tags:
            if s.do_sync and not s.objects_match(bool_only=True):
                success = False
                print("1 (FAIL) :", model_to_dict(s))
            else:
                print("1 (SUCCESS) :", model_to_dict(s))
    sgacls = ACL.objects.filter(visible=True)
    if len(sgacls) != len(sync._config.ise_default_sgacls + sync._config.meraki_default_sgacls):
        success = False
        print("2 (FAIL) :", "Incorrect number of objects in DB")
    for s in sgacls:
        if s.name in sync._config.expected_ise_sgacls:
            if s.do_sync and not s.objects_match(bool_only=True):
                success = False
                print("2 (FAIL-NO_MATCH) :", model_to_dict(s), "\n", s.objects_match())
        else:
            if s.do_sync:
                success = False
                print("2 (FAIL-SHOULD_NOT_SYNC) :", model_to_dict(s))
        if success:
            print("2 (SUCCESS) :", model_to_dict(s))
    policies = Policy.objects.all()
    if len(policies) != len(sync._config.ise_default_policies + sync._config.meraki_default_policies):
        success = False
        print("3 (FAIL) :", "Incorrect number of objects in DB")
    for s in policies:
        if s.name in sync._config.expected_ise_policies:
            if s.do_sync and not s.objects_match(bool_only=True):
                success = False
                print("3 (FAIL-NO_MATCH) :", model_to_dict(s), "\n", s.objects_match())
                for obj in s.policydata_set.all():
                    print("---", model_to_dict(obj))
        else:
            if s.do_sync:
                success = False
                print("3 (FAIL-SHOULD_NOT_SYNC) :", model_to_dict(s))
        if success:
            print("3 (SUCCESS) :", model_to_dict(s))

    assert success


def push_ise_updates(delay=None):
    ci = ISEServer.objects.all()[0]
    ise = ERS(ise_node=ci.ipaddress, ers_user=ci.username, ers_pass=ci.password, verify=False, disable_warnings=True)

    upd_sgt = ise.get_sgt(sync._config.update_ise_sgt["search"])["response"]
    upd_sgacl = ise.get_sgacl(sync._config.update_ise_sgacl["search"])["response"]
    upd_policy = ise.get_egressmatrixcell(sync._config.update_ise_policy["search"])["response"]

    if not upd_sgt or not upd_sgacl or not upd_policy:
        print("One or more elements missing during search", upd_sgt, upd_sgacl, upd_policy)
        assert False

    if delay:
        time.sleep(delay)
    ise.update_egressmatrixcell(upd_policy["id"], upd_policy["sourceSgtId"], upd_policy["destinationSgtId"],
                                sync._config.update_ise_policy["default"],
                                acls=sync._config.update_ise_policy["acls"],
                                description=sync._config.update_ise_policy["description"])
    # adding sleep for pxgrid test - pxgrid client doesn't seem to be able to catch to several events quickly
    if delay:
        time.sleep(delay)
    ise.update_sgacl(upd_sgacl["id"], sync._config.update_ise_sgacl["name"],
                     sync._config.update_ise_sgacl["description"],
                     sync._config.update_ise_sgacl["version"], sync._config.update_ise_sgacl["aclcontent"])
    # adding sleep for pxgrid test - pxgrid client doesn't seem to be able to catch to several events quickly
    if delay:
        time.sleep(delay)
    ise.update_sgt(upd_sgt["id"], sync._config.update_ise_sgt["name"], sync._config.update_ise_sgt["description"],
                   sync._config.update_ise_sgt["value"])
    if delay:
        time.sleep(delay)


def push_meraki_updates():
    db = Dashboard.objects.all()[0]
    org = Organization.objects.all()[0]
    dashboard = meraki.DashboardAPI(base_url=db.baseurl, api_key=db.apikey, print_console=False, output_log=False,
                                    caller=settings.CUSTOM_UA, suppress_logging=True)

    src_sgt_id = dst_sgt_id = update_sgt_id = update_sgacl_id = None
    # Look up SGT that we are going to be updating in Dashboard...
    sgt_list = meraki_read_sgt(dashboard, org.orgid)
    for a in sgt_list:
        if a["name"] == sync._config.update_ise_sgt["search"]:
            update_sgt_id = a["groupId"]
    # Look up SGACL that we are going to be updating in Dashboard...
    sgacl_list = meraki_read_sgacl(dashboard, org.orgid)
    # print("````````````", sgacl_list)
    for a in sgacl_list:
        # print(a["name"] == sync._config.update_meraki_sgacl["search"], a["name"], sync._config.update_meraki_sgacl["search"])
        if a["name"] == sync._config.update_ise_sgacl["search"]:
            update_sgacl_id = a["aclId"]
        # print("========", update_sgacl_id, a["name"] == sync._config.update_ise_sgacl["search"], a["name"], sync._config.update_ise_sgacl["search"])
    # print("````````````", update_sgacl_id)
    # Look up Policy elements that we are going to be updating in Dashboard...
    for s in sgt_list:
        if s["name"] == sync._config.update_ise_policy["src"]:
            src_sgt_id = s["groupId"]
        if s["name"] == sync._config.update_ise_policy["dst"]:
            dst_sgt_id = s["groupId"]
        # print("``````", src_sgt_id, dst_sgt_id, s["name"], sync._config.update_ise_policy["src"], sync._config.update_ise_policy["dst"])
    acl_id_list = []
    for acl in sync._config.update_ise_policy["acls"]:
        for a in sgacl_list:
            if a["name"] == acl:
                acl_id_list.append(a["aclId"])
    # Update!
    sgp = meraki_update_sgpolicy(dashboard, org.orgid, name=sync._config.update_ise_policy["name"],
                                 description=sync._config.update_ise_policy["description"], srcGroupId=src_sgt_id,
                                 dstGroupId=dst_sgt_id, aclIds=acl_id_list if len(acl_id_list) > 0 else None,
                                 catchAllRule=sync._config.update_ise_policy["default_meraki"], bindingEnabled=True,
                                 monitorModeEnabled=False)

    acl = meraki_update_sgacl(dashboard, org.orgid, update_sgacl_id, name=sync._config.update_ise_sgacl["name"],
                              description=sync._config.update_ise_sgacl["description"],
                              rules=sync._config.update_ise_sgacl["aclcontent_meraki"],
                              ipVersion=sync._config.update_ise_sgacl["version_meraki"])
    sgt = meraki_update_sgt(dashboard, org.orgid, update_sgt_id, name=sync._config.update_ise_sgt["name"],
                            description=sync._config.update_ise_sgt["description"],
                            value=sync._config.update_ise_sgt["value"])
    # Tag.objects.filter(name=sync._config.update_ise_sgt["search"]).update(meraki_id=sgt["groupId"], meraki_data=sgt)
    TagData.objects.exclude(organization=None).filter(tag__name=sync._config.update_ise_sgt["search"]). \
        update(source_id=sgt["groupId"], source_data=sgt)
    print(sgp)
    print(acl)
    print(sgt)


def check_sync_results(d_sgt, d_acl, d_policy, expected_failures=[]):
    success = True
    sgts = Tag.objects.filter(name=d_sgt["name"])
    if len(sgts) != 1:
        print("1 (FAIL) :", "Incorrect number of objects in DB", sgts)
        if "sgt" in expected_failures:
            print("=========This is marked as an expected failure, so maintaining successful response=========")
        else:
            success = False
    for s in sgts:
        # sds = s.tagdata_set.all()
        # for sd in sds:
        #     print("******", s.tag_number, model_to_dict(sd))
        if s.name == d_sgt["name"] and \
                s.description == d_sgt["description"] and \
                s.tag_number == d_sgt["value"] and s.objects_match(True):
            print("1 (SUCCESS) :", model_to_dict(s))
        else:
            print("1 (FAIL) :", model_to_dict(s))
            if "sgt" in expected_failures:
                print("=========This is marked as an expected failure, so maintaining successful response=========")
            else:
                success = False
                print("---", s.name == d_sgt["name"], s.name, d_sgt["name"])
                print("---", s.description == d_sgt["description"], s.description, d_sgt["description"])
                print("---", s.tag_number == d_sgt["value"], s.tag_number, d_sgt["value"])
                # print("---", s.objects_match())
    sgacls = ACL.objects.filter(name=d_acl["name"])
    if len(sgacls) != 1:
        print("2 (FAIL) :", "Incorrect number of objects in DB", sgacls)
        if "sgacl" in expected_failures:
            print("=========This is marked as an expected failure, so maintaining successful response=========")
        else:
            success = False
    for s in sgacls:
        sds = s.acldata_set.all()
        for sd in sds:
            # print("******", sd.acl.name, sd.acl.objects_in_sync(), sd.acl.object_update_target(), model_to_dict(sd))
            if sd.iseserver:
                ise_data = json.loads(sd.source_data)
                if s.name == d_acl["name"] and \
                        s.description == d_acl["description"] and \
                        sd.lookup_version(sd) == d_acl["version"] and \
                        ise_data["aclcontent"] == "\n".join(d_acl["aclcontent"]) and \
                        s.objects_match(True):
                    print("2 (SUCCESS) :", model_to_dict(s))
                else:
                    print("2 (FAIL) :", model_to_dict(s))
                    if "sgacl" in expected_failures:
                        print("=========This is marked as an expected failure, so maintaining successful response=========")
                    else:
                        success = False
                        print("---", s.name == d_acl["name"], s.name, d_acl["name"])
                        print("---", s.description == d_acl["description"], s.description, d_acl["description"])
                        print("---", sd.lookup_version(sd) == d_acl["version"], sd.lookup_version(sd), d_acl["version"])
                        print("---", ise_data["aclcontent"] == "\n".join(d_acl["aclcontent"]),
                              ise_data["aclcontent"], "\n".join(d_acl["aclcontent"]))
                        # print("---", s.objects_match())
    policies = Policy.objects.filter(name=d_policy["name"])
    if len(policies) != 1:
        print("3 (FAIL) :", "Incorrect number of objects in DB", policies)
        if "sgpolicy" in expected_failures:
            print("=========This is marked as an expected failure, so maintaining successful response=========")
        else:
            success = False
    for s in policies:
        sds = s.policydata_set.all()
        for sd in sds:
            # print("******", model_to_dict(sd))
            if sd.iseserver:
                if s.name == d_policy["name"] and \
                        s.description == d_policy["description"] and \
                        sd.lookup_acl_catchall(sd, True) == d_policy.get("default_meraki") and \
                        s.objects_match(True):
                    print("3 (SUCCESS) :", model_to_dict(s))
                else:
                    print("3 (FAIL) :", model_to_dict(s))
                    if "sgpolicy" in expected_failures:
                        print("=========This is marked as an expected failure, so maintaining successful response=========")
                    else:
                        success = False
                        print("---", s.name == d_policy["name"], s.name, d_policy["name"])
                        print("---", s.description == d_policy["description"], s.description, d_policy["description"])
                        print("---", sd.lookup_acl_catchall(sd) == d_policy["default_meraki"], sd.lookup_acl_catchall(sd), d_policy["default_meraki"])
                        # print("---", s.objects_match())

    return success


@pytest.mark.parametrize('arg', ['setup_ise24_data_sync_i_src', 'setup_ise26_data_sync_i_src',
                                 'setup_ise27_data_sync_i_src', 'setup_ise30_data_sync_i_src',
                                 'setup_ise24_data_sync_m_src', 'setup_ise26_data_sync_m_src',
                                 'setup_ise27_data_sync_m_src', 'setup_ise30_data_sync_m_src'], indirect=True)
@pytest.mark.django_db
def test_update_element_success(arg):
    """Perform a full sync and then update each side for SGT, SGACL and Policy; verify elements update correctly"""
    sa = SyncSession.objects.all()[0]

    if sa.ise_source:
        push_ise_updates()
    else:
        push_meraki_updates()

    sa.force_rebuild = True
    sa.save()
    if sa.ise_source:
        msg, log = scripts.ise_monitor.sync_ise()
        # print(msg, log)
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print(msg, log)
    else:
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print(msg, log)
        msg, log = scripts.ise_monitor.sync_ise()
        # print(msg, log)

    success = check_sync_results(sync._config.update_ise_sgt, sync._config.update_ise_sgacl, sync._config.update_ise_policy)
    assert success


@pytest.mark.parametrize('arg', ['setup_ise24_data_sync_i_src', 'setup_ise26_data_sync_i_src',
                                 'setup_ise27_data_sync_i_src', 'setup_ise30_data_sync_i_src',
                                 'setup_ise24_data_sync_m_src', 'setup_ise26_data_sync_m_src',
                                 'setup_ise27_data_sync_m_src', 'setup_ise30_data_sync_m_src'], indirect=True)
@pytest.mark.django_db
def test_update_element_revert(arg):
    """Perform a full sync and then update wrong side for SGT, SGACL and Policy - change should get reverted"""
    sa = SyncSession.objects.all()[0]

    if not sa.ise_source:
        push_ise_updates()
    else:
        push_meraki_updates()

    sa.force_rebuild = True
    sa.save()

    if sa.ise_source:
        msg, log = scripts.ise_monitor.sync_ise()
        # print(msg, log)
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print(msg, log)
    else:
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print(msg, log)
        msg, log = scripts.ise_monitor.sync_ise()
        # print(msg, log)

    success = check_sync_results(sync._config.ise_default_sgts[15], sync._config.ise_default_sgacls[1], sync._config.ise_default_policies[2])
    assert success


def push_meraki_delete():
    db = Dashboard.objects.all()[0]
    org = Organization.objects.all()[0]
    dashboard = meraki.DashboardAPI(base_url=db.baseurl, api_key=db.apikey, print_console=False, output_log=False,
                                    caller=settings.CUSTOM_UA, suppress_logging=True)

    src_sgt_id = dst_sgt_id = update_sgt_id = update_sgacl_id = None
    # Look up SGT that we are going to be updating in Dashboard...
    sgt_list = meraki_read_sgt(dashboard, org.orgid)
    for a in sgt_list:
        if a["name"] == sync._config.update_ise_sgt["search"]:
            update_sgt_id = a["groupId"]
    # Look up SGACL that we are going to be updating in Dashboard...
    sgacl_list = meraki_read_sgacl(dashboard, org.orgid)
    # print("````````````", sgacl_list)
    for a in sgacl_list:
        # print(a["name"] == sync._config.update_meraki_sgacl["search"], a["name"], sync._config.update_meraki_sgacl["search"])
        if a["name"] == sync._config.update_ise_sgacl["search"]:
            update_sgacl_id = a["aclId"]
        # print("========", update_sgacl_id, a["name"] == sync._config.update_ise_sgacl["search"], a["name"], sync._config.update_ise_sgacl["search"])
    # print("````````````", update_sgacl_id)
    # Look up Policy elements that we are going to be updating in Dashboard...
    for s in sgt_list:
        if s["name"] == sync._config.update_ise_policy["src"]:
            src_sgt_id = s["groupId"]
        if s["name"] == sync._config.update_ise_policy["dst"]:
            dst_sgt_id = s["groupId"]
        # print("``````", src_sgt_id, dst_sgt_id, s["name"], sync._config.update_meraki_policy["src"], sync._config.update_meraki_policy["dst"])
    acl_id_list = []
    for acl in sync._config.update_ise_policy["acls"]:
        for a in sgacl_list:
            if a["name"] == acl:
                acl_id_list.append(a["aclId"])

    db = Dashboard.objects.all()[0]
    org = Organization.objects.all()[0]
    dashboard = meraki.DashboardAPI(base_url=db.baseurl, api_key=db.apikey, print_console=False, output_log=False,
                                    caller=settings.CUSTOM_UA, suppress_logging=True)

    src_sgt_id = dst_sgt_id = update_sgt_id = update_sgacl_id = None
    # Look up SGT that we are going to be updating in Dashboard...
    sgt_list = meraki_read_sgt(dashboard, org.orgid)
    # print("#####", sgt_list)
    for a in sgt_list:
        if a["name"] == sync._config.update_ise_sgt["search"]:
            update_sgt_id = a["groupId"]
            # t = Tag.objects.filter(name=a["name"])
            # print(a["name"], sync._config.update_ise_sgt["search"], update_sgt_id, model_to_dict(t[0]))
            break
    # Look up SGACL that we are going to be updating in Dashboard...
    sgacl_list = meraki_read_sgacl(dashboard, org.orgid)
    # print("#####", sgacl_list)
    for a in sgacl_list:
        # print(a["name"], sync._config.update_ise_sgacl["search"])
        if a["name"] == sync._config.update_ise_sgacl["search"]:
            update_sgacl_id = a["aclId"]
    # Look up Policy elements that we are going to be updating in Dashboard...
    for s in sgt_list:
        if s["name"] == sync._config.update_ise_policy["src"]:
            src_sgt_id = s["groupId"]
        if s["name"] == sync._config.update_ise_policy["dst"]:
            dst_sgt_id = s["groupId"]
    acl_id_list = []
    for acl in sync._config.update_ise_policy["acls"]:
        for a in sgacl_list:
            if a["name"] == acl:
                acl_id_list.append(a["aclId"])
    # Delete!
    meraki_update_sgpolicy(dashboard, org.orgid, name=sync._config.update_ise_policy["search"],
                           description=sync._config.update_ise_policy["description"], srcGroupId=src_sgt_id,
                           dstGroupId=dst_sgt_id, aclIds=None, catchAllRule="global")
    meraki_delete_sgacl(dashboard, org.orgid, update_sgacl_id)
    meraki_delete_sgt(dashboard, org.orgid, update_sgt_id)

    # print(update_sgt_id, sgt)
    # Tag.objects.filter(name=sync._config.update_ise_sgt["search"]).update(meraki_id=None, meraki_data=None)


def push_ise_delete():
    ci = ISEServer.objects.all()[0]
    ise = ERS(ise_node=ci.ipaddress, ers_user=ci.username, ers_pass=ci.password, verify=False, disable_warnings=True)

    upd_sgt = ise.get_sgt(sync._config.update_ise_sgt["search"])["response"]
    upd_sgacl = ise.get_sgacl(sync._config.update_ise_sgacl["search"])["response"]
    upd_policy = ise.get_egressmatrixcell(sync._config.update_ise_policy["search"])["response"]

    if not upd_sgt or not upd_sgacl or not upd_policy:
        print("One or more elements missing during search", upd_sgt, upd_sgacl, upd_policy)
        assert False

    ise.delete_egressmatrixcell(upd_policy["id"])
    ise.delete_sgacl(upd_sgacl["id"])
    ise.delete_sgt(upd_sgt["id"])


@pytest.mark.parametrize('arg', ['setup_ise24_data_sync_i_src', 'setup_ise26_data_sync_i_src',
                                 'setup_ise27_data_sync_i_src', 'setup_ise30_data_sync_i_src',
                                 'setup_ise24_data_sync_m_src', 'setup_ise26_data_sync_m_src',
                                 'setup_ise27_data_sync_m_src', 'setup_ise30_data_sync_m_src'], indirect=True)
@pytest.mark.django_db
def test_delete_element_success(arg):
    """Perform a full sync and then delete SGT, SGACL and Policy from each side"""
    sa = SyncSession.objects.all()[0]

    if sa.ise_source:
        push_ise_delete()
    else:
        push_meraki_delete()

    sa.force_rebuild = True
    sa.save()
    if sa.ise_source:
        msg, log = scripts.ise_monitor.sync_ise()
        # print(msg, log)
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print(msg, log)
    else:
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print(msg, log)
        msg, log = scripts.ise_monitor.sync_ise()
        # print(msg, log)

    # m_sgt_list = meraki_read_sgt(dashboard, db.orgid)
    # i_sgt_list = ise.get_sgts(detail=True)
    #
    # sgts = Tag.objects.all()
    # print(sgts, m_sgt_list, i_sgt_list)

    success = True
    sgts = Tag.objects.filter(name=sync._config.update_ise_sgt["search"])
    if len(sgts) != 0:
        success = False
        print("1 (FAIL) :", "Incorrect number of objects in DB")
        for s in sgts:
            print("---", s.push_delete, model_to_dict(s))
            for sd in s.tagdata_set.all():
                print("=====", model_to_dict(sd))
    else:
        print("1 (SUCCESS) :", "Element deleted from DB")
    sgacls = ACL.objects.filter(name=sync._config.update_ise_sgacl["search"])
    if len(sgacls) != 0:
        success = False
        print("2 (FAIL) :", "Incorrect number of objects in DB")
        for s in sgacls:
            print("---", s.push_delete, model_to_dict(s))
            for sd in s.acldata_set.all():
                print("=====", model_to_dict(sd))
    else:
        print("2 (SUCCESS) :", "Element deleted from DB")
    policies = Policy.objects.filter(description=sync._config.update_ise_policy["search"])
    if len(policies) != 0:
        success = False
        print("3 (FAIL) :", "Incorrect number of objects in DB")
        for s in policies:
            print("---", s.push_delete, model_to_dict(s))
            for sd in s.policydata_set.all():
                print("=====", model_to_dict(sd))
    else:
        print("3 (SUCCESS) :", "Element deleted from DB")

    assert success


@pytest.mark.parametrize('arg', ['setup_ise24_data_sync_i_src', 'setup_ise26_data_sync_i_src',
                                 'setup_ise27_data_sync_i_src', 'setup_ise30_data_sync_i_src',
                                 'setup_ise24_data_sync_m_src', 'setup_ise26_data_sync_m_src',
                                 'setup_ise27_data_sync_m_src', 'setup_ise30_data_sync_m_src'], indirect=True)
@pytest.mark.django_db
def test_delete_element_revert(arg):
    """Perform a full sync and then delete SGT, SGACL and Policy from each non-auth size; change should be reverted"""
    sa = SyncSession.objects.all()[0]

    if not sa.ise_source:
        push_ise_delete()
    else:
        push_meraki_delete()

    sa.force_rebuild = True
    sa.save()
    if sa.ise_source:
        msg, log = scripts.ise_monitor.sync_ise()
        # print("ise---------", msg, log)
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print("meraki---------", msg, log)
    else:
        msg, log = scripts.dashboard_monitor.sync_dashboard()
        # print("meraki---------", msg, log)
        msg, log = scripts.ise_monitor.sync_ise()
        # print("ise---------", msg, log)

    # m_sgt_list = meraki_read_sgt(dashboard, db.orgid)
    # i_sgt_list = ise.get_sgts(detail=True)
    #
    # sgts = Tag.objects.all()
    # print(sgts, m_sgt_list, i_sgt_list)

    success = True
    sgts = Tag.objects.filter(name=sync._config.update_ise_sgt["search"])
    if len(sgts) != 1:
        success = False
        print("1 (FAIL) :", "Incorrect number of objects in DB")
    else:
        print("1 (SUCCESS) :", "Element deleted from DB")
    sgacls = ACL.objects.filter(name=sync._config.update_ise_sgacl["search"])
    if len(sgacls) != 1:
        success = False
        print("2 (FAIL) :", "Incorrect number of objects in DB")
    else:
        print("2 (SUCCESS) :", "Element deleted from DB")
    policies = Policy.objects.filter(description=sync._config.update_ise_policy["search"])
    if len(policies) != 1:
        success = False
        print("3 (FAIL) :", "Incorrect number of objects in DB")
    else:
        print("3 (SUCCESS) :", "Element deleted from DB")

    assert success


class PXGridTests(StaticLiveServerTestCase):
    @classmethod
    def test_pxgrid_setup(self, src=None, ci=None, un=None):
        success = True
        if not src or not ci or not un:
            pytest.skip("unsupported configuration")
        UploadZip.objects.create(description=ci["cliname"], file=ci["cert"])
        uploads = Upload.objects.all()
        cli_cert = cli_key = svr_cert = None
        for upload in uploads:
            if upload.filename() == ci["clicert"]:
                cli_cert = upload
            if upload.filename() == ci["clikey"]:
                cli_key = upload
            if upload.filename() == ci["svrcert"]:
                svr_cert = upload
        if not cli_cert or not cli_key or not svr_cert:
            print("Error locating correct certs", uploads)
            assert False
        else:
            cm = Dashboard.objects.create(description="Meraki", apikey=sync._config.merakiapi["apikey"],
                                          baseurl="https://api.meraki.com/api/v1")
            org = Organization.objects.create(orgid=sync._config.merakiapi["testorg1_id"])
            cm.organization.add(org)
            expected_failures = ci.get("expected_failures", [])
            ci = ISEServer.objects.create(description=ci["desc"], ipaddress=ci["ip"], username=ci["user"],
                                          password=ci["pass"], pxgrid_enable=True, pxgrid_cliname=ci["cliname"],
                                          pxgrid_clicert=cli_cert, pxgrid_clikey=cli_key, pxgrid_clipw=ci["pass"],
                                          pxgrid_isecert=svr_cert, pxgrid_ip=ci["ip"])
            SyncSession.objects.create(description="Sync", dashboard=cm, iseserver=ci, force_rebuild=True,
                                       ise_source=True)

            # Ingest default elements into database
            if src == "ise":
                scripts.ise_monitor.sync_ise()
                scripts.dashboard_monitor.sync_dashboard()
            else:
                scripts.dashboard_monitor.sync_dashboard()
                scripts.ise_monitor.sync_ise()

            # Mark tags to sync
            sgts = Tag.objects.order_by("tag_number")
            for s in sgts:
                if s.tag_number in sync._config.sync_tags:
                    print("Enabling sync for tag", s.tag_number, "...")
                    s.do_sync = True
                    s.save()

            # Re-run sync to push updates out
            if src == "ise":
                scripts.ise_monitor.sync_ise()
                scripts.dashboard_monitor.sync_dashboard()
            else:
                scripts.dashboard_monitor.sync_dashboard()
                scripts.ise_monitor.sync_ise()

            # Now, we will start the pxgrid monitor and make more changes
            print("Starting Monitor...")
            loop = asyncio.new_event_loop()
            testthread = scripts.px_subscribe.StoppableThread(loop)
            testthread.start()
            # try:
            #     loop = asyncio.new_event_loop()
            #     th = threading.Thread(target=scripts.px_subscribe.start_background_loop, args=(loop,))
            #     th.start()
            #     scripts.px_subscribe.run(loop)
            # except Exception:
            #     print("exception on async loop")

            print("Sleeping 10 seconds to allow websocket to establish...")
            time.sleep(10)
            print("Initiating updates...")
            if src == "ise":
                push_ise_updates(delay=10)
            else:
                push_meraki_updates()

            print("Sleeping 5 seconds to allow results to finish...")
            time.sleep(5)
            print("Checking results...")
            success = check_sync_results(sync._config.update_ise_sgt, sync._config.update_ise_sgacl,
                                         sync._config.update_ise_policy, expected_failures=expected_failures)

            print("Sleeping 10 seconds to allow job to terminate...")
            time.sleep(10)
            testthread.stop()

            # try:
            #     if loop:
            #         loop.stop()
            # except Exception:
            #     print("exception stopping loop")
        return success

    def test_web_ise_24_i(self):
        assert self.test_pxgrid_setup("ise", setup_ise24_reset(), "ise_src_24")

    def test_web_ise_26_i(self):
        assert self.test_pxgrid_setup("ise", setup_ise26_reset(), "ise_src_26")

    def test_web_ise_27_i(self):
        assert self.test_pxgrid_setup("ise", setup_ise27_reset(), "ise_src_27")

    def test_web_ise_30_i(self):
        assert self.test_pxgrid_setup("ise", setup_ise30_reset(), "ise_src_30")

    # def test_web_ise_24_m(self):
    #     assert self.test_pxgrid_setup("meraki", setup_ise24_reset(), "meraki_src_24")
    #
    # def test_web_ise_26_m(self):
    #     assert self.test_pxgrid_setup("meraki", setup_ise26_reset(), "meraki_src_26")
    #
    # def test_web_ise_27_m(self):
    #     assert self.test_pxgrid_setup("meraki", setup_ise27_reset(), "meraki_src_27")
    #
    # def test_web_ise_30_m(self):
    #     assert self.test_pxgrid_setup("meraki", setup_ise30_reset(), "meraki_src_30")


class APITests(StaticLiveServerTestCase):
    @classmethod
    def test_api_setup(self, src=None, ci=None, un=None):
        if not src or not ci or not un:
            pytest.skip("unsupported configuration")
        user = User.objects.create_superuser(sync._config.test_user["username"], sync._config.test_user["email"],
                                             sync._config.test_user["password"])
        t = Token.objects.get_or_create(user=user, key=sync._config.test_user["apikey"])
        success = True
        headers = {"Authorization": "Bearer " + sync._config.test_user["apikey"],
                   "Content-Type": "application/json"}

        url = self.live_server_url + "/api/v0/iseserver/"
        data = {"description": ci["desc"],
                "ipaddress": ci["ip"],
                "username": ci["user"],
                "password": ci["pass"],
                "pxgrid_enable": False}
        ret = requests.request("POST", url, json=data, headers=headers)
        ise_json = ret.json()

        url = self.live_server_url + "/api/v0/organization/"
        data = {"orgid": sync._config.merakiapi["testorg1_id"]}
        ret = requests.request("POST", url, json=data, headers=headers)
        org1_json = ret.json()

        if src == "ise":
            print("Source is ISE; Configuring multi-org for Meraki")
            url = self.live_server_url + "/api/v0/organization/"
            data = {"orgid": sync._config.merakiapi["testorg2_id"]}
            ret = requests.request("POST", url, json=data, headers=headers)
            org2_json = ret.json()

            url = self.live_server_url + "/api/v0/dashboard/"
            data = {"description": "My Meraki Dashboard",
                    "apikey": sync._config.merakiapi["apikey"],
                    "webhook_enable": False,
                    "webhook_ngrok": False,
                    "webhook_url": "",
                    "organization":
                        [org1_json.get("id"), org2_json.get("id")]}
            ret = requests.request("POST", url, json=data, headers=headers)
            dashboard_json = ret.json()
        else:
            print("Source is Meraki; Configuring single org only")
            url = self.live_server_url + "/api/v0/dashboard/"
            data = {"description": "My Meraki Dashboard",
                    "apikey": sync._config.merakiapi["apikey"],
                    "webhook_enable": False,
                    "webhook_ngrok": False,
                    "webhook_url": "",
                    "organization":
                        [org1_json.get("id")]}
            ret = requests.request("POST", url, json=data, headers=headers)
            dashboard_json = ret.json()

        url = self.live_server_url + "/api/v0/syncsession/"
        data = {"description": "Sync Session",
                "dashboard": dashboard_json.get("id"),
                "iseserver": ise_json.get("id"),
                "ise_source": True if src == "ise" else False,
                "sync_enabled": True,
                "apply_changes": True,
                "sync_interval": 300}
        ret = requests.request("POST", url, json=data, headers=headers)
        ss_json = ret.json()

        if src == "ise":
            msg, log = scripts.ise_monitor.sync_ise()
            msg, log = scripts.dashboard_monitor.sync_dashboard()
        else:
            msg, log = scripts.dashboard_monitor.sync_dashboard()
            msg, log = scripts.ise_monitor.sync_ise()

        url = self.live_server_url + "/api/v0/tag/"
        ret = requests.request("GET", url, headers=headers)
        tags = ret.json()

        for t in tags["results"]:
            if t.get("tag_number") in sync._config.sync_tags:
                url = self.live_server_url + "/api/v0/tag/" + str(t.get("id", "")) + "/"
                data = {"do_sync": True}
                ret = requests.request("PATCH", url, json=data, headers=headers)
                # tag_json = ret.json()

        if src == "ise":
            msg, log = scripts.ise_monitor.sync_ise()
            msg, log = scripts.dashboard_monitor.sync_dashboard()
            push_ise_updates()
        else:
            msg, log = scripts.dashboard_monitor.sync_dashboard()
            msg, log = scripts.ise_monitor.sync_ise()
            push_meraki_updates()

        url = self.live_server_url + "/api/v0/syncsession/" + ss_json.get("id", "") + "/"
        data = {"force_rebuild": True}
        ret = requests.request("PATCH", url, json=data, headers=headers)
        ss_json = ret.json()

        if src == "ise":
            msg, log = scripts.ise_monitor.sync_ise()
            msg, log = scripts.dashboard_monitor.sync_dashboard()
        else:
            msg, log = scripts.dashboard_monitor.sync_dashboard()
            msg, log = scripts.ise_monitor.sync_ise()

        success = check_sync_results(sync._config.update_ise_sgt, sync._config.update_ise_sgacl,
                                     sync._config.update_ise_policy)

        return success

    def test_web_ise_24_i(self):
        assert self.test_api_setup("ise", setup_ise24_reset(), "ise_src_24")

    def test_web_ise_26_i(self):
        assert self.test_api_setup("ise", setup_ise26_reset(), "ise_src_26")

    def test_web_ise_27_i(self):
        assert self.test_api_setup("ise", setup_ise27_reset(), "ise_src_27")

    def test_web_ise_30_i(self):
        assert self.test_api_setup("ise", setup_ise30_reset(), "ise_src_30")

    def test_web_ise_24_m(self):
        assert self.test_api_setup("meraki", setup_ise24_reset(), "meraki_src_24")

    def test_web_ise_26_m(self):
        assert self.test_api_setup("meraki", setup_ise26_reset(), "meraki_src_26")

    def test_web_ise_27_m(self):
        assert self.test_api_setup("meraki", setup_ise27_reset(), "meraki_src_27")

    def test_web_ise_30_m(self):
        assert self.test_api_setup("meraki", setup_ise30_reset(), "meraki_src_30")


class BrowserTests(StaticLiveServerTestCase):
    # https://medium.com/@unionproject88/django-and-selenium-unit-tests-1136041f8d24
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # cls.selenium = WebDriver()
        # cls.selenium = webdriver.Chrome()
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-gpu')  # Last I checked this was necessary.
        cls.selenium = webdriver.Chrome(ChromeDriverManager().install(), chrome_options=options)

        cls.selenium.implicitly_wait(10)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super().tearDownClass()

    # @pytest.mark.django_db
    # @staticmethod
    # https://medium.com/@bierus/end-2-end-testing-with-separated-fronted-f2a5dc5be12
    @pytest.mark.skip(reason="internal function")
    def test_web_setup(self, src=None, ci=None, un=None):
        if not src or not ci or not un:
            pytest.skip("unsupported configuration")
        User.objects.create_superuser(un, sync._config.test_user["email"],
                                      sync._config.test_user["password"])
        success = True      # sync._config.test_user["username"]
        self.selenium.get(self.live_server_url)
        # Log into Adaptive Policy Sync Tool
        username_input = self.selenium.find_element_by_name("username")
        username_input.send_keys(un)        # sync._config.test_user["username"]
        password_input = self.selenium.find_element_by_name("password")
        password_input.send_keys(sync._config.test_user["password"])
        self.selenium.find_element_by_name("login").click()

        # Setup Landing page; Click the Start button
        self.selenium.find_element_by_name("start").click()

        # ISE Setup page. Enter the ISE Server IP address, username and password. Then click Next
        iseip_input = self.selenium.find_element_by_name("iseIP")
        iseip_input.send_keys(ci["ip"])
        iseusername_input = self.selenium.find_element_by_name("iseUser")
        iseusername_input.send_keys(ci["user"])
        isepassword_input = self.selenium.find_element_by_name("isePass")
        isepassword_input.send_keys(ci["pass"])
        self.selenium.find_element_by_name("nextbtn").click()

        # Meraki Setup page. Enter the Meraki API Key, select the organization, then click Next
        merakikey_input = self.selenium.find_element_by_name("apiKey")
        merakikey_input.send_keys(sync._config.merakiapi["apikey"])
        merakikey_input.send_keys(Keys.TAB)
        time.sleep(3)
        self.selenium.find_element_by_id("btnorg").click()
        time.sleep(1)
        element = self.selenium.find_element_by_id(sync._config.merakiapi["testorg1_id"])
        coordinates = element.location_once_scrolled_into_view
        self.selenium.execute_script('window.scrollTo({}, {});'.format(coordinates['x'], coordinates['y']))
        element.click()
        self.selenium.find_element_by_name("nextbtn").click()

        # Sync Setup page. Ensure configuration is set to source from ISE, then click Finish
        if src == "ise":
            self.selenium.find_element_by_id("label_ise").click()
        elif src == "meraki":
            self.selenium.find_element_by_id("label_meraki").click()
        else:
            assert False
        self.selenium.find_element_by_name("finishbtn").click()

        # Manually sync environments
        if src == "ise":
            msg, log = scripts.ise_monitor.sync_ise()
            msg, log = scripts.dashboard_monitor.sync_dashboard()
        else:
            msg, log = scripts.dashboard_monitor.sync_dashboard()
            msg, log = scripts.ise_monitor.sync_ise()
        self.selenium.refresh()

        # Click Status on Sidebar
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-1").click()
        # Click SGTs under Status on Sidebar
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-3-1").click()

        # Check all of the SGTs that are in the sync_tags list in _config
        tags = Tag.objects.all()
        for t in tags:
            if t.tag_number in sync._config.sync_tags:
                checkid = "check-" + str(t.id)
                self.selenium.find_element_by_name(checkid).send_keys(Keys.SPACE)

        # Click Save
        element = self.selenium.find_element_by_id("savebtn")
        coordinates = element.location_once_scrolled_into_view
        self.selenium.execute_script('window.scrollTo({}, {});'.format(coordinates['x'], coordinates['y']))
        element.click()

        # Manually sync environments
        if src == "ise":
            msg, log = scripts.ise_monitor.sync_ise()
            msg, log = scripts.dashboard_monitor.sync_dashboard()
        else:
            msg, log = scripts.dashboard_monitor.sync_dashboard()
            msg, log = scripts.ise_monitor.sync_ise()
        self.selenium.refresh()

        # Click Status on Sidebar (already open; skip)
        # print("Opening Status Menu")
        # self.selenium.find_element_by_id("md-sidebar__nav-item-1-1").click()
        # Click SGACLs under Status on Sidebar
        print("Opening Status->SGACLs")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-3-3").click()
        # Click Policies under Status on Sidebar
        print("Opening Status->Policies")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-3-5").click()

        # Click Configuration on Sidebar
        print("Opening Configuration Menu")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-4").click()
        # Click ISE Certificates under Status on Sidebar
        print("Opening Configuration->ISE Certificates")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-6-1").click()
        # Click ISE Server under Status on Sidebar
        print("Opening Configuration->ISE Server")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-6-3").click()
        # Click Meraki Dashboard under Status on Sidebar
        print("Opening Configuration->Meraki Dashboard")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-6-5").click()
        # Click Sync Config under Status on Sidebar
        print("Opening Configuration->Sync")
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-6-7").click()

        # Click Home on Sidebar
        self.selenium.find_element_by_id("md-sidebar__nav-item-1-9").click()

        msgt = self.selenium.find_element_by_id("meraki-sgt-ok").text
        isgt = self.selenium.find_element_by_id("ise-sgt-ok").text
        msgacl = self.selenium.find_element_by_id("meraki-sgacl-ok").text
        isgacl = self.selenium.find_element_by_id("ise-sgacl-ok").text
        mpol = self.selenium.find_element_by_id("meraki-policy-ok").text
        ipol = self.selenium.find_element_by_id("ise-policy-ok").text
        # print(msgt, isgt, msgacl, isgacl, mpol, ipol)

        if int(msgt) + int(isgt) != len(sync._config.sync_tags):
            print("1 (FAIL) :", "Incorrect number of objects in DB")
            print("--", msgt, isgt, str(int(msgt) + int(isgt)), str(len(sync._config.sync_tags)))
            for o in Tag.objects.all():
                print("--", o.name, o.update_success(), o.origin_org, o.origin_ise)
            success = False
        else:
            print("1 (SUCCESS) :", "Correct number of objects in DB")

        if int(msgacl) + int(isgacl) != len(sync._config.expected_ise_sgacls):
            print("2 (FAIL) :", "Incorrect number of objects in DB")
            print("--", msgacl, isgacl, str(int(msgacl) + int(isgacl)), str(len(sync._config.expected_ise_sgacls)))
            for o in ACL.objects.all():
                print("--", o.name, o.update_success(), o.origin_org, o.origin_ise)
            success = False
        else:
            print("2 (SUCCESS) :", "Correct number of objects in DB")

        if int(mpol) + int(ipol) != len(sync._config.expected_ise_policies):
            print("3 (FAIL) :", "Incorrect number of objects in DB")
            print("--", mpol, ipol, str(int(mpol) + int(ipol)), str(len(sync._config.expected_ise_policies)))
            for o in Policy.objects.all():
                print("--", o.name, o.update_success(), o.origin_org, o.origin_ise)
            success = False
        else:
            print("3 (SUCCESS) :", "Correct number of objects in DB")

        return success

    def test_web_ise_24_i(self):
        assert self.test_web_setup("ise", setup_ise24_reset(), "ise_src_24")

    def test_web_ise_26_i(self):
        assert self.test_web_setup("ise", setup_ise26_reset(), "ise_src_26")

    def test_web_ise_27_i(self):
        assert self.test_web_setup("ise", setup_ise27_reset(), "ise_src_27")

    def test_web_ise_30_i(self):
        assert self.test_web_setup("ise", setup_ise30_reset(), "ise_src_30")

    def test_web_ise_24_m(self):
        assert self.test_web_setup("meraki", setup_ise24_reset(), "meraki_src_24")

    def test_web_ise_26_m(self):
        assert self.test_web_setup("meraki", setup_ise26_reset(), "meraki_src_26")

    def test_web_ise_27_m(self):
        assert self.test_web_setup("meraki", setup_ise27_reset(), "meraki_src_27")

    def test_web_ise_30_m(self):
        assert self.test_web_setup("meraki", setup_ise30_reset(), "meraki_src_30")
