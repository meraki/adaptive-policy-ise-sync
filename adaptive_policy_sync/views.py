from sync.models import ISEServer, Upload, UploadZip, Dashboard, Organization, \
    Task, DataPipeline, Element, ElementSync, GenericData, GenericType, Generic
# from sync.models import Tag, ACL, Policy, SyncSession, TagData, ACLData, PolicyData,
from django.shortcuts import redirect, reverse, render
from django.contrib.auth import logout
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import views as auth_views
from .forms import UploadForm
from scripts.db_backup import backup, tech_backup
from scripts.db_restore import restore
import os
from pathlib import Path
import meraki
from meraki.exceptions import APIError
from django.conf import settings
import json
import string
import random
import uuid
from requests.auth import HTTPBasicAuth
import requests
requests.urllib3.disable_warnings()


def string_generator(size):
    chars = string.digits + string.ascii_uppercase + string.ascii_lowercase
    return ''.join(random.choice(chars) for _ in range(size))


def string_num_generator(size):
    chars = string.digits
    return ''.join(random.choice(chars) for _ in range(size))


def startresync(request):
    # ss = SyncSession.objects.all()
    # if len(ss) > 0:
    #     ss[0].force_rebuild = True
    #     ss[0].save()
    ElementSync.objects.filter(enabled=True).update(force_rebuild=True)
    Element.objects.filter(enabled=True).update(force_rebuild=True)
    # ISEServer.objects.filter(enabled=True).update(force_rebuild=True)
    # Organization.objects.filter(enabled=True).update(force_rebuild=True)
    return JsonResponse({}, safe=False)


def delobject(request):
    pathlist = request.path.split("/")
    if len(pathlist) == 4:
        if pathlist[2] == "sgt":
            Generic.objects.filter(elementtype_name="Tag").filter(id=pathlist[3]).delete()
            # Tag.objects.filter(id=pathlist[3]).delete()
        elif pathlist[2] == "sgacl":
            Generic.objects.filter(elementtype_name="ACL").filter(id=pathlist[3]).delete()
            # ACL.objects.filter(id=pathlist[3]).delete()
        elif pathlist[2] == "policy":
            Generic.objects.filter(elementtype_name="Policy").filter(id=pathlist[3]).delete()
            # Policy.objects.filter(id=pathlist[3]).delete()

    return JsonResponse({}, safe=False)


def getmerakiorgs(request):
    apikey = request.headers.get("X-Cisco-Meraki-API-Key")
    baseurl = request.headers.get("X-Cisco-Meraki-API-URL")

    try:
        dashboard = meraki.DashboardAPI(base_url=baseurl, api_key=apikey,
                                        print_console=False, output_log=False)
        orgs = dashboard.organizations.getOrganizations()
        orgs_sorted = sorted(orgs, key=lambda i: i['name'])
        return JsonResponse(orgs_sorted, safe=False)
    except Exception:
        return JsonResponse({}, safe=False)


def doisecheck(request):
    baseurl = request.headers.get("X-ISE-URL")
    username = request.headers.get("X-ISE-Username")
    password = request.headers.get("X-ISE-Password")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    try:
        req = requests.get(baseurl, auth=HTTPBasicAuth(username, password), headers=headers, verify=False, timeout=4)
        if req.ok:
            ise_details = req.json()
            # {
            # 	'VersionInfo': {
            # 		'currentServerVersion': '1.2',
            # 		'supportedVersions': '1.0,1.1,1.2',
            # 		'link': {
            # 			'rel': 'self',
            # 			'href': 'https://10.102.172.126:9060/ers/config/node/versioninfo',
            # 			'type': 'application/json'
            # 		}
            # 	}
            # }

            return JsonResponse([ise_details], safe=False)
        else:
            return JsonResponse([{"error": "Unable to get response from ISE."}])
    except Exception:
        return JsonResponse([{"error": "Exception ocurred trying to contact ISE."}], safe=False)


def dolanding(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    # syncs = SyncSession.objects.all()
    syncs = ElementSync.objects.all()
    if len(syncs) > 0:
        sync = syncs[0]
    else:
        sync = None

    if sync:
        return redirect("/home")
    else:
        return redirect("/setup")


def setup(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    return render(request, 'setup/landing.html', {"active": 1})


def setupise(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    iseservers = ISEServer.objects.all()
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    return render(request, 'setup/ise.html', {"active": 2, "data": iseserver})


def setupisenext(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    iseservers = ISEServer.objects.all()
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    if request.method == 'POST':
        iseip = request.POST.get("iseIP")
        iseun = request.POST.get("iseUser")
        isepw = request.POST.get("isePass")
        pxgrid_post = request.POST.get("use_pxgrid")
        if pxgrid_post:
            pxgrid = True
        else:
            pxgrid = False

        if iseip and iseun and isepw:
            if iseserver:
                iseserver.ipaddress = iseip
                iseserver.username = iseun
                iseserver.password = isepw
                iseserver.pxgrid_enable = pxgrid
                iseserver.save()
            else:
                ISEServer.objects.create(description="ISE Server", ipaddress=iseip, username=iseun, password=isepw,
                                         pxgrid_enable=pxgrid)
        else:
            print("ISE Server: missing fields")

        if pxgrid:
            return redirect('/setup/isecert')
        else:
            return redirect('/setup/meraki')
    else:
        return redirect('/setup/isecert')


def setupcert(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    uploadzips = Upload.objects.all()

    form = UploadForm()
    return render(request, 'setup/isecert.html', {"active": 3, "data": uploadzips, "form": form})


def setuppxgrid(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    if request.method == 'POST':
        form = UploadForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()

    iseservers = ISEServer.objects.all()
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    uploads = Upload.objects.all().exclude(description__contains="CertificateServices")
    return render(request, 'setup/isepxgrid.html', {"active": 4, "data": iseserver, "upload": uploads})


def setupmeraki(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    dashboards = Dashboard.objects.all()
    if len(dashboards) > 0:
        dashboard = dashboards[0]
    else:
        dashboard = None

    organizations = Organization.objects.all()
    if len(organizations) > 0:
        organization = organizations[0]
    else:
        organization = None

    iseservers = ISEServer.objects.all()
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    if request.method == 'POST':
        pxgridip = request.POST.get("pxgridIP")
        pxgridcli = request.POST.get("pxgridClient")
        pxgridpw = request.POST.get("pxgridPassword")
        client_certid = request.POST.get("clientcertid")
        client_keyid = request.POST.get("clientkeyid")
        server_certid = request.POST.get("servercertid")
        cli_cert = Upload.objects.filter(id=client_certid)
        cli_key = Upload.objects.filter(id=client_keyid)
        server_cert = Upload.objects.filter(id=server_certid)

        if pxgridip and pxgridcli and pxgridpw and len(cli_cert) > 0 and len(cli_key) > 0 and len(server_cert) > 0:
            if iseserver:
                iseserver.pxgrid_ip = pxgridip
                iseserver.pxgrid_cliname = pxgridcli
                iseserver.pxgrid_clicert = cli_cert[0]
                iseserver.pxgrid_clikey = cli_key[0]
                iseserver.pxgrid_clipw = pxgridpw
                iseserver.pxgrid_isecert = server_cert[0]
                iseserver.save()

    return render(request, 'setup/meraki.html', {"active": 5, "data": dashboard, "org": organization})


def setupsync(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = ElementSync.objects.all()
    if len(syncs) > 0:
        sync = syncs[0]
        defsync = False
    else:
        sync = None
        defsync = True

    dashboards = Dashboard.objects.all()
    if len(dashboards) > 0:
        dashboard = dashboards[0]
    else:
        dashboard = None

    if request.method == 'POST':
        apiurl = request.POST.get("apiUrl")
        apikey = request.POST.get("apiKey")
        orgid = request.POST.get("orgid")
        if apikey and orgid:
            if dashboard:
                dashboard.apikey = apikey
                # dashboard.orgid = orgid
                orgs = Organization.objects.all()
                if len(orgs) == 1:                      # If there is one organization selected, replace it
                    orgs[0].orgid = orgid
                    orgs[0].save()
                else:                                   # Otherwise, if there are 0 or >1 orgs, add it
                    o = Organization.objects.create(orgid=orgid)
                    dashboard.organization.add(o)
                dashboard.save()
            else:
                o = Organization.objects.create(orgid=orgid)
                d = Dashboard.objects.create(description="Meraki Dashboard", apikey=apikey, baseurl=apiurl)
                d.organization.add(o)

    return render(request, 'setup/sync.html', {"active": 6, "data": sync, "default_sync": defsync})


def setupdone(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = ElementSync.objects.all()
    if len(syncs) > 0:
        sync = syncs[0]
    else:
        sync = None

    # iseservers = ISEServer.objects.all()
    iseservers = Element.objects.filter(organization=None)
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    # dashboards = Dashboard.objects.all()
    organizations = Element.objects.filter(iseserver=None)
    if len(organizations) > 0:
        organization = organizations[0]
    else:
        organization = None

    if request.method == 'POST':
        source = request.POST.get("basicRadio")
        sync_int = request.POST.get("syncInterval")
        post_dosync = request.POST.get("do_sync")
        if post_dosync:
            dosync = True
        else:
            dosync = False

        if source.lower() == "ise":
            # ise_source = True
            element_source = iseserver
            element_dest = organization
        else:
            element_source = organization
            element_dest = iseserver

        if sync_int:
            if sync and iseserver and organization:
                # sync.ise_source = ise_source
                sync.src_element = element_source
                sync.sync_interval = sync_int
                sync.apply_changes = dosync
                sync.dst_element.add(element_dest)
                sync.save()
            else:
                sync = ElementSync.objects.create(description="TrustSec Sync", src_element=element_source,
                                                  sync_interval=sync_int, enabled=True, apply_changes=dosync)
                sync.dst_element.add(element_dest)
                sync.save()

    return redirect("/home")


def home(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    # syncs = SyncSession.objects.all()
    syncs = ElementSync.objects.all()
    if len(syncs) > 0:
        sync = syncs[0]
    else:
        sync = None

    iseservers = ISEServer.objects.all()
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    dashboards = Dashboard.objects.all()
    if len(dashboards) > 0:
        dashboard = dashboards[0]
    else:
        dashboard = None

    # meraki_sgts = Tag.objects.filter(origin_org__isnull=False)
    # meraki_sgacls = ACL.objects.filter(origin_org__isnull=False)
    # meraki_policies = Policy.objects.filter(origin_org__isnull=False)
    # ise_sgts = Tag.objects.filter(origin_ise__isnull=False)
    # ise_sgacls = ACL.objects.filter(origin_ise__isnull=False)
    # ise_policies = Policy.objects.filter(origin_ise__isnull=False)
    meraki_sgts = Generic.objects.filter(generictype__name="Tag").filter(element__organization__isnull=False)
    meraki_sgacls = Generic.objects.filter(generictype__name="ACL").filter(element__organization__isnull=False)
    meraki_policies = Generic.objects.filter(generictype__name="Policy").filter(element__organization__isnull=False)
    ise_sgts = Generic.objects.filter(generictype__name="Tag").filter(element__iseserver__isnull=False)
    ise_sgacls = Generic.objects.filter(generictype__name="ACL").filter(element__iseserver__isnull=False)
    ise_policies = Generic.objects.filter(generictype__name="Policy").filter(element__iseserver__isnull=False)

    e_meraki_sgts = []
    e_meraki_sgacls = []
    e_meraki_policies = []
    e_ise_sgts = []
    e_ise_sgacls = []
    e_ise_policies = []
    s_meraki_sgts = []
    s_meraki_sgacls = []
    s_meraki_policies = []
    s_ise_sgts = []
    s_ise_sgacls = []
    s_ise_policies = []
    for element in meraki_sgts:
        us = element.update_success()
        if us is True:
            s_meraki_sgts.append(element)
        elif us is False:
            e_meraki_sgts.append(element)

    for element in meraki_sgacls:
        us = element.update_success()
        if us is True:
            s_meraki_sgacls.append(element)
        elif us is False:
            e_meraki_sgacls.append(element)

    for element in meraki_policies:
        us = element.update_success()
        if us is True:
            s_meraki_policies.append(element)
        elif us is False:
            e_meraki_policies.append(element)

    for element in ise_sgts:
        us = element.update_success()
        if us is True:
            s_ise_sgts.append(element)
        elif us is False:
            e_ise_sgts.append(element)

    for element in ise_sgacls:
        us = element.update_success()
        if us is True:
            s_ise_sgacls.append(element)
        elif us is False:
            e_ise_sgacls.append(element)

    for element in ise_policies:
        us = element.update_success()
        if us is True:
            s_ise_policies.append(element)
        elif us is False:
            e_ise_policies.append(element)

    # e_meraki_sgts = Tag.objects.filter(sourced_from="meraki").exclude(last_update_state="200").\
    #     exclude(last_update_state="201").exclude(last_update_state=None)
    # e_meraki_sgacls = ACL.objects.filter(sourced_from="meraki").exclude(last_update_state="200").\
    #     exclude(last_update_state="201").exclude(last_update_state=None)
    # e_meraki_policies = Policy.objects.filter(sourced_from="meraki").exclude(last_update_state="200").\
    #     exclude(last_update_state="201").exclude(last_update_state=None)
    # e_ise_sgts = Tag.objects.filter(sourced_from="ise").exclude(last_update_state="200").\
    #     exclude(last_update_state="201").exclude(last_update_state=None)
    # e_ise_sgacls = ACL.objects.filter(sourced_from="ise").exclude(last_update_state="200").\
    #     exclude(last_update_state="201").exclude(last_update_state=None)
    # e_ise_policies = Policy.objects.filter(sourced_from="ise").exclude(last_update_state="200").\
    #     exclude(last_update_state="201").exclude(last_update_state=None)
    #
    # s_meraki_sgts = Tag.objects.filter(sourced_from="meraki").filter(Q(last_update_state="200") |
    #                                                                  Q(last_update_state="201"))
    # s_meraki_sgacls = ACL.objects.filter(sourced_from="meraki").filter(Q(last_update_state="200") |
    #                                                                    Q(last_update_state="201"))
    # s_meraki_policies = Policy.objects.filter(sourced_from="meraki").filter(Q(last_update_state="200") |
    #                                                                         Q(last_update_state="201"))
    # s_ise_sgts = Tag.objects.filter(sourced_from="ise").filter(Q(last_update_state="200") |
    #                                                            Q(last_update_state="201"))
    # s_ise_sgacls = ACL.objects.filter(sourced_from="ise").filter(Q(last_update_state="200") |
    #                                                              Q(last_update_state="201"))
    # s_ise_policies = Policy.objects.filter(sourced_from="ise").filter(Q(last_update_state="200") |
    #                                                                   Q(last_update_state="201"))

    crumbs = '<li class="current">Home</li>'
    return render(request, 'home/home.html',
                  {"crumbs": crumbs, "data": {"sync": sync, "counts": [len(meraki_sgts), len(meraki_sgacls),
                                                                       len(meraki_policies), len(ise_sgts),
                                                                       len(ise_sgacls), len(ise_policies)],
                                              "err_counts": [len(e_meraki_sgts), len(e_meraki_sgacls),
                                                             len(e_meraki_policies), len(e_ise_sgts),
                                                             len(e_ise_sgacls), len(e_ise_policies)],
                                              "ok_counts": [len(s_meraki_sgts), len(s_meraki_sgacls),
                                                            len(s_meraki_policies), len(s_ise_sgts),
                                                            len(s_ise_sgacls), len(s_ise_policies)],
                                              "dashboard": dashboard, "iseserver": iseserver}})


# def sgtstatus(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     filter_name = "All"
#     if request.method == 'POST':
#         filter_id = request.POST.get("filter-id-id")
#     else:
#         filter_id = request.GET.get("filter-id-id")
#
#     if filter_id:
#         if filter_id == "0":
#             tags = Tag.objects.all()
#         else:
#             tags = Tag.objects.filter(syncsession=filter_id)
#     else:
#         tags = Tag.objects.all()
#
#     log_filter = [{"id": 0, "description": "All"}]
#     syncs = SyncSession.objects.all()
#     for d in syncs:
#         this_id = str(d.id)
#         if filter_id == this_id:
#             filter_name = d.description
#         log_filter.append({"id": this_id, "description": "Sync: " + d.description})
#
#     pk = request.GET.get("id")
#     if pk:
#         sgts = Tag.objects.filter(id=pk)
#         if len(sgts) == 1:
#             sgt = sgts[0]
#             desc = sgt.name + " (" + str(sgt.tag_number) + ")"
#             crumbs = '''
#                 <li class="current">Status</li>
#                 <li><a href="/home/status-sgt">SGTs</a></li>
#                 <li class="current">''' + desc + '''</li>
#             '''
#             return render(request, 'home/showsgt.html', {"crumbs": crumbs, "menuopen": 1, "data": sgt})
#
#     # sgts = Tag.objects.order_by("-do_sync", "tag_number")
#     sgts = tags.order_by("-do_sync", "tag_number")
#     crumbs = '<li class="current">Status</li><li class="current">SGTs</li>'
#     return render(request, 'home/sgtstatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"sgt": sgts},
#                                                    "filters": log_filter, "filter_id": filter_id,
#                                                    "filter_name": filter_name})


def objstatus(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    otype = request.GET.get("type")
    gt = GenericType.objects.filter(name=otype).first()
    pk = request.GET.get("id")

    filter_id = None
    filter_name = "All"
    if request.method == 'POST':
        filter_id = request.POST.get("filter-id-id")
        action = request.POST.get("action")
        if action == "reset_error":
            Generic.objects.filter(id=pk).update(err_disabled=False)
        elif action == "clear_history":
            Generic.objects.filter(id=pk).update(update_history=None)
    else:
        filter_id = request.GET.get("filter-id-id")

    if not filter_id:
        filter_id = request.COOKIES.get("filter-id")

    if filter_id:
        if filter_id == "0":
            objs = Generic.objects.filter(generictype=gt)
        else:
            objs = Generic.objects.filter(generictype=gt).filter(elementsync=filter_id)
    else:
        objs = Generic.objects.filter(generictype=gt)

    log_filter = [{"id": 0, "description": "All"}]
    syncs = ElementSync.objects.all()
    for d in syncs:
        this_id = str(d.id)
        if filter_id == this_id:
            filter_name = d.description
        log_filter.append({"id": this_id, "description": "Sync: " + d.description})

    if pk:
        objs = Generic.objects.filter(id=pk)
        if len(objs) == 1:
            obj = objs[0]
            desc = str(obj)
            crumbs = '''
                <li class="current">Status</li>
                <li><a href="/home/status-obj?type=''' + otype + '''">''' + otype + '''</a></li>
                <li class="current">''' + desc + '''</li>
            '''
            response = render(request, 'home/objstatus.html', {"crumbs": crumbs, "menuopen": 1, "id": pk, "data": obj})
            response.set_cookie("filter-id", filter_id)
            return response

    # objs = objs.order_by("-do_sync")
    # print(objs)
    crumbs = '<li class="current">Status</li><li class="current">' + otype + '</li>'
    response = render(request, 'home/objstatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"obj": objs},
                                                       "filters": log_filter, "filter_id": filter_id,
                                                       "filter_name": filter_name, "obj_type": gt,
                                                       "baseurl": "/home/status-obj?type=" + otype})
    response.set_cookie("filter-id", filter_id)
    return response


# def sgtsave(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     add = (";" + request.POST.get("addlist", ""))[:-1]
#     sub = (";" + request.POST.get("sublist", ""))[:-1]
#     addlist = add.split(";;check-")[1:]
#     sublist = sub.split(";;check-")[1:]
#     sgts = Tag.objects.filter(id__in=addlist)
#     for s in sgts:
#         s.do_sync = True
#         s.save()
#
#     sgts = Tag.objects.filter(id__in=sublist)
#     for s in sgts:
#         s.do_sync = False
#         s.save()
#
#     ss = SyncSession.objects.all()
#     if len(ss) > 0:
#         ss[0].force_rebuild = True
#         ss[0].save()
#
#     return redirect("/home/status-sgt")


def objsave(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    otype = request.GET.get("type")

    add = (";" + request.POST.get("addlist", ""))[:-1]
    sub = (";" + request.POST.get("sublist", ""))[:-1]
    addlist = add.split(";;check-")[1:]
    sublist = sub.split(";;check-")[1:]
    objs = Generic.objects.filter(id__in=addlist)
    for s in objs:
        s.do_sync = True
        s.save()

    objs = Generic.objects.filter(id__in=sublist)
    for s in objs:
        s.do_sync = False
        s.save()

    ss = ElementSync.objects.all()
    if len(ss) > 0:
        ss[0].force_rebuild = True
        ss[0].save()

    return redirect("/home/status-obj?type=" + otype)


# def sgaclstatus(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     filter_name = "All"
#     if request.method == 'POST':
#         filter_id = request.POST.get("filter-id-id")
#     else:
#         filter_id = request.GET.get("filter-id-id")
#
#     if filter_id:
#         if filter_id == "0":
#             acls = ACL.objects.all()
#         else:
#             acls = ACL.objects.filter(syncsession=filter_id)
#     else:
#         acls = ACL.objects.all()
#
#     log_filter = [{"id": 0, "description": "All"}]
#     syncs = SyncSession.objects.all()
#     for d in syncs:
#         this_id = str(d.id)
#         if filter_id == this_id:
#             filter_name = d.description
#         log_filter.append({"id": this_id, "description": "Sync: " + d.description})
#
#     pk = request.GET.get("id")
#     if pk:
#         sgacls = ACL.objects.filter(id=pk)
#         if len(sgacls) == 1:
#             sgacl = sgacls[0]
#             desc = sgacl.name
#             crumbs = '''
#                 <li class="current">Status</li>
#                 <li><a href="/home/status-sgacl">ACLs</a></li>
#                 <li class="current">''' + desc + '''</li>
#             '''
#             return render(request, 'home/showsgacl.html', {"crumbs": crumbs, "menuopen": 1, "data": sgacl})
#
#     # sgacls = ACL.objects.filter(visible=True).order_by("-do_sync")
#     sgacls = acls.filter(visible=True).order_by("-do_sync")
#     crumbs = '<li class="current">Status</li><li class="current">ACLs</li>'
#     return render(request, 'home/sgaclstatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"sgacl": sgacls},
#                                                      "filters": log_filter, "filter_id": filter_id,
#                                                      "filter_name": filter_name})
#
#
# def policystatus(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     filter_name = "All"
#     if request.method == 'POST':
#         filter_id = request.POST.get("filter-id-id")
#     else:
#         filter_id = request.GET.get("filter-id-id")
#
#     if filter_id:
#         if filter_id == "0":
#             pols = Policy.objects.all()
#         else:
#             pols = Policy.objects.filter(syncsession=filter_id)
#     else:
#         pols = Policy.objects.all()
#
#     log_filter = [{"id": 0, "description": "All"}]
#     syncs = SyncSession.objects.all()
#     for d in syncs:
#         this_id = str(d.id)
#         if filter_id == this_id:
#             filter_name = d.description
#         log_filter.append({"id": this_id, "description": "Sync: " + d.description})
#
#     pk = request.GET.get("id")
#     if pk:
#         policies = Policy.objects.filter(id=pk)
#         if len(policies) == 1:
#             policy = policies[0]
#             desc = policy.name + " (" + str(policy.mapping) + ")"
#             crumbs = '''
#                 <li class="current">Status</li>
#                 <li><a href="/home/status-policy">Policies</a></li>
#                 <li class="current">''' + desc + '''</li>
#             '''
#             return render(request, 'home/showpolicy.html', {"crumbs": crumbs, "menuopen": 1, "data": policy})
#
#     policies = pols.order_by("-do_sync")
#     crumbs = '<li class="current">Status</li><li class="current">Policies</li>'
#     return render(request, 'home/policystatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"policy": policies},
#                                                       "filters": log_filter, "filter_id": filter_id,
#                                                       "filter_name": filter_name})
#
#
# def sgtdata(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     pk = request.GET.get("id")
#     if pk:
#         sgts = TagData.objects.filter(id=pk)
#         if len(sgts) == 1:
#             sgt = sgts[0]
#             desc = sgt.tag.name + " (" + str(sgt.tag.tag_number) + ")"
#             ddesc = str(sgt.iseserver) if sgt.iseserver else \
#                 str(sgt.organization)
#             crumbs = '''
#                 <li class="current">Status</li>
#                 <li><a href="/home/status-sgt">SGTs</a></li>
#                 <li><a href="/home/status-sgt?id=''' + str(sgt.tag.id) + '''">''' + desc + '''</a></li>
#                 <li class="current">''' + ddesc + '''</li>
#             '''
#             return render(request, 'home/showsgtdata.html', {"crumbs": crumbs, "menuopen": 1, "data": sgt})
#
#     return redirect(reverse('sgtstatus'))
#
#
# def sgacldata(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     pk = request.GET.get("id")
#     if pk:
#         sgacls = ACLData.objects.filter(id=pk)
#         if len(sgacls) == 1:
#             sgacl = sgacls[0]
#             desc = sgacl.acl.name
#             ddesc = str(sgacl.iseserver) if sgacl.iseserver else \
#                 str(sgacl.organization)
#             crumbs = '''
#                 <li class="current">Status</li>
#                 <li><a href="/home/status-sgacl">ACLs</a></li>
#                 <li><a href="/home/status-sgacl?id=''' + str(sgacl.acl.id) + '''">''' + desc + '''</a></li>
#                 <li class="current">''' + ddesc + '''</li>
#             '''
#             return render(request, 'home/showsgacldata.html', {"crumbs": crumbs, "menuopen": 1, "data": sgacl})
#
#     return redirect(reverse('sgaclstatus'))
#
#
# def policydata(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     pk = request.GET.get("id")
#     if pk:
#         policies = PolicyData.objects.filter(id=pk)
#         if len(policies) == 1:
#             policy = policies[0]
#             desc = policy.policy.name + " (" + str(policy.policy.mapping) + ")"
#             ddesc = str(policy.iseserver) if policy.iseserver else \
#                 str(policy.organization)
#             crumbs = '''
#                 <li class="current">Status</li>
#                 <li><a href="/home/status-policy">Policies</a></li>
#                 <li><a href="/home/status-policy?id=''' + str(policy.policy.id) + '''">''' + desc + '''</a></li>
#                 <li class="current">''' + ddesc + '''</li>
#             '''
#             return render(request, 'home/showpolicydata.html', {"crumbs": crumbs, "menuopen": 1, "data": policy})
#
#     return redirect(reverse('policystatus'))


def certconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    uploadzip = UploadZip.objects.all()
    upload = Upload.objects.all()

    for u in uploadzip:
        print(u.upload_set.all())

    crumbs = '<li class="current">Configuration</li><li class="current">Certificates</li>'
    return render(request, 'home/certconfig.html', {"crumbs": crumbs, "menuopen": 2,
                                                    "data": {"zip": uploadzip, "file": upload}})


def certupload(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    form = UploadForm(request.POST or None, request.FILES or None)
    if request.method == 'POST':
        if form.is_valid():
            form.save()
            return redirect(reverse("certconfig"))
    else:
        act = request.GET.get("action")
        cert_id = request.GET.get("id")
        if act == "delzip" and cert_id:
            UploadZip.objects.filter(id=cert_id).delete()
            return redirect(reverse("certconfig"))

    crumbs = '''
        <li class="current">Configuration</li>
        <li><a href="/home/config-cert">Certificates</a></li>
        <li class="current">Upload</li>
    '''

    return render(request, 'home/cert_upload.html', {"crumbs": crumbs, "form": form, "menuopen": 2})


def backuprestore(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    msg = None
    if request.method == 'POST':
        act = request.POST.get("action")
        a_list = act.split("_")
        action = a_list[0].upper()
        if action == "BACKUP":
            backup()
            msg = "Database Backup Created"
        elif action == "RESTORE":
            restore(a_list[1])
            msg = "Database Restored Successfully"
        elif action == "DELETE":
            os.remove(a_list[1])
            msg = "Database Backup Deleted"
        elif action == "RESET_ALL":
            # ISEServer.objects.all().delete()
            # Dashboard.objects.all().delete()
            # Organization.objects.all().delete()
            # SyncSession.objects.all().delete()
            # Task.objects.all().delete()
            # UploadZip.objects.all().delete()
            # Tag.objects.all().delete()
            # ACL.objects.all().delete()
            # Policy.objects.all().delete()
            # TagData.objects.all().delete()
            # ACLData.objects.all().delete()
            # PolicyData.objects.all().delete()
            ISEServer.objects.all().delete()
            Dashboard.objects.all().delete()
            Organization.objects.all().delete()
            Element.objects.all().delete()
            ElementSync.objects.all().delete()
            Task.objects.all().delete()
            UploadZip.objects.all().delete()
            Upload.objects.all().delete()
            Generic.objects.all().delete()
            GenericData.objects.all().delete()
            msg = "Database Cleared"
        elif action == "RESET_OBJ":
            # Task.objects.all().delete()
            # Tag.objects.all().delete()
            # ACL.objects.all().delete()
            # Policy.objects.all().delete()
            # TagData.objects.all().delete()
            # ACLData.objects.all().delete()
            # PolicyData.objects.all().delete()
            # SyncSession.objects.all().update(sync_enabled=False)
            Task.objects.all().delete()
            ElementSync.objects.all().update(enabled=False)
            Generic.objects.all().delete()
            GenericData.objects.all().delete()
            msg = "Synced Objects Cleared"

    mypath = os.path.join(".", "config")
    # f = []
    # for (dirpath, dirnames, filenames) in os.walk(mypath):
    #     f.extend(filenames)
    #     break
    f = sorted(Path(mypath).iterdir(), key=os.path.getmtime)

    crumbs = '<li class="current">Configuration</li><li class="current">Backup/Restore</li>'
    return render(request, 'home/backuprestore.html', {"crumbs": crumbs, "menuopen": 2,
                                                       "data": f, "msg": msg})


def iseconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    if request.method == 'POST':
        postvars = request.POST
        idlist = []
        for v in postvars:
            if "intDesc-" in v:
                vid = v.replace("intDesc-", "")
                idlist.append(vid)

        for itemid in idlist:
            ise_desc = request.POST.get("intDesc-" + itemid)
            ise_host = request.POST.get("intIP-" + itemid)
            ise_user = request.POST.get("intUser-" + itemid)
            ise_pswd = request.POST.get("intPass-" + itemid)
            if ise_pswd.find("****") < 0:
                ise_pass = ise_pswd
            else:
                ise_pass = None
            ise_enab = True if request.POST.get("intEnabled-" + itemid) else False
            ise_pxen = True if request.POST.get("intPxGrid-" + itemid) else False
            ise_pxip = request.POST.get("intPxIP-" + itemid)
            ise_pxcn = request.POST.get("intPxClName-" + itemid)
            ise_pxcc = request.POST.get("clientcert-id-" + itemid)
            ise_pxck = request.POST.get("clientkey-id-" + itemid)
            ise_pxcp = request.POST.get("intPxClPass-" + itemid)
            ise_pxsc = request.POST.get("servercert-id-" + itemid)
            ise_rbld = True if request.POST.get("intRebuild-" + itemid) else False
            crt_pxcc = Upload.objects.filter(id=ise_pxcc) if ise_pxcc else None
            crt_pxck = Upload.objects.filter(id=ise_pxck) if ise_pxck else None
            crt_pxsc = Upload.objects.filter(id=ise_pxsc) if ise_pxsc else None
            if (crt_pxcc and len(crt_pxcc) == 1) and (crt_pxck and len(crt_pxck) == 1) and \
                    (crt_pxsc and len(crt_pxsc) == 1):
                crt_pxcc = crt_pxcc[0]
                crt_pxck = crt_pxck[0]
                crt_pxsc = crt_pxsc[0]

            if itemid == "new" or itemid == "":
                ISEServer.objects.create(description=ise_desc, ipaddress=ise_host, username=ise_user, password=ise_pass,
                                         pxgrid_enable=ise_pxen, pxgrid_ip=ise_pxip, pxgrid_cliname=ise_pxcn,
                                         pxgrid_clicert=crt_pxcc, pxgrid_clikey=crt_pxck, pxgrid_clipw=ise_pxcp,
                                         pxgrid_isecert=crt_pxsc, force_rebuild=True, enabled=ise_enab)
            else:
                if ise_pass:
                    ISEServer.objects.filter(id=itemid).update(description=ise_desc, ipaddress=ise_host,
                                                               username=ise_user, password=ise_pass,
                                                               pxgrid_enable=ise_pxen, pxgrid_ip=ise_pxip,
                                                               pxgrid_cliname=ise_pxcn, pxgrid_clicert=crt_pxcc,
                                                               pxgrid_clikey=crt_pxck, pxgrid_clipw=ise_pxcp,
                                                               pxgrid_isecert=crt_pxsc, force_rebuild=ise_rbld,
                                                               enabled=ise_enab)
                else:
                    ISEServer.objects.filter(id=itemid).update(description=ise_desc, ipaddress=ise_host,
                                                               username=ise_user,
                                                               pxgrid_enable=ise_pxen, pxgrid_ip=ise_pxip,
                                                               pxgrid_cliname=ise_pxcn, pxgrid_clicert=crt_pxcc,
                                                               pxgrid_clikey=crt_pxck, pxgrid_clipw=ise_pxcp,
                                                               pxgrid_isecert=crt_pxsc, force_rebuild=ise_rbld,
                                                               enabled=ise_enab)

    thisact = request.GET.get("action")
    thisid = request.GET.get("id")
    if thisid and thisact and thisact.upper() == "DEL":
        ISEServer.objects.filter(id=thisid).delete()
        thisid = None

    iseservers = ISEServer.objects.all().order_by("description")
    # if len(iseservers) == 0:
    #     iseservers = [{"id": "new"}]
    certs = Upload.objects.all().order_by("description", "file")

    if thisid and (not thisact or (thisact and thisact.upper() != "DEL")):
        if thisid == "new":
            thisserver = {"id": "new"}
            serverdesc = "(New)"
        else:
            thisserver = iseservers.filter(id=thisid).first()
            serverdesc = thisserver.description

        crumbs = '''
            <li class="current">Configuration</li>
            <li><a href="/home/config-ise">ISE Servers</a></li>
            <li class="current">''' + serverdesc + '''</li>
        '''
    else:
        thisserver = None
        crumbs = '<li class="current">Configuration</li><li class="current">ISE Servers</li>'
    return render(request, 'home/iseconfig.html', {"crumbs": crumbs, "menuopen": 2, "i": thisserver,
                                                   "certs": certs, "server_id": thisid, "servers": iseservers})


def merakiconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    thisid = request.GET.get("id")
    if request.method == 'POST':
        if request.GET.get("action") == "addorg":
            postvars = request.POST
            idlist = []
            for v in postvars:
                if "org-id-" in v:
                    vid = v.replace("org-id-", "")
                    idlist.append(vid)

            for itemid in idlist:
                db = Dashboard.objects.filter(id=itemid)
                thisid = str(db.first().id)
                orgid = request.POST.get("org-id-" + itemid)

                if len(db) == 1 and orgid:
                    if orgid not in db[0].organization.all():
                        neworg = Organization.objects.create(orgid=orgid)
                        db[0].organization.add(neworg)
        else:
            postvars = request.POST
            idlist = []
            for v in postvars:
                if "intDesc-" in v:
                    vid = v.replace("intDesc-", "")
                    idlist.append(vid)

            for itemid in idlist:
                dash_desc = request.POST.get("intDesc-" + itemid)
                dash_aurl = request.POST.get("intURL-" + itemid)
                dash_akey = request.POST.get("intKey-" + itemid)
                if dash_akey.find("****") < 0:
                    dash_apik = dash_akey
                else:
                    dash_apik = None

                if itemid == "new":
                    Dashboard.objects.create(description=dash_desc, baseurl=dash_aurl, apikey=dash_apik)
                else:
                    if dash_apik:
                        Dashboard.objects.filter(id=itemid).update(description=dash_desc, baseurl=dash_aurl,
                                                                   apikey=dash_apik)
                    else:
                        Dashboard.objects.filter(id=itemid).update(description=dash_desc, baseurl=dash_aurl)

    thisact = request.GET.get("action")
    if thisact and thisact.upper() == "DELORG" and thisid:
        org = Organization.objects.filter(id=thisid)
        thisid = str(org.first().dashboard_set.first().id)
        org.delete()
    if thisact and thisact.upper() == "DEL" and thisid:
        db = Dashboard.objects.filter(id=thisid).first()
        orgs = db.organization.all()
        for o in orgs:
            o.delete()
        db.delete()
        thisid = None

    dashboards = Dashboard.objects.all()
    # for dashboard in dashboards:
    if thisid:
        dashboard = dashboards.filter(id=thisid).first()
        if dashboard.baseurl and dashboard.apikey and dashboard.apikey != "":
            try:
                db = meraki.DashboardAPI(base_url=dashboard.baseurl, api_key=dashboard.apikey, print_console=False,
                                         output_log=False, caller=settings.CUSTOM_UA, suppress_logging=True)
                orgs = db.organizations.getOrganizations()
                dashboard.raw_data = orgs
                dashboard.save()
            except APIError:
                dashboard.apikey = ""
                dashboard.save()
    # if len(dashboards) == 0:
    #     dashboards = [{"id": "new"}]

    if thisid and (not thisact or (thisact and thisact.upper() != "DEL")):
        if thisid == "new":
            thisdashboard = {"id": "new"}
            dashboarddesc = "(New)"
        else:
            thisdashboard = dashboards.filter(id=thisid).first()
            dashboarddesc = thisdashboard.description

        crumbs = '''
            <li class="current">Configuration</li>
            <li><a href="/home/config-meraki">Meraki Accounts</a></li>
            <li class="current">''' + dashboarddesc + '''</li>
        '''
    else:
        thisdashboard = None
        crumbs = '<li class="current">Configuration</li><li class="current">Meraki Dashboard</li>'

    return render(request, 'home/merakiconfig.html', {"crumbs": crumbs, "menuopen": 2, "i": thisdashboard,
                                                      "dashboard_id": thisid, "dashboards": dashboards})


# def syncconfig(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     if request.method == 'POST':
#         postvars = request.POST
#         print(postvars)
#         idlist = []
#         dst = {"ise": [], "org": []}
#         for v in postvars:
#             if "intDesc-" in v:
#                 vid = v.replace("intDesc-", "")
#                 idlist.append(vid)
#             if "dstIse-" in v:
#                 did = v.replace("dstIse-", "")
#                 dst["ise"].append(uuid.UUID(did))
#             if "dstOrg-" in v:
#                 did = v.replace("dstOrg-", "")
#                 dst["org"].append(uuid.UUID(did))
#
#         for itemid in idlist:
#             sync_desc = request.POST.get("intDesc-" + itemid)
#             # source
#             sync_isvr = request.POST.get("iseserver-id-" + itemid)
#             sync_dash = request.POST.get("dashboard-id-" + itemid)
#             opt_rbld = request.POST.get("intRebuild-" + itemid)
#             sync_rbld = True if opt_rbld else False
#             opt_sync = request.POST.get("intSync-" + itemid)
#             sync_sync = True if opt_sync else False
#             opt_aply = request.POST.get("intApply-" + itemid)
#             sync_aply = True if opt_aply else False
#             opt_rev = request.POST.get("intReverse-" + itemid)
#             sync_rev = True if opt_rev else False
#             sync_itvl = request.POST.get("intInterval-" + itemid)
#             if itemid == "new":
#                 if sync_isvr:
#                     ss = SyncSession.objects.create(description=sync_desc, src_iseserver_id=sync_isvr,
#                                                     force_rebuild=sync_rbld, enabled=sync_sync,
#                                                     apply_changes=sync_aply, sync_interval=sync_itvl,
#                                                     reverse_sync=sync_rev)
#                 else:
#                     ss = SyncSession.objects.create(description=sync_desc, src_organization_id=sync_dash,
#                                                     force_rebuild=sync_rbld, enabled=sync_sync,
#                                                     apply_changes=sync_aply, sync_interval=sync_itvl,
#                                                     reverse_sync=sync_rev)
#             else:
#                 if sync_isvr:
#                     sy_s = SyncSession.objects.filter(id=itemid)
#                     sy_s.update(description=sync_desc, src_iseserver_id=sync_isvr, force_rebuild=sync_rbld,
#                                 enabled=sync_sync, apply_changes=sync_aply, sync_interval=sync_itvl,
#                                 reverse_sync=sync_rev)
#
#                 else:
#                     sy_s = SyncSession.objects.filter(id=itemid)
#                     sy_s.update(description=sync_desc, src_organization_id=sync_dash, force_rebuild=sync_rbld,
#                                 enabled=sync_sync, apply_changes=sync_aply, sync_interval=sync_itvl,
#                                 reverse_sync=sync_rev)
#                 ss = sy_s.first()
#
#             if len(dst["ise"]) > 0:
#                 ss.dst_iseserver.clear()
#                 ss.dst_iseserver.add(*dst["ise"])
#             if len(dst["org"]) > 0:
#                 ss.dst_organization.clear()
#                 ss.dst_organization.add(*dst["org"])
#             ss.save()
#
#     thisid = request.GET.get("id")
#     thisact = request.GET.get("action")
#     if thisact and thisact.upper() == "DEL" and thisid:
#         SyncSession.objects.filter(id=thisid).delete()
#         thisid = None
#
#     syncs = SyncSession.objects.all()
#     if len(syncs) == 0:
#         syncs = [{"id": "new"}]
#     iseservers = ISEServer.objects.all()
#     # dashboards = Dashboard.objects.all()
#     orgs = Organization.objects.all()
#
#     if thisid and (not thisact or (thisact and thisact.upper() != "DEL")):
#         if thisid == "new":
#             thissync = {"id": "new"}
#             syncdesc = "(New)"
#         else:
#             thissync = syncs.filter(id=thisid).first()
#             syncdesc = thissync.description
#
#         crumbs = '''
#             <li class="current">Configuration</li>
#             <li><a href="/home/config-sync">Synchronization</a></li>
#             <li class="current">''' + syncdesc + '''</li>
#         '''
#     else:
#         thissync = None
#         crumbs = '<li class="current">Configuration</li><li class="current">Synchronization</li>'
#
#     return render(request, 'home/syncconfig.html', {"crumbs": crumbs, "menuopen": 2, "data": syncs,
#                                                     "iseservers": iseservers, "organizations": orgs,
#                                                     "i": thissync, "sync_id": thisid})


def elmsyncconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    if request.method == 'POST':
        postvars = request.POST
        idlist = []
        dst = {"elm": []}
        for v in postvars:
            if "intDesc-" in v:
                vid = v.replace("intDesc-", "")
                idlist.append(vid)
            if "dstElm-" in v:
                did = v.replace("dstElm-", "")
                dst["elm"].append(uuid.UUID(did))

        for itemid in idlist:
            sync_desc = request.POST.get("intDesc-" + itemid)
            # source
            sync_element = request.POST.get("element-id-" + itemid)
            opt_rbld = request.POST.get("intRebuild-" + itemid)
            sync_rbld = True if opt_rbld else False
            opt_sync = request.POST.get("intSync-" + itemid)
            sync_sync = True if opt_sync else False
            opt_aply = request.POST.get("intApply-" + itemid)
            sync_aply = True if opt_aply else False
            opt_rev = request.POST.get("intReverse-" + itemid)
            sync_rev = True if opt_rev else False
            sync_itvl = request.POST.get("intInterval-" + itemid)
            if itemid == "new":
                ss = ElementSync.objects.create(description=sync_desc, src_element_id=sync_element,
                                                force_rebuild=sync_rbld, enabled=sync_sync,
                                                apply_changes=sync_aply, sync_interval=sync_itvl,
                                                reverse_sync=sync_rev)
            else:
                sy_s = ElementSync.objects.filter(id=itemid)
                sy_s.update(description=sync_desc, src_element_id=sync_element, force_rebuild=sync_rbld,
                            enabled=sync_sync, apply_changes=sync_aply, sync_interval=sync_itvl,
                            reverse_sync=sync_rev)
                ss = sy_s.first()

            if len(dst["elm"]) > 0:
                ss.dst_element.clear()
                ss.dst_element.add(*dst["elm"])
            ss.save()

    thisid = request.GET.get("id")
    thisact = request.GET.get("action")
    if thisact and thisact.upper() == "DEL" and thisid:
        ElementSync.objects.filter(id=thisid).delete()
        thisid = None

    syncs = ElementSync.objects.all()
    # if len(syncs) == 0:
    #     syncs = [{"id": "new"}]
    elements = Element.objects.all().order_by('elementtype', 'iseserver__description',
                                              'organization__dashboard__description')

    if thisid and (not thisact or (thisact and thisact.upper() != "DEL")):
        if thisid == "new":
            thissync = {"id": "new"}
            syncdesc = "(New)"
        else:
            thissync = syncs.filter(id=thisid).first()
            syncdesc = thissync.description

        crumbs = '''
            <li class="current">Configuration</li>
            <li><a href="/home/config-elm-sync">Synchronization</a></li>
            <li class="current">''' + syncdesc + '''</li>
        '''
    else:
        thissync = None
        crumbs = '<li class="current">Configuration</li><li class="current">Synchronization</li>'

    return render(request, 'home/elmsyncconfig.html', {"crumbs": crumbs, "menuopen": 2, "data": syncs,
                                                       "elements": elements, "i": thissync, "sync_id": thisid})


class MyLoginView(auth_views.LoginView):
    template_name = "general/login.html"

    def get_context_data(self, **kwargs):
        context = super(MyLoginView, self).get_context_data(**kwargs)
        return context

    def get_success_url(self):
        return reverse('landing')


class MyLogoutView(auth_views.LogoutView):
    def dispatch(self, request, *args, **kwargs):
        logout(request)
        return redirect('/')


def trbl_data(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    # changing this from .filter to .exclude will switch to generic element mapping
    dps = DataPipeline.objects.exclude(element=None)
    d_arr = {}
    default_dict = {"s1": None, "s2": None, "s3": None, "s4": None, "obj_id": None}
    for d in dps:
        elem_str = None
        if d.iseserver:
            elem_str = str(d.iseserver)
            if str(d.iseserver) not in d_arr:
                d_arr[elem_str] = {**default_dict}
        elif d.organization:
            elem_str = str(d.organization)
            if str(d.organization) not in d_arr:
                d_arr[elem_str] = {**default_dict}
        elif d.element:
            elem_str = str(d.element)
            if str(d.element) not in d_arr:
                d_arr[elem_str] = {**default_dict}

        if elem_str:
            d_arr[elem_str]["s" + str(d.stage)] = d
            if d.iseserver:
                d_arr[elem_str]["obj_id"] = "ise~" + str(d.iseserver.id)
            elif d.organization:
                d_arr[elem_str]["obj_id"] = "org~" + str(d.organization.id)
            elif d.element:
                d_arr[elem_str]["obj_id"] = "elm~" + str(d.element.id)

    d_list = []
    for element in d_arr:
        d_list.append({"element": element, "obj_id": d_arr[element]["obj_id"], "stages": d_arr[element]})

    # Manually Add elements that haven't been touched by the pipeline yet
    elements = {"ise": [], "org": [], "elm": []}
    for d in DataPipeline.objects.all():
        if d.iseserver:
            elements["ise"].append(d.iseserver.id)
        elif d.organization:
            elements["org"].append(d.organization.id)
        elif d.element:
            elements["elm"].append(d.element.id)

    # non_i = ISEServer.objects.exclude(id__in=elements["ise"])
    # non_o = Organization.objects.exclude(id__in=elements["org"])
    non_e = Element.objects.exclude(id__in=elements["elm"])

    # for i in non_i:
    #     d_list.append({"element": str(i), "obj_id": "ise~" + str(i.id), "stages": default_dict})
    # for i in non_o:
    #     d_list.append({"element": str(i), "obj_id": "org~" + str(i.id), "stages": default_dict})
    for i in non_e:
        d_list.append({"element": str(i), "obj_id": "elm~" + str(i.id), "stages": default_dict})

    crumbs = '<li class="current">Troubleshooting</li><li class="current">Data Pipeline</li>'
    return render(request, 'home/pipeline.html', {"crumbs": crumbs, "menuopen": 3, "data": d_list})


def trbl_logs(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    crumbs = '<li class="current">Troubleshooting</li><li class="current">Logs</li>'

    filter_name = "All"
    if request.method == 'POST':
        filter_id = request.POST.get("filter-id-id")
    else:
        filter_id = request.GET.get("filter-id-id")

    if filter_id:
        if filter_id == "0":
            tasks = Task.objects.all()
        else:
            filter_list = filter_id.split("~")
            if filter_list[0] == "ise":
                tasks = Task.objects.filter(iseserver=filter_list[1])
            elif filter_list[0] == "org":
                tasks = Task.objects.filter(organization=filter_list[1])
            elif filter_list[0] == "elm":
                tasks = Task.objects.filter(element=filter_list[1])
            elif filter_list[0] == "els":
                tasks = Task.objects.filter(elementsync=filter_list[1])
            else:
                tasks = Task.objects.filter(syncsession=filter_list[1])
    else:
        tasks = Task.objects.all()

    if not request.method == "POST":
        log_id = request.GET.get("id")
        action = request.GET.get("action")
        if action and action.upper() == "DEL":
            Task.objects.filter(id=log_id).delete()
    log_filter = [{"id": 0, "description": "All"}]
    # iseservers = ISEServer.objects.all()
    # for d in iseservers:
    #     this_id = "ise~" + str(d.id)
    #     if filter_id == this_id:
    #         filter_name = d.description
    #     log_filter.append({"id": this_id, "description": "ISE: " + d.description})
    # organizations = Organization.objects.all()
    # for d in organizations:
    #     this_id = "org~" + str(d.id)
    #     if filter_id == this_id:
    #         filter_name = d.dashboard_set.first().description
    #     log_filter.append({"id": this_id, "description": "Meraki: " + d.dashboard_set.first().description})
    # syncs = SyncSession.objects.all()
    # for d in syncs:
    #     this_id = "sss~" + str(d.id)
    #     if filter_id == this_id:
    #         filter_name = d.description
    #     log_filter.append({"id": this_id, "description": "Sync: " + d.description})

    # This adds Elements to the filter list. Remove everything else to switch to Generic Element
    elements = Element.objects.all()
    for d in elements:
        this_id = "elm~" + str(d.id)
        if filter_id == this_id:
            filter_name = "Element " + str(d)
        log_filter.append({"id": this_id, "description": "Element : " + str(d)})
    syncs = ElementSync.objects.all()
    for d in syncs:
        this_id = "els~" + str(d.id)
        if filter_id == this_id:
            filter_name = d.description
        log_filter.append({"id": this_id, "description": "Sync: " + d.description})

    return render(request, 'home/logs.html', {"crumbs": crumbs, "menuopen": 3, "data": tasks,
                                              "filters": log_filter, "filter_id": filter_id,
                                              "filter_name": filter_name})


def trbl_load(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    crumbs = '<li class="current">Troubleshooting</li><li class="current">Manual Dataset</li>'

    if request.method == 'POST':
        data = request.POST.get("config-data")
        new_data = json.loads(data.replace("\r\n", "").replace("\r", "").replace("\n", ""))
        if "sgts" in new_data and "sgacls" in new_data and "sgpolicies" in new_data:
            # this is an ISE dataset
            ISEServer.objects.create(description="ise_" + string_generator(8), ipaddress="127.0.0.1",
                                     raw_data=new_data, manual_dataset=True, enabled=False)
        else:
            this_oid = string_num_generator(20)
            org = Organization.objects.create(orgid=this_oid, manual_dataset=True,
                                              raw_data=new_data)
            o_data = [{"id": this_oid, "name": "Imported Org Data", "url": "https://dashboard.meraki.com/"}]
            db = Dashboard.objects.create(description="dash_" + string_generator(8), apikey="",
                                          enabled=False, raw_data=o_data)
            db.organization.add(org)
            db.save()
    else:
        dataset_id = request.GET.get("id")
        action = request.GET.get("action")
        if action and action.upper() == "DEL":
            dataset_list = dataset_id.split("~")
            if dataset_list[0] == "ise":
                ISEServer.objects.filter(id=dataset_list[1]).delete()
            else:
                org = Organization.objects.filter(id=dataset_list[1]).first()
                db = org.dashboard_set.first()
                db.delete()
                org.delete()

    i = ISEServer.objects.filter(manual_dataset=True)
    o = Organization.objects.filter(manual_dataset=True)
    datasets = {"ise": i, "org": o}

    return render(request, 'home/dataset.html', {"crumbs": crumbs, "menuopen": 3, "data": datasets})


def trbl_tech(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    msg = None

    if request.method == 'POST':
        action = request.POST.get("action").upper()
        if action == "RESET_ALL":
            ISEServer.objects.all().delete()
            Dashboard.objects.all().delete()
            Organization.objects.all().delete()
            Element.objects.all().delete()
            ElementSync.objects.all().delete()
            Task.objects.all().delete()
            UploadZip.objects.all().delete()
            Upload.objects.all().delete()
            Generic.objects.all().delete()
            GenericData.objects.all().delete()
            msg = "Database Cleared"
        elif action == "RESET_OBJ":
            Task.objects.all().delete()
            ElementSync.objects.all().update(enabled=False)
            Generic.objects.all().delete()
            GenericData.objects.all().delete()
            msg = "Synced Objects Cleared"
    else:
        tech_act = request.GET.get("action")
        if tech_act == "file":
            filecontent = tech_backup()
            response = HttpResponse(filecontent, content_type="application/zip")
            response['Content-Disposition'] = 'inline; filename=tech_support.zip'
            return response

    crumbs = '<li class="current">Troubleshooting</li><li class="current">Technical Support</li>'
    return render(request, 'home/support.html', {"crumbs": crumbs, "menuopen": 3, "msg": msg})


def trbl_admin(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    return redirect('/admin')


# def update_objects(data, tag_dict, acl_dict, pol_dict):
#     if type(data) == ISEServer:
#         for obj in TagData.objects.filter(iseserver=data):
#             d = obj.get_data("value")
#             if d not in tag_dict:
#                 tag_dict[d] = []
#             tag_dict[d].append(obj)
#         for obj in ACLData.objects.filter(iseserver=data):
#             d = obj.get_data("cleaned_name")
#             if d not in acl_dict:
#                 acl_dict[d] = []
#             acl_dict[d].append(obj)
#         for obj in PolicyData.objects.filter(iseserver=data):
#             d = obj.get_data("mapping")
#             if d not in pol_dict:
#                 pol_dict[d] = []
#             pol_dict[d].append(obj)
#     elif type(data) == Organization:
#         for obj in TagData.objects.filter(organization=data):
#             d = obj.get_data("value")
#             if d not in tag_dict:
#                 tag_dict[d] = []
#             tag_dict[d].append(obj)
#         for obj in ACLData.objects.filter(organization=data):
#             d = obj.get_data("cleaned_name")
#             if d not in acl_dict:
#                 acl_dict[d] = []
#             acl_dict[d].append(obj)
#         for obj in PolicyData.objects.filter(organization=data):
#             d = obj.get_data("mapping")
#             if d not in pol_dict:
#                 pol_dict[d] = []
#             pol_dict[d].append(obj)


# def syncstatus(request):
#     if not request.user.is_authenticated:
#         return redirect('/login')
#
#     sync_id = request.GET.get("id")
#     if not sync_id:
#         return redirect("/home")
#
#     sync = SyncSession.objects.filter(id=sync_id).first()
#     managers = {"src": {}, "dst": [], "all": [], "sync": sync}
#     tag_dict = {}
#     acl_dict = {}
#     pol_dict = {}
#     if sync.src_iseserver:
#         src = sync.src_iseserver
#         update_objects(src, tag_dict, acl_dict, pol_dict)
#         managers["src"] = src
#         managers["all"].append(src)
#         # managers["dst"].append(sync.src_iseserver)
#         # managers["all"].append(sync.src_iseserver)
#     else:
#         src = sync.src_organization
#         update_objects(src, tag_dict, acl_dict, pol_dict)
#         managers["src"] = src
#         managers["all"].append(src)
#         # managers["dst"].append(sync.src_organization)
#         # managers["all"].append(sync.src_iseserver)
#
#     for x in sync.dst_iseserver.all():
#         update_objects(x, tag_dict, acl_dict, pol_dict)
#         managers["dst"].append(x)
#         managers["all"].append(x)
#
#     for x in sync.dst_organization.all():
#         update_objects(x, tag_dict, acl_dict, pol_dict)
#         managers["dst"].append(x)
#         managers["all"].append(x)
#
#     # print(managers)
#     # crumbs = '<li class="current">Home</li><li class="current">Sync Status</li>'
#     crumbs = '''
#         <li class="current">Configuration</li>
#         <li><a href="/home/config-sync">Synchronization</a></li>
#         <li class="current">''' + sync.description + '''</li>
#     '''
#     return render(request, 'home/syncstatus.html', {"crumbs": crumbs, "menuopen": 2, "data":
#                                                     {"tags": dict(sorted(tag_dict.items())),
#                                                      "acls": dict(sorted(acl_dict.items())),
#                                                      "policies": dict(sorted(pol_dict.items())),
#                                                      "elements": managers}})


def update_elm_objects(data, obj_dict):
    for ty in GenericType.objects.all():
        tmp_dict = obj_dict.get(str(ty), {})
        for obj in GenericData.objects.filter(element=data).filter(generictype=ty):
            fld = obj.generictype.significant_name_key
            d = obj.get_data(fld, safe=True)
            # print(fld, d)
            if d not in tmp_dict:
                tmp_dict[d] = []
            tmp_dict[d].append(obj)

        obj_dict[str(ty)] = dict(sorted(tmp_dict.items()))


def elmsyncstatus(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    sync_id = request.GET.get("id")
    if not sync_id:
        return redirect("/home")

    sync = ElementSync.objects.filter(id=sync_id).first()
    managers = {"src": {}, "dst": [], "all": [], "sync": sync}
    obj_dict = {}
    if sync.src_element:
        src = sync.src_element
        update_elm_objects(src, obj_dict)
        managers["src"] = src
        managers["all"].append(src)

    for x in sync.dst_element.all():
        update_elm_objects(x, obj_dict)
        managers["dst"].append(x)
        managers["all"].append(x)

    # print(managers)
    # crumbs = '<li class="current">Home</li><li class="current">Sync Status</li>'
    crumbs = '''
        <li class="current">Configuration</li>
        <li><a href="/home/config-elm-sync">Synchronization</a></li>
        <li class="current">''' + sync.description + '''</li>
    '''
    # print(obj_dict)
    # print(managers)
    return render(request, 'home/elmsyncstatus.html', {"crumbs": crumbs, "menuopen": 2, "data":
                                                       {"objects": obj_dict,
                                                        "elements": managers}})


def objdata(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    objtype = request.GET.get("type")
    pk = request.GET.get("id")
    if pk:
        objs = GenericData.objects.filter(id=pk)
        gen = objs.first().generic
        if gen:
            gen_id = str(gen.id)
            gen_desc = str(gen)
        else:
            gen_id = None
            gen_desc = None
        if len(objs) == 1:
            obj = objs[0]
            desc = str(obj)
            if gen_id:
                crumbs = '''
                    <li class="current">Status</li>
                    <li><a href="/home/status-obj?type=''' + objtype + '''">''' + objtype + '''</a></li>
                    <li><a href="/home/status-obj?type=''' + objtype + '''&id=''' + gen_id + '''">''' + gen_desc + '''</a></li>
                    <li class="current">''' + desc + '''</li>
                '''
            else:
                crumbs = '''
                    <li class="current">Status</li>
                    <li><a href="/home/status-obj?type=''' + objtype + '''">''' + objtype + '''</a></li>
                    <li class="current">''' + desc + '''</li>
                '''

            return render(request, 'home/showobjdata.html', {"crumbs": crumbs, "menuopen": 1, "data": obj})

    return redirect("/home/status-obj?type=" + objtype + "&id=" + pk)
