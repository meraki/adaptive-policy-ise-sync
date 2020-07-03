from sync.models import ISEServer, Upload, UploadZip, Dashboard, Tag, ACL, Policy, SyncSession
from django.shortcuts import redirect, reverse, render
from django.contrib.auth import logout
from django.http import JsonResponse
from django.contrib.auth import views as auth_views
from .forms import UploadForm
import meraki


def startresync(request):
    ss = SyncSession.objects.all()
    if len(ss) > 0:
        ss[0].force_rebuild = True
        ss[0].save()

    return JsonResponse({}, safe=False)


def delobject(request):
    # /del/policy/64c6515b-e32f-476d-a043-20924f1ed560
    pathlist = request.path.split("/")
    if len(pathlist) == 4:
        if pathlist[2] == "sgt":
            Tag.objects.filter(id=pathlist[3]).delete()
        elif pathlist[2] == "sgacl":
            ACL.objects.filter(id=pathlist[3]).delete()
        elif pathlist[2] == "policy":
            Policy.objects.filter(id=pathlist[3]).delete()

    return JsonResponse({}, safe=False)


def getmerakiorgs(request):
    dashboards = Dashboard.objects.all()
    if len(dashboards) > 0:
        dashboard = dashboards[0]
    else:
        dashboard = None

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


def dolanding(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = SyncSession.objects.all()
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

    return render(request, 'setup/meraki.html', {"active": 5, "data": dashboard})


def setupsync(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = SyncSession.objects.all()
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
                dashboard.orgid = orgid
                dashboard.save()
            else:
                Dashboard.objects.create(description="Meraki Dashboard", apikey=apikey, orgid=orgid, baseurl=apiurl)

    return render(request, 'setup/sync.html', {"active": 6, "data": sync, "default_sync": defsync})


def setupdone(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = SyncSession.objects.all()
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

    if request.method == 'POST':
        source = request.POST.get("basicRadio")
        sync_int = request.POST.get("syncInterval")
        post_dosync = request.POST.get("do_sync")
        if post_dosync:
            dosync = True
        else:
            dosync = False

        if source.lower() == "ise":
            ise_source = True
        else:
            ise_source = False

        if sync_int:
            if sync and iseserver and dashboard:
                sync.ise_source = ise_source
                sync.sync_interval = sync_int
                sync.apply_changes = dosync
                sync.save()
            else:
                SyncSession.objects.create(description="TrustSec Sync", dashboard=dashboard, iseserver=iseserver,
                                           ise_source=ise_source, sync_interval=sync_int, sync_enabled=True,
                                           apply_changes=dosync)

    return redirect("/home")


def home(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = SyncSession.objects.all()
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

    meraki_sgts = Tag.objects.filter(sourced_from="meraki")
    meraki_sgacls = ACL.objects.filter(sourced_from="meraki")
    meraki_policies = Policy.objects.filter(sourced_from="meraki")
    ise_sgts = Tag.objects.filter(sourced_from="ise")
    ise_sgacls = ACL.objects.filter(sourced_from="ise")
    ise_policies = Policy.objects.filter(sourced_from="ise")

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


def sgtstatus(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    pk = request.GET.get("id")
    if pk:
        sgts = Tag.objects.filter(id=pk)
        if len(sgts) == 1:
            sgt = sgts[0]
            desc = sgt.name + " (" + str(sgt.tag_number) + ")"
            crumbs = '''
                <li class="current">Status</li>
                <li><a href="/home/status-sgt">SGTs</a></li>
                <li class="current">''' + desc + '''</li>
            '''
            return render(request, 'home/showsgt.html', {"crumbs": crumbs, "menuopen": 1, "data": sgt})

    sgts = Tag.objects.order_by("-do_sync", "tag_number")
    crumbs = '<li class="current">Status</li><li class="current">SGTs</li>'
    return render(request, 'home/sgtstatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"sgt": sgts}})


def sgtsave(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    add = (";" + request.POST.get("addlist", ""))[:-1]
    sub = (";" + request.POST.get("sublist", ""))[:-1]
    addlist = add.split(";;check-")[1:]
    sublist = sub.split(";;check-")[1:]
    sgts = Tag.objects.filter(id__in=addlist)
    for s in sgts:
        s.do_sync = True
        s.save()

    sgts = Tag.objects.filter(id__in=sublist)
    for s in sgts:
        s.do_sync = False
        s.save()

    ss = SyncSession.objects.all()
    if len(ss) > 0:
        ss[0].force_rebuild = True
        ss[0].save()

    return redirect("/home/status-sgt")


def sgaclstatus(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    pk = request.GET.get("id")
    if pk:
        sgacls = ACL.objects.filter(id=pk)
        if len(sgacls) == 1:
            sgacl = sgacls[0]
            desc = sgacl.name
            crumbs = '''
                <li class="current">Status</li>
                <li><a href="/home/status-sgacl">SGACLs</a></li>
                <li class="current">''' + desc + '''</li>
            '''
            return render(request, 'home/showsgacl.html', {"crumbs": crumbs, "menuopen": 1, "data": sgacl})

    sgacls = ACL.objects.filter(visible=True).order_by("-do_sync")
    crumbs = '<li class="current">Status</li><li class="current">SGACLs</li>'
    return render(request, 'home/sgaclstatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"sgacl": sgacls}})


def policystatus(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    pk = request.GET.get("id")
    if pk:
        policies = Policy.objects.filter(id=pk)
        if len(policies) == 1:
            policy = policies[0]
            desc = policy.name + " (" + str(policy.mapping) + ")"
            crumbs = '''
                <li class="current">Status</li>
                <li><a href="/home/status-policy">Policies</a></li>
                <li class="current">''' + desc + '''</li>
            '''
            return render(request, 'home/showpolicy.html', {"crumbs": crumbs, "menuopen": 1, "data": policy})

    policies = Policy.objects.order_by("-do_sync")
    crumbs = '<li class="current">Status</li><li class="current">Policies</li>'
    return render(request, 'home/policystatus.html', {"crumbs": crumbs, "menuopen": 1, "data": {"policy": policies}})


def certconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    uploadzip = UploadZip.objects.all()
    upload = Upload.objects.all()

    crumbs = '<li class="current">Configuration</li><li class="current">Certificates</li>'
    return render(request, 'home/certconfig.html', {"crumbs": crumbs, "menuopen": 2,
                                                    "data": {"zip": uploadzip, "file": upload}})


def iseconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    iseservers = ISEServer.objects.all()
    if len(iseservers) > 0:
        iseserver = iseservers[0]
    else:
        iseserver = None

    crumbs = '<li class="current">Configuration</li><li class="current">ISE Server</li>'
    return render(request, 'home/iseconfig.html', {"crumbs": crumbs, "menuopen": 2, "data": iseserver})


def merakiconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    dashboards = Dashboard.objects.all()
    if len(dashboards) > 0:
        dashboard = dashboards[0]
    else:
        dashboard = None

    crumbs = '<li class="current">Configuration</li><li class="current">Meraki Dashboard</li>'
    return render(request, 'home/merakiconfig.html', {"crumbs": crumbs, "menuopen": 2, "data": dashboard})


def syncconfig(request):
    if not request.user.is_authenticated:
        return redirect('/login')

    syncs = SyncSession.objects.all()
    if len(syncs) > 0:
        sync = syncs[0]
    else:
        sync = None

    crumbs = '<li class="current">Configuration</li><li class="current">Synchronization</li>'
    return render(request, 'home/syncconfig.html', {"crumbs": crumbs, "menuopen": 2, "data": sync})


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
