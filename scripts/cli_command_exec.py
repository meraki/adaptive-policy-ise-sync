# import meraki
# from operator import itemgetter
# import copy
import json
# from django.core import serializers
from sync.models import Organization, ISEServer, Dashboard, ElementSync, GenericData, Upload, Element
import shlex
from django.forms.models import model_to_dict
import requests


def show_enabled(e_stat):
    if e_stat is True:
        return "Yes"
    else:
        return "No"


def xstr(s):
    return '' if s is None else str(s)


def format_data(srcdata, excluded_fields=None, headers=False):
    is_list_of_dicts = False
    if isinstance(srcdata, list) and len(srcdata) > 0:
        if isinstance(srcdata[0], dict):
            is_list_of_dicts = True

    if is_list_of_dicts:
        data = []
        headdata = []
        for x in srcdata[0]:
            if excluded_fields and x not in excluded_fields:
                headdata.append(x)
            elif not excluded_fields or len(excluded_fields) == 0:
                headdata.append(x)
        data.append(headdata)
        for row in srcdata:
            rowdata = []
            for x in row:
                if excluded_fields and x not in excluded_fields:
                    rowdata.append(str(row[x]).replace("\n", "\\n"))
                elif not excluded_fields or len(excluded_fields) == 0:
                    rowdata.append(str(row[x]).replace("\n", "\\n"))
            data.append(rowdata)
        next_src_data = data
    else:
        next_src_data = srcdata

    odata = ""
    widths = [max(map(len, col)) for col in zip(*next_src_data)]
    for row in range(0, len(next_src_data)):
        hd = "-" * (sum(widths) + (2 * (len(widths) - 1))) + "\n"
        if row == 0 and headers:
            odata += hd
        odata += "  ".join((val.ljust(width) for val, width in zip(next_src_data[row], widths))) + "\n"
        if row == 0 and headers:
            odata += hd

    return odata


def resolve_arg(arg, datalist):
    dodebug = False
    if dodebug:
        print(datalist)
    retval = None

    for x in datalist:
        # print(x)
        for y in x:
            if y and y.lower() == arg.lower():
                retval = x
                break

        if retval:
            break

    if retval is None:
        if isinstance(arg, int) and arg < len(datalist):
            retval = datalist[arg]

    return retval


def exec_quit(data, clitext, contextchain):
    return "", []


def decode_model(dev_model):
    if dev_model.find("MS") >= 0:
        return "switch"
    elif dev_model.find("MR") >= 0:
        return "wireless"
    elif dev_model.find("MX") >= 0:
        return "appliance"

    return "unknown"


def clear_none(instr):
    if instr is None:
        return ""
    else:
        return str(instr)


def mask_password(in_pw, is_enabled):
    if is_enabled:
        return "*" * len(in_pw)
    else:
        return in_pw


def exec_get_config(data, clitext, contextchain):
    if data["command"]["command"] == "unmask":
        mask_pw = False
    else:
        mask_pw = True
    iseservers = ISEServer.objects.all()
    dashboards = Dashboard.objects.all()
    syncsessions = ElementSync.objects.all()
    out_config = "!\n"
    for e in iseservers:
        out_config += "ise-server \"" + str(e.description) + "\"\n"
        out_config += " ip address " + str(e.ipaddress) + "\n" if e.ipaddress else " no ip address\n"
        out_config += " username " + str(e.username) + "\n" if e.username else " no username\n"
        out_config += " password " + mask_password(str(e.password), mask_pw) + "\n" if e.username else " no password\n"
        out_config += " pxgrid\n"
        out_config += "  server ip address " + str(e.pxgrid_ip) + "\n" if e.pxgrid_ip else "  no server ip address\n"
        out_config += "  server cert " + str(e.pxgrid_isecert.filename()) + "\n" if e.pxgrid_isecert else "  no server cert\n"
        out_config += "  client name " + str(e.pxgrid_cliname) + "\n" if e.pxgrid_cliname else "  no client name\n"
        out_config += "  client cert " + str(e.pxgrid_clicert.filename()) + "\n" if e.pxgrid_clicert else "  no client cert\n"
        out_config += "  client key " + str(e.pxgrid_clikey.filename()) + "\n" if e.pxgrid_clikey else "  no client key\n"
        out_config += "  client password " + mask_password(str(e.pxgrid_clipw), mask_pw) + "\n" if e.pxgrid_clipw else "  no client password\n"
        out_config += ("  no " if e.pxgrid_enable else "  ") + "shutdown\n"
        out_config += " !\n"
        out_config += (" no " if not e.manual_dataset else " ") + "static-dataset\n"
        out_config += (" no " if e.enabled else " ") + "shutdown\n"
        out_config += "!\n"
    out_config += "!\n"
    for e in dashboards:
        out_config += "meraki-account \"" + str(e.description) + "\"\n"
        out_config += " api base-url " + str(e.baseurl) + "\n"
        out_config += " api key " + mask_password(str(e.apikey), mask_pw) + "\n" if e.apikey else " no api key\n"
        out_config += (" no " if e.enabled else " ") + "shutdown\n"
        for o in e.organization.all():
            out_config += " organization " + str(o.orgid) + "\n"
            out_config += ("  no " if not o.manual_dataset else "  ") + "static-dataset\n"
            out_config += " !\n"
        out_config += "!\n"
    for e in syncsessions:
        out_config += "sync-session \"" + str(e.description) + "\"\n"
        if e.src_element and e.src_element.iseserver:
            out_config += " source ise-server \"" + str(e.src_element.iseserver.description) + "\"\n"
        elif e.src_element and e.src_element.organization:
            out_config += " source organization " + str(e.src_element.organization.orgid) + "\n"
        else:
            out_config += " no source\n"
        out_config += " destinations\n"
        for o in e.dst_element.all():
            if o.iseserver:
                out_config += "  ise-server \"" + str(o.iseserver.description) + "\"\n"
            elif o.organization:
                out_config += "  organization " + str(o.organization.orgid) + "\n"
        out_config += " !\n"
        out_config += (" no " if e.enabled else " ") + "shutdown\n"
        out_config += (" no " if not e.apply_changes else " ") + "push-changes\n"
        out_config += (" no " if not e.reverse_sync else " ") + "reverse-sync\n"

    return out_config, contextchain


def render_data(source, element, lookup, excluded_fields):
    object_list = []
    objects = None
    if element == "tags":
        objects = GenericData.objects.filter(generictype__name="Tag")
    elif element == "acls":
        objects = GenericData.objects.filter(generictype__name="ACL")
    elif element == "policies":
        objects = GenericData.objects.filter(generictype__name="Policy")

    if source == "ise":
        objects = objects.filter(element__iseserver__description=lookup)
    elif source == "mdb":
        objects = objects.filter(element__organization__orgid=lookup)

    for o in objects:
        object_list.append(o.source_data)
    out_tags = format_data(object_list, excluded_fields=excluded_fields, headers=True)
    return out_tags


def exec_show_ise(data, clitext, contextchain):
    out_data = ""
    cli_list = shlex.split(clitext)
    # print(data, clitext, contextchain)
    # print(data["command"]["command"])
    if data["command"]["command"] == "raw":
        e = ISEServer.objects.filter(description=cli_list[2]).first()
        out_data = json.dumps(e.raw_data, indent=4)
    elif data["command"]["command"] == "objects":
        out_data = "SGTs:\n" + render_data("ise", "tags", cli_list[2], ["link"]) + "\n" +\
                   "ACLs:\n" + render_data("ise", "acls", cli_list[2], ["link"]) + "\n" +\
                   "Policies:\n" + render_data("ise", "policies", cli_list[2], ["id", "link", "description"])
    elif data["command"]["command"] == "tags":
        out_data = "SGTs:\n" + render_data("ise", "tags", cli_list[2], ["link"])
    elif data["command"]["command"] == "acls":
        out_data = "ACLs:\n" + render_data("ise", "acls", cli_list[2], ["link"])
    elif data["command"]["command"] == "policies":
        out_data = "Policies:\n" + render_data("ise", "policies", cli_list[2], ["id", "link", "description"])
    elif data["command"]["command"] == "ise-server":
        object_list = []
        objects = ISEServer.objects.all()
        for o in objects:
            object_list.append(model_to_dict(o))
        out_data = format_data(object_list, excluded_fields=["raw_data", "username", "password", "force_rebuild",
                                                             "pxgrid_enable", "pxgrid_ip", "pxgrid_cliname",
                                                             "pxgrid_clicert", "pxgrid_clikey", "pxgrid_clipw",
                                                             "pxgrid_isecert", "pxgrid_reset", "skip_update"],
                               headers=True)
    return out_data, contextchain


def exec_show_meraki(data, clitext, contextchain):
    out_data = ""
    cli_list = shlex.split(clitext)
    # print(data, clitext, contextchain)
    # print(data["command"]["command"])
    if data["command"]["command"] == "meraki-account":
        object_list = []
        objects = Dashboard.objects.all()
        for o in objects:
            object_list.append(model_to_dict(o))
        out_data = format_data(object_list, excluded_fields=["raw_data", "apikey", "force_rebuild", "webhook_enable",
                                                             "webhook_ngrok", "webhook_url", "webhook_reset",
                                                             "skip_update", "organization"],
                               headers=True)
    elif data["command"]["command"] == "raw":
        if len(cli_list) == 3:
            e = Dashboard.objects.filter(description=cli_list[2]).first()
            out_data = json.dumps(e.raw_data, indent=4)
        elif len(cli_list) == 6:
            e = Organization.objects.filter(orgid=cli_list[4]).first()
            out_data = json.dumps(e.raw_data, indent=4)
    elif data["command"]["command"] == "organizations":
        object_list = []
        e = Dashboard.objects.filter(description=cli_list[2]).first()
        for o in e.organization.all():
            object_list.append(model_to_dict(o))
        out_data = format_data(object_list, excluded_fields=["raw_data", "force_rebuild"], headers=True)
    elif data["command"]["command"] == "objects":
        out_data = "SGTs:\n" + render_data("mdb", "tags", cli_list[4], ["requiredIpMappings", "description"]) + "\n" +\
                   "ACLs:\n" + render_data("mdb", "acls", cli_list[4], ["description", "rules"]) + "\n" +\
                   "Policies:\n" + render_data("mdb", "policies", cli_list[4], ["description"])
    elif data["command"]["command"] == "tags":
        out_data = "SGTs:\n" + render_data("mdb", "tags", cli_list[4], ["requiredIpMappings", "description"])
    elif data["command"]["command"] == "acls":
        out_data = "ACLs:\n" + render_data("mdb", "acls", cli_list[4], ["description", "rules"])
    elif data["command"]["command"] == "policies":
        out_data = "Policies:\n" + render_data("mdb", "policies", cli_list[4], ["description"])
    return out_data, contextchain


def exec_show_sync(data, clitext, contextchain):
    out_data = ""
    # cli_list = shlex.split(clitext)
    # print(data, clitext, contextchain)
    # print(data["command"]["command"])
    if data["command"]["command"] == "sync-session":
        object_list = []
        objects = ElementSync.objects.all()
        for o in objects:
            # new_m = {}
            new_m = {**model_to_dict(o)}
            if not o.src_element:
                new_m["source"] = "None"
            elif o.src_element.iseserver:
                new_m["source"] = str(o.src_element.iseserver)
            else:
                new_m["source"] = str(o.src_element.organization)
            # new_m = {**new_m, **model_to_dict(o)}
            new_m["Dst Elm. #"] = len(new_m["dst_element"])
            object_list.append(new_m)
        out_data = format_data(object_list, excluded_fields=["force_rebuild", "dst_element", "src_element"],
                               headers=True)
    return out_data, contextchain


def exec_show_parse(data, clitext, contextchain):
    return "", contextchain


def exec_show_debug(data, clitext, contextchain):
    out = ""
    for c in contextchain:
        out += str(c) + "\n"

    return out, contextchain
    # return str(json.dumps(contextchain)), contextchain


def exec_config_mode(data, clitext, contextchain):
    curcontext = "config"
    contextchain.append(
        {"prompt": "(config)" + "#", "contextname": curcontext,
         "elements": None, "selected": None, "selected_data": None})

    return "", contextchain


def exec_root_context(data, clitext, contextchain):
    outcx = contextchain[0]
    outcx["selected"] = None
    outcx["selected_data"] = None
    return "", [outcx]


def exec_up_context(data, clitext, contextchain):
    outcx = contextchain[:-1]
    # outcx[len(outcx)-1]["selected"] = None
    # outcx[len(outcx)-1]["selected_data"] = None
    return "", outcx


def exec_context_ise(data, clitext, contextchain):
    cli_list = shlex.split(clitext)
    was_no = True if data["chain"][0] == "no" else False
    if was_no:
        ISEServer.objects.filter(description=cli_list[2]).delete()
        return "", contextchain
    else:
        obj, c = ISEServer.objects.get_or_create(description=cli_list[1],
                                                 defaults={"enabled": False})

    curcontext = "ise-config"
    contextchain.append(
        {"prompt": "(ise-config)" + "#", "contextname": curcontext,
         "elements": None, "selected": obj, "selected_data": None})

    return "", contextchain


def exec_context_ise_pxgrid(data, clitext, contextchain):
    curcontext = "ise-pxgrid-config"
    contextchain.append(
        {"prompt": "(ise-pxgrid-config)" + "#", "contextname": curcontext,
         "elements": None, "selected": None, "selected_data": None})

    return "", contextchain


def exec_context_meraki(data, clitext, contextchain):
    cli_list = shlex.split(clitext)
    was_no = True if data["chain"][0] == "no" else False
    if was_no:
        Dashboard.objects.filter(description=cli_list[2]).delete()
        return "", contextchain
    else:
        obj, c = Dashboard.objects.get_or_create(description=cli_list[1],
                                                 defaults={"enabled": False})

    curcontext = "meraki-config"
    contextchain.append(
        {"prompt": "(meraki-config)" + "#", "contextname": curcontext,
         "elements": None, "selected": obj, "selected_data": None})

    return "", contextchain


def exec_context_meraki_org(data, clitext, contextchain):
    cli_list = shlex.split(clitext)
    was_no = True if data["chain"][0] == "no" else False
    if was_no:
        Organization.objects.filter(description=cli_list[2]).delete()
        return "", contextchain
    else:
        obj, c = Organization.objects.get_or_create(orgid=cli_list[1])

    curcontext = "meraki-org-config"
    contextchain.append(
        {"prompt": "(meraki-org-config)" + "#", "contextname": curcontext,
         "elements": None, "selected": obj, "selected_data": None})

    return "", contextchain


def exec_context_sync(data, clitext, contextchain):
    cli_list = shlex.split(clitext)
    was_no = True if data["chain"][0] == "no" else False
    if was_no:
        ElementSync.objects.filter(description=cli_list[2]).delete()
        return "", contextchain
    else:
        obj, c = ElementSync.objects.get_or_create(description=cli_list[1],
                                                   defaults={"enabled": False, "apply_changes": False})

    curcontext = "sync-config"
    contextchain.append(
        {"prompt": "(sync-config)" + "#", "contextname": curcontext,
         "elements": None, "selected": obj, "selected_data": None})

    return "", contextchain


def exec_context_sync_destination(data, clitext, contextchain):
    curcontext = "sync-dest-config"
    contextchain.append(
        {"prompt": "(sync-dest-config)" + "#", "contextname": curcontext,
         "elements": None, "selected": None, "selected_data": None})

    return "", contextchain


def exec_syncsession_ise(data, clitext, contextchain):
    # print("exec_syncsession_ise", data["command"].get("fx_command"), data, clitext)
    fx_cmd = data["command"].get("fx_command")
    cmd = data["command"]["command"]
    was_no = True if data["chain"][0] == "no" else False
    obj = contextchain[-1]["selected"]
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    if fx_cmd == "ise-ip-address":
        obj.ipaddress = None if was_no else last_arg
    elif fx_cmd == "ise-username":
        obj.username = None if was_no else last_arg
    elif fx_cmd == "ise-password":
        obj.password = None if was_no else last_arg
    elif cmd == "shutdown":
        obj.enabled = True if was_no else False
    elif cmd == "static-dataset":
        obj.manual_dataset = False if was_no else True
    obj.save()
    return "", contextchain


def file_lookup(fn):
    return Upload.objects.filter(file__exact="upload/" + fn).first()


def exec_syncsession_ise_pxgrid(data, clitext, contextchain):
    # print("exec_syncsession_ise_pxgrid", data["command"].get("fx_command"), data, clitext)
    fx_cmd = data["command"].get("fx_command")
    cmd = data["command"]["command"]
    was_no = True if data["chain"][0] == "no" else False
    obj = contextchain[-2]["selected"]
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    if fx_cmd == "pxgrid-server-ip-address":
        obj.pxgrid_ip = None if was_no else last_arg
    elif fx_cmd == "pxgrid-server-cert":
        obj.pxgrid_isecert = None if was_no else file_lookup(last_arg)
    elif fx_cmd == "pxgrid-client-name":
        obj.pxgrid_cliname = None if was_no else last_arg
    elif fx_cmd == "pxgrid-client-password":
        obj.pxgrid_clipw = None if was_no else last_arg
    elif fx_cmd == "pxgrid-client-cert":
        obj.pxgrid_clicert = None if was_no else file_lookup(last_arg)
    elif fx_cmd == "pxgrid-client-key":
        obj.pxgrid_clikey = None if was_no else file_lookup(last_arg)
    elif cmd == "shutdown":
        obj.pxgrid_enable = True if was_no else False
    obj.save()
    return "", contextchain


def exec_syncsession_meraki(data, clitext, contextchain):
    # print("exec_syncsession_meraki", data["command"].get("fx_command"), data, clitext)
    fx_cmd = data["command"].get("fx_command")
    cmd = data["command"]["command"]
    was_no = True if data["chain"][0] == "no" else False
    obj = contextchain[-1]["selected"]
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    if fx_cmd == "api-base-url":
        obj.baseurl = None if was_no else last_arg
    elif fx_cmd == "api-key":
        obj.apikey = None if was_no else last_arg
    elif fx_cmd == "organization":
        if was_no:
            Organization.objects.filter(orgid=last_arg).delete()
        else:
            org, _ = Organization.objects.get_or_create(orgid=last_arg)
            obj.organization.add(org)
            obj.save()
    elif cmd == "shutdown":
        obj.enabled = True if was_no else False
    obj.save()
    return "", contextchain


def exec_syncsession_meraki_org(data, clitext, contextchain):
    # print("exec_syncsession_meraki_org", data["command"].get("fx_command"), data, clitext)
    # fx_cmd = data["command"].get("fx_command")
    cmd = data["command"]["command"]
    was_no = True if data["chain"][0] == "no" else False
    obj = contextchain[-1]["selected"]
    # cli_list = shlex.split(clitext)
    # last_arg = cli_list[-1]
    if cmd == "static-dataset":
        obj.manual_dataset = False if was_no else True
    obj.save()
    return "", contextchain


def exec_syncsession_sync(data, clitext, contextchain):
    # print("exec_syncsession_sync", data["command"].get("fx_command"), data, clitext)
    fx_cmd = data["command"].get("fx_command")
    cmd = data["command"]["command"]
    was_no = True if data["chain"][0] == "no" else False
    obj = contextchain[-1]["selected"]
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    if fx_cmd == "ise-server":
        obj.src_iseserver = None if was_no else ISEServer.objects.filter(description=last_arg).first()
    elif fx_cmd == "meraki-org":
        obj.src_organization = None if was_no else Organization.objects.filter(orgid=last_arg).first()
    elif cmd == "shutdown":
        obj.enabled = True if was_no else False
    elif cmd == "push-changes":
        obj.apply_changes = False if was_no else True
    elif cmd == "reverse-sync":
        obj.reverse_sync = False if was_no else True
    obj.save()
    return "", contextchain


def exec_syncsession_sync_dest(data, clitext, contextchain):
    # print("exec_syncsession_sync_dest", data["command"].get("fx_command"), data, clitext)
    fx_cmd = data["command"].get("fx_command")
    # cmd = data["command"]["command"]
    was_no = True if data["chain"][0] == "no" else False
    obj = contextchain[-2]["selected"]
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    if fx_cmd == "ise-server":
        ref = Element.objects.filter(iseserver__description=last_arg).first()
    elif fx_cmd == "meraki-org":
        ref = Element.objects.filter(organization__orgid=last_arg).first()

    if was_no:
        obj.dst_element.remove(ref)
    else:
        obj.dst_element.add(ref)
    # elif fx_cmd == "meraki-org":
    #     ref = Organization.objects.filter(orgid=last_arg).first()
    #     if was_no:
    #         obj.dst_organization.remove(ref)
    #     else:
    #         obj.dst_organization.add(ref)
    obj.save()
    return "", contextchain


def exec_show_files(data, clitext, contextchain):
    objects = Upload.objects.all()
    object_list = []
    for o in objects:
        m = model_to_dict(o)
        m["file"] = str(m["file"]).replace("upload/", "")
        m["bundle"] = o.uploadzip.description
        m["uploaded_at"] = o.uploaded_at
        object_list.append(m)
    out_tags = format_data(object_list, excluded_fields=["description", "uploadzip"], headers=True)
    return out_tags, contextchain


def exec_show_tag(data, clitext, contextchain):
    fx_cmd = data["command"].get("fx_command")
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    objs = []
    object_list = []
    excl = ["source_data", "source_ver", "last_sync", "last_update", "last_update_data", "last_update_state",
            "update_failed", "generictype", "generic"]
    objs = GenericData.objects.filter(generictype__name="Tag").order_by('generictype__type_order', 'element')
    if fx_cmd is None:
        pass
    elif fx_cmd == "organization":
        objs = objs.filter(organization__orgid=last_arg)
        excl.append("iseserver")
    elif fx_cmd == "meraki-account":
        objs = objs.filter(organization__dashboard__name=last_arg)
        excl.append("iseserver")
    elif fx_cmd == "ise-server":
        objs = objs.filter(iseserver__name=last_arg)
        excl.append("organization")
    elif fx_cmd == "sync-session":
        # tags = TagData.objects.filter(=last_arg)
        object_list = []
    # print("exec_show_tag", fx_cmd, data, clitext, last_arg)

    for o in objs:
        newo = {}
        newo["value"] = o.get_data("value")
        newo["associated_tag"] = str(o.generic)
        newo = {**newo, **model_to_dict(o)}
        if o.element.iseserver:
            newo["element"] = str(o.element.iseserver)
        else:
            newo["element"] = str(o.element.organization)
        # newo["iseserver"] = str(o.element.iseserver)
        # newo["organization"] = str(o.element.organization)
        object_list.append(newo)

    out_tags = format_data(object_list, excluded_fields=excl, headers=True)
    return out_tags, contextchain


def exec_show_acl(data, clitext, contextchain):
    fx_cmd = data["command"].get("fx_command")
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    objs = []
    object_list = []
    excl = ["source_data", "generictype", "generic"]
    objs = GenericData.objects.filter(generictype__name="ACL").order_by('generictype__type_order', 'element')
    if fx_cmd is None:
        pass
    elif fx_cmd == "organization":
        objs = objs.filter(organization__orgid=last_arg)
        excl.append("iseserver")
    elif fx_cmd == "meraki-account":
        objs = objs.filter(organization__dashboard__name=last_arg)
        excl.append("iseserver")
    elif fx_cmd == "ise-server":
        objs = objs.filter(iseserver__name=last_arg)
        excl.append("organization")
    elif fx_cmd == "sync-session":
        # tags = TagData.objects.filter(=last_arg)
        object_list = []
    # print("exec_show_tag", fx_cmd, data, clitext, last_arg)

    for o in objs:
        newo = {}
        newo["name"] = o.get_data("name")
        newo["associated_acl"] = str(o.generic)
        newo = {**newo, **model_to_dict(o)}
        if o.element.iseserver:
            newo["element"] = str(o.element.iseserver)
        else:
            newo["element"] = str(o.element.organization)
        # newo["iseserver"] = str(o.element.iseserver)
        # newo["organization"] = str(o.element.organization)
        object_list.append(newo)

    out_tags = format_data(object_list, excluded_fields=excl, headers=True)
    return out_tags, contextchain


def exec_show_policy(data, clitext, contextchain):
    fx_cmd = data["command"].get("fx_command")
    cli_list = shlex.split(clitext)
    last_arg = cli_list[-1]
    objs = []
    object_list = []
    excl = ["source_data", "generictype", "generic"]
    objs = GenericData.objects.filter(generictype__name="Policy").order_by('generictype__type_order', 'element')
    if fx_cmd is None:
        pass
    elif fx_cmd == "organization":
        objs = objs.filter(organization__orgid=last_arg)
        excl.append("iseserver")
    elif fx_cmd == "meraki-account":
        objs = objs.filter(organization__dashboard__name=last_arg)
        excl.append("iseserver")
    elif fx_cmd == "ise-server":
        objs = objs.filter(iseserver__name=last_arg)
        excl.append("organization")
    elif fx_cmd == "sync-session":
        # tags = TagData.objects.filter(=last_arg)
        object_list = []
    # print("exec_show_tag", fx_cmd, data, clitext, last_arg)

    for o in objs:
        newo = {}
        newo["mapping"] = o.get_data("_{{srcGroupId}}-{{dstGroupId}}||{{sourceSgtId}}-{{destinationSgtId}}::Tag||name::name")
        newo["associated_policy"] = "Policy :: " + str(o.generic.name) if o.generic else None
        newo = {**newo, **model_to_dict(o)}
        if o.element.iseserver:
            newo["element"] = str(o.element.iseserver)
        else:
            newo["element"] = str(o.element.organization)
        # newo["iseserver"] = str(o.element.iseserver)
        # newo["organization"] = str(o.element.organization)
        object_list.append(newo)

    out_tags = format_data(object_list, excluded_fields=excl, headers=True)
    return out_tags, contextchain


def lookup_func(data):
    headers = {"Authorization": "Bearer 488e377a430d72b3f5e4c16f21a1be455ec515fe"}
    recs = requests.get("http://127.0.0.1:8000/api/v0/organization/", headers=headers)
    # recs = getattr(sync.models, data.get("table")).objects.all()
    rj = recs.json()
    for r in rj["results"]:
        print(r)
    # recs = getattr(sync.models, data.get("table")).objects.all()
    # for rec in recs:
    #     print(rec)

    # for rec in await process_django_call(data):
    #     print(rec)

    # get_objects = await sync_to_async(process_django_call, thread_sensitive=True)(data)
    # print(get_objects)
    # print(data)

    return "hi"
