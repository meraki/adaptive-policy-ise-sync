import json
import base64
from django import template
# from sync.models import Tag, ACL, Policy, TagData, ACLData, PolicyData

register = template.Library()


@register.filter
def pretty_json(value):
    try:
        j = json.dumps(value, indent=4)
    except Exception:
        j = value
    return j


@register.filter
def apikey(value):
    if value:
        showpart = value[-4:]
        outkey = ("*" * (len(value) - 4)) + showpart
        return outkey

    return value


@register.filter
def password(value):
    if value:
        outkey = "********"
        return outkey

    return value


@register.filter
def search(search_list, search_id):
    for sl in search_list:
        if sl["id"] == search_id:
            return sl["name"]


@register.filter
def json_dump(value):
    return json.dumps(value)


@register.filter
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


# @register.filter
# def choice_name(q, choices):
#     # print(q, choices)
#     for choice in choices:
#         if choice[0] == q:
#             return choice[1]
#     return ''


@register.filter
def get_state_name(o):
    if o:
        # return o.get_state_name()
        return "<font color='" + o.get_state_color() + "'>" + o.get_state_name() + "</font>"

    return ''


@register.filter
def default_if_blank(val, def_val):
    if not val or val == "":
        return def_val
    return val


@register.filter
def collect_el(values, element):
    return values, element


# @register.filter
# def check_el(values_element, elements):
#     values = values_element[0]
#     element = values_element[1]
#     # print(element, values)
#     # db_error = False
#     # for v in values:
#     #     if not v.tag:
#     #         db_error = True
#     for v in values:
#         if v.is_protected():
#             return '<font color="gray">Excluded</font>'
#         if not v.has_synced():
#             return '<font color="gray">Pending Sync</font>'
#
#         if v.iseserver == element or v.organization == element:
#             # print(v, type(v), element)
#             if (type(v) == Tag and not v.tag) or (type(v) == ACL and not v.acl) or (type(v) == Policy and not v.policy):
#                 if element != elements["src"] and not elements["sync"].reverse_sync:
#                     # if (v.iseserver and not v.iseserver.last_read) or (v.organization and not v.organization.last_read):
#                     #     return '<font color="gray">Pending Sync</font>'
#                     # else:
#                     return '<font color="orange">Delete</font>'
#                 else:
#                     return '<font color="blue">Source Missing</font>'
#             else:
#                 if element == elements["src"]:
#                     return '<font color="green">Source</font>'
#                 else:
#                     a, det = v.matches_source()
#                     if a is True:
#                         return '<font color="green">Matches Source</font> <i class="md-icon icon icon-info_8" \
#                         style="font-size: 16px;" onmouseover="showtooltip(\'' + base64encode(det) + '\')" \
#                         onmouseout="hidetooltip()"></i>'
#                     elif a is False:
#                         return '<font color="red">Update</font>  <i class="md-icon icon icon-info_8" \
#                         style="font-size: 16px;" onmouseover="showtooltip(\'' + base64encode(det) + '\')" \
#                         onmouseout="hidetooltip()"></i>'
#                     else:
#                         # return '<font color="lightgreen">Present</font>  <i class="md-icon icon icon-info_8" \
#                         # style="font-size: 16px;" onmouseover="showtooltip(\'' + base64encode(det) + '\')" \
#                         # onmouseout="hidetooltip()"></i>'
#                         # return '<font color="orange">Delete</font>'
#                         if element != elements["src"] and not elements["sync"].reverse_sync:
#                             # if (v.iseserver and not v.iseserver.last_read) or (
#                             #         v.organization and not v.organization.last_read):
#                             #     return '<font color="gray">Pending Sync</font>'
#                             # else:
#                             return '<font color="orange">Delete</font>'
#                         else:
#                             return '<font color="blue">Source Missing</font>'
#
#     if (elements["sync"].reverse_sync and element == elements["src"]) or (element != elements["src"]):
#         # if (v.iseserver and not v.iseserver.last_read) or (v.organization and not v.organization.last_read):
#         #     return '<font color="gray">Pending Sync</font>'
#         # else:
#         return '<font color="purple">Create</font>'
#     else:
#         return '<font color="gray">N/A</font>'
#     # return False
#
#
# @register.filter
# def el_bgcolor(values, element):
#     sel_color = "lightblue"
#     non_color = "pink"
#     # print(values, element)
#     for v in values:
#         # print(type(element), element.is_protected())
#         if type(v) == TagData or type(v) == ACLData or type(v) == PolicyData:
#             if v.is_protected():
#                 return non_color
#
#             if v.iseserver == element or v.organization == element:
#                 # print(v, type(v), v.tag, v.tag.do_sync)
#                 # print(v, v.is_protected())
#
#                 if type(v) == TagData and v.tag and v.tag.do_sync:
#                     return sel_color
#                 if type(v) == ACLData and v.acl and v.acl.do_sync:
#                     return sel_color
#                 if type(v) == PolicyData and v.policy and v.policy.do_sync:
#                     return sel_color
#
#         if type(element) == Tag or type(element) == ACL or type(element) == Policy:
#             if element.is_protected():
#                 return non_color
#
#             # if (v.origin_ise and v.origin_ise == element) or (v.origin_org and v.origin_org == element):
#             if type(element) == Tag and element.do_sync:
#                 return sel_color
#             if type(element) == ACL and element.do_sync:
#                 return sel_color
#             if type(element) == Policy and element.do_sync:
#                 return sel_color
#
#     return "white"


@register.filter
def lookup_val(value_list, element):
    missing_error = False
    for v in value_list:
        if v.element == element:
            return v.get_cell_content()
        if v.generic and v.generic.do_sync:
            missing_error = True

    if missing_error:
        # print(element, value_list)
        return '<font color="red">Missing</font>'
    else:
        return '<font color="gray">Not Present</font>'


@register.filter
def clean(data_obj, attr):
    return data_obj.get_data(attr, safe=True)


@register.filter
def make_list(query):
    out = "<ul>"
    objs, count = query
    for q in objs:
        out += "<li>" + str(q) + "</li>"
    out += "<ul>"
    return out


@register.filter
def list_to_ul(list_obj):
    if list_obj is None:
        return "<ul><li>None</li></ul>"

    out = "<ul>"
    for q in list_obj:
        out += "<li>" + str(q) + "</li>"
    out += "<ul>"
    return out


@register.filter
def get_key_label(data_obj):
    # print(data_obj, key_type)
    try:
        res = next(iter(data_obj))
        dt = data_obj[res][0].generictype.significant_key_label
        return dt
    except Exception:
        return "Label"
