from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import string
import random
import json
import os
from random import randint
import uuid
from .base_simulator import handle_request
import time
from scripts.dblog import append_log, db_log


def write_file(out_filename, content):
    with open(os.path.join("scripts", out_filename), 'w') as out_file:
        out_file.write(content)


def read_file(in_filename):
    with open(os.path.join("scripts", in_filename), 'r+') as in_file:
        return in_file.read().splitlines()


def read_file_all(in_filename):
    with open(os.path.join("scripts", in_filename), 'r+') as in_file:
        return in_file.read()


def read_json_file(in_filename, log):
    fail_count = 0
    while True:
        try:
            r = read_file_all(in_filename)
            out = json.loads(r)
            return out
        except Exception as e:
            fail_count += 1
            time.sleep(1)
            append_log(log, "dashboard_monitor::read_json_file::", fail_count, e)


def random_words(size):
    out = []
    lst = read_file("words.txt")
    for s in range(0, size):
        o = random.choice(lst)
        out.append(o)

    return out


def string_num_generator(size):
    chars = string.digits
    return ''.join(random.choice(chars) for _ in range(size))


def string_generator(size):
    chars = string.digits + string.ascii_uppercase + string.ascii_lowercase
    return ''.join(random.choice(chars) for _ in range(size))


def get_rules():
    t = int(time.time() * 1000.0)
    random.seed(((t & 0xff000000) >> 24) +
                ((t & 0x00ff0000) >> 8) +
                ((t & 0x0000ff00) << 8) +
                ((t & 0x000000ff) << 24))

    rules = []
    r_count = randint(2, 6)
    has_anyany = False
    for r in range(0, r_count):
        s_choice = random.choice([0, 1, 2, 3])
        if s_choice == 1:
            srclist = []
            s_len = randint(2, 10)
            for s in range(0, s_len):
                srclist.append(str(randint(1, 65535)))
            src = "eq " + " ".join(srclist)
        elif s_choice == 2:
            s_start = randint(1, 65500)
            s_end = randint(s_start, 65535)
            src = "range " + str(s_start) + " " + str(s_end)
        elif s_choice == 3:
            s_port = randint(1, 65500)
            src = "eq " + str(s_port)
        else:
            src = "any"

        d_choice = random.choice([0, 1, 2, 3])
        if d_choice == 1:
            dstlist = []
            d_len = randint(2, 10)
            for d in range(0, d_len):
                dstlist.append(str(randint(1, 65535)))
            dst = "eq " + " ".join(dstlist)
        elif d_choice == 2:
            d_start = randint(1, 65500)
            d_end = randint(d_start, 65535)
            dst = "range " + str(d_start) + " " + str(d_end)
        elif d_choice == 3:
            d_port = randint(1, 65500)
            dst = "eq " + str(d_port)
        else:
            dst = "any"

        rule_pol = random.choice(["permit", "deny"])
        if has_anyany:
            rule_proto = random.choice(["tcp", "udp"])
        else:
            rule_proto = random.choice(["any", "tcp", "udp", "icmp"])

        if rule_proto == "icmp" or rule_proto == "any":
            has_anyany = True
            rules.append(rule_pol + " " + rule_proto)
        else:
            srctxt = ""
            dsttxt = ""
            if src != "any":
                srctxt = " src " + src
            if dst != "any":
                dsttxt = " dst " + dst
            rules.append(rule_pol + " " + rule_proto + srctxt + dsttxt)

    return "\n".join(rules)


def run(tags, acls, policies):
    # newtags = {"SearchResult": {"total": tags, "resources": []}}
    # newacls = {"SearchResult": {"total": tags, "resources": []}}
    # newpolicies = {"SearchResult": {"total": tags, "resources": []}}
    newtags = []
    newacls = []
    newpolicies = []

    used_names = ["TrustSec_Devices", "Unknown"]
    tag_id = "947832a0-8c01-11e6-996c-525400b48521"
    tag_name = "TrustSec_Devices"
    tag_desc = "TrustSec Devices Security Group"
    tag_num = 2
    newtags.append({"id": tag_id, "name": tag_name, "description": tag_desc,
                    "value": tag_num, "generationId": "0", "propogateToApic": False,
                    "link": {"rel": "self", "type": "application/json",
                             "href": "{{url}}/ers/config/sgt/" + tag_id}
                    })
    tag_id = "92adf9f0-8c01-11e6-996c-525400b48521"
    tag_name = "Unknown"
    tag_desc = "Unknown Security Group"
    tag_num = 0
    newtags.append({"id": tag_id, "name": tag_name, "description": tag_desc,
                    "value": tag_num, "generationId": "0", "propogateToApic": False,
                    "link": {"rel": "self", "type": "application/json",
                             "href": "{{url}}/ers/config/sgt/" + tag_id}
                    })

    for t in range(0, int(tags)):
        while True:
            tw = random_words(6)
            tag_name = (tw[0] + "_" + tw[1]).title()
            if tag_name not in used_names:
                used_names.append(tag_name)
                break

        tag_id = str(uuid.uuid4())
        tag_desc = (tw[2] + " " + tw[3] + " " + tw[4] + " " + tw[5]).title()
        tag_num = randint(3, 65529)
        newtags.append({"id": tag_id, "name": tag_name, "description": tag_desc,
                        "value": tag_num, "generationId": "1", "propogateToApic": False,
                        "link": {"rel": "self", "type": "application/json",
                                 "href": "{{url}}/ers/config/sgt/" + tag_id}
                        })

    used_names.append("Permit IP")
    used_names.append("Deny IP")
    acl_id = "92951ac0-8c01-11e6-996c-525400b48521"
    acl_name = "Permit_IP"
    acl_desc = "Permit IP SGACL"
    acl_rules = "permit ip"
    newacls.append({"id": acl_id, "name": acl_name, "description": acl_desc,
                    "generationId": "0", "aclcontent": acl_rules,
                    "link": {"rel": "self", "type": "application/json",
                             "href": "{{url}}/ers/config/sgacl/" + acl_id}
                    })
    acl_id = "92919850-8c01-11e6-996c-525400b48521"
    acl_name = "Deny_IP"
    acl_desc = "Deny IP SGACL"
    acl_rules = "deny ip"
    newacls.append({"id": acl_id, "name": acl_name, "description": acl_desc,
                    "generationId": "0", "aclcontent": acl_rules,
                    "link": {"rel": "self", "type": "application/json",
                             "href": "{{url}}/ers/config/sgacl/" + acl_id}
                    })

    for a in range(0, int(acls)):
        while True:
            tw = random_words(6)
            acl_name = (tw[0] + "_" + tw[1]).title()
            if acl_name not in used_names:
                used_names.append(acl_name)
                break

        acl_id = str(uuid.uuid4())
        acl_desc = (tw[2] + " " + tw[3] + " " + tw[4] + " " + tw[5]).title()
        acl_v = random.choice(["IPV4", "IPV6", ""])
        acl_rules = get_rules()
        if acl_v == "":
            newacls.append({"id": acl_id, "name": acl_name, "description": acl_desc,
                            "generationId": "1", "aclcontent": acl_rules,
                            "link": {"rel": "self", "type": "application/json",
                                     "href": "{{url}}/ers/config/sgacl/" + acl_id}
                            })
        else:
            newacls.append({"id": acl_id, "name": acl_name, "description": acl_desc,
                            "generationId": "1", "ipVersion": acl_v, "aclcontent": acl_rules,
                            "link": {"rel": "self", "type": "application/json",
                                     "href": "{{url}}/ers/config/sgacl/" + acl_id}
                            })

    used_names.append("ANY-ANY")
    pol_id = "92c1a900-8c01-11e6-996c-525400b48521"
    pol_src = pol_dst = "92bb1950-8c01-11e6-996c-525400b48521"
    pol_name = "ANY-ANY"
    pol_desc = "Default egress rule"
    pol_catch = "PERMIT_IP"
    pol_acls = ["92951ac0-8c01-11e6-996c-525400b48521"]
    newpolicies.append({"id": pol_id, "name": pol_name, "description": pol_desc,
                        "sourceSgtId": pol_src, "destinationSgtId": pol_dst,
                        "matrixCellStatus": "ENABLED", "defaultRule": pol_catch,
                        "sgacls": pol_acls,
                        "link": {"rel": "self", "type": "application/json",
                                 "href": "{{url}}/ers/config/egressmatrixcell/" + pol_id}
                        })

    for b in range(0, int(policies)):
        # Use sgt names instead
        # while True:
        #     tw = random_words(6)
        #     pol_name = (tw[0] + " " + tw[1]).title()
        #     if pol_name not in used_names:
        #         used_names.append(pol_name)
        #         break

        pol_id = str(uuid.uuid4())
        pol_desc = (tw[2] + " " + tw[3] + " " + tw[4] + " " + tw[5]).title()
        pol_catch = random.choice(["NONE", "PERMIT_IP", "DENY_IP"])
        pol_acls = []
        apply_acl = random.choice([True, False])
        if apply_acl:
            for x in range(0, randint(2, 9)):
                newpol = random.choice(newacls)
                if newpol["id"] not in pol_acls and newpol["generationId"] == "1":
                    pol_acls.append(newpol["id"])
        pol_src = random.choice(newtags)
        pol_dst = random.choice(newtags)
        pol_name = pol_src["name"] + "-" + pol_dst["name"]
        newpolicies.append({"id": pol_id, "name": pol_name, "description": pol_desc,
                            "sourceSgtId": pol_src["id"], "destinationSgtId": pol_dst["id"],
                            "matrixCellStatus": "ENABLED", "defaultRule": pol_catch,
                            "sgacls": pol_acls,
                            "link": {"rel": "self", "type": "application/json",
                                     "href": "{{url}}/ers/config/egressmatrixcell/" +
                                     pol_id}
                            })

    write_file("sgt.json", json.dumps(newtags, indent=4))
    write_file("sgacl.json", json.dumps(newacls, indent=4))
    write_file("egressmatrixcell.json", json.dumps(newpolicies, indent=4))


@csrf_exempt
def parse_url(request):
    log = []
    baseurl = "/".join(request.build_absolute_uri().split("/")[:4])
    p = request.path.replace("/ise/ers/config/", "").replace("/ise/ers/config", "")
    arr = p.split("/")

    fixedvals = {"sgt": {"id": "{{uuid}}", "generationId": 1,
                         "link": {"rel": "self", "href": "{{url}}/ers/config/sgt/{{uuid}}",
                                  "type": "application/json"}},
                 "sgacl": {"id": "{{uuid}}", "generationId": 1,
                           "link": {"rel": "self", "href": "{{url}}/ers/config/sgacl/{{uuid}}",
                                    "type": "application/json"}},
                 "egressmatrixcell": {"id": "{{uuid}}", "name": None,
                                      "link": {"rel": "self",
                                               "href": "{{url}}/ers/config/egressmatrixcell/{{uuid}}",
                                               "type": "application/json"}}}
    postvals = {"sgt": {"name": None, "description": None, "value": None, "propogateToApic": None},
                "sgacl": {"name": None, "description": None, "aclcontent": None},
                "egressmatrixcell": {"description": None, "sourceSgtId": None, "destinationSgtId": None,
                                     "matrixCellStatus": None, "defaultRule": None, "sgacls": None}}
    info = {"sgt": {"id": "id", "unique": [{"value": [], "id": []}], "single_header": {"Sgt": "{{results}}"},
                    "multi_header": {"SearchResult": {"total": "{{length}}", "resources": "{{results}}"}},
                    "list_get_fields": ["id", "name", "description", "link"]},
            "sgacl": {"id": "id", "unique": [{"name": [], "id": []}], "single_header": {"Sgacl": "{{results}}"},
                      "multi_header": {"SearchResult": {"total": "{{length}}", "resources": "{{results}}"}},
                      "list_get_fields": ["id", "name", "description", "link"]},
            "egressmatrixcell": {"id": "id", "unique": [{"id": []}],
                                 "single_header": {"EgressMatrixCell": "{{results}}"},
                                 "multi_header": {"SearchResult": {"total": "{{length}}", "resources": "{{results}}"}},
                                 "list_get_fields": ["id", "name", "description", "link"]}}

    append_log(log, "ise_ers_simulator::", request.path)
    ret = None
    try:
        file_type = arr[0] + ".json"
        # dataset = json.loads(read_file_all(file_type).replace("{{url}}", baseurl))
        dataset = read_json_file(file_type, log)
        if len(arr) > 1:
            elem_id = arr[1]
        else:
            elem_id = None

        if request.body:
            jd = json.loads(request.body)
            if arr[0] == "egressmatrixcell" and (request.method == "POST" or request.method == "PUT"):
                srcsgt = jd.get("EgressMatrixCell", {}).get("sourceSgtId", None)
                dstsgt = jd.get("EgressMatrixCell", {}).get("destinationSgtId", None)
                srcname = None
                dstname = None
                sgtset = read_json_file("sgt.json", log)
                if srcsgt and dstsgt:
                    for s in sgtset:
                        if s["id"] == srcsgt:
                            srcname = s["name"]
                        if s["id"] == dstsgt:
                            dstname = s["name"]
                        if srcname is not None and dstname is not None:
                            break
                if srcname is None or dstname is None:
                    append_log(log, "ise_ers_simulator::Error. Unable to match Sgts.")
                    db_log("ise_ers_simulator", log)
                    return JsonResponse({"error": "Error. Unable to match Sgts."})
                fixedvals["egressmatrixcell"]["name"] = srcname + "-" + dstname
        else:
            jd = None

        updated_data, ret = handle_request(request.method, jd, baseurl, arr[0], elem_id, dataset, fixedvals, postvals,
                                           info)
        if updated_data:
            write_file(file_type, json.dumps(updated_data, indent=4))
    except Exception as e:
        append_log(log, "ise_ers_simulator::Exception.", e)

    db_log("ise_ers_simulator", log)
    return ret
