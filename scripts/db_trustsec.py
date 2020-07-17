from sync.models import Tag, ACL, Policy
import datetime
from django.utils.timezone import make_aware
from django.db.models import Q
import json
from scripts.dblog import append_log
import traceback


def clean_sgts(src, sgts, is_base, sync_session, log=None):
    append_log(log, "db_trustsec::clean_sgts::", sgts)
    try:
        changed_objs = []
        active_id_list = []
        if src == "ise":
            for s in sgts:
                active_id_list.append(s["id"])
        elif src == "meraki":
            for s in sgts:
                active_id_list.append(s["groupId"])

        tags = Tag.objects.filter(syncsession=sync_session)
        for i in tags:
            if src == "ise" and i.ise_id and i.ise_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgts::setting ise", i.ise_id, "for delete")
                    i.push_delete = True
                    i.last_update = make_aware(datetime.datetime.now())
                else:
                    append_log(log, "db_trustsec::clean_sgts::removing ise", i.ise_id, "from db")
                    i.ise_id = None
                    i.ise_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                i.save()
                changed_objs.append(i)
            if src == "meraki" and i.meraki_id and i.meraki_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgts::setting meraki", i.meraki_id, "for delete")
                    i.push_delete = True
                    i.last_update = make_aware(datetime.datetime.now())
                else:
                    append_log(log, "db_trustsec::clean_sgts::removing meraki", i.meraki_id, "from db")
                    i.meraki_id = None
                    i.meraki_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                i.save()
                changed_objs.append(i)
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::clean_sgts::Exception in clean_sgts: ", e)


def clean_sgacls(src, sgacls, is_base, sync_session, log=None):
    append_log(log, "db_trustsec::clean_sgacls::", sgacls)
    try:
        changed_objs = []
        active_id_list = []
        if src == "ise":
            for s in sgacls:
                active_id_list.append(s["id"])
        elif src == "meraki":
            for s in sgacls:
                active_id_list.append(s["aclId"])

        acls = ACL.objects.filter(syncsession=sync_session)
        for i in acls:
            if src == "ise" and i.ise_id and i.ise_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgacls::setting ise", i.ise_id, "for delete")
                    i.push_delete = True
                    i.last_update = make_aware(datetime.datetime.now())
                else:
                    append_log(log, "db_trustsec::clean_sgacls::removing ise", i.ise_id, "from db")
                    i.ise_id = None
                    i.ise_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                i.save()
                changed_objs.append(i)
            if src == "meraki" and i.meraki_id and i.meraki_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgacls::setting meraki", i.meraki_id, "for delete")
                    i.push_delete = True
                    i.last_update = make_aware(datetime.datetime.now())
                else:
                    append_log(log, "db_trustsec::clean_sgacls::removing meraki", i.meraki_id, "from db")
                    i.meraki_id = None
                    i.meraki_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                i.save()
                changed_objs.append(i)
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::clean_sgacls::Exception in clean_sgacls: ", e)


def clean_sgpolicies(src, sgpolicies, is_base, sync_session, log=None):
    append_log(log, "db_trustsec::clean_sgpolicies::", sgpolicies)
    try:
        changed_objs = []
        active_id_list = []
        if src == "ise":
            for s in sgpolicies:
                active_id_list.append(s["id"])
        elif src == "meraki":
            for s in sgpolicies:
                active_id_list.append("s" + str(s["srcGroupId"]) + "-d" + str(s["dstGroupId"]))

        policies = Policy.objects.filter(syncsession=sync_session)
        for i in policies:
            if src == "ise" and i.ise_id and i.ise_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgpolicies::setting ise", i.ise_id, "for delete")
                    i.push_delete = True
                    i.last_update = make_aware(datetime.datetime.now())
                else:
                    append_log(log, "db_trustsec::clean_sgpolicies::removing ise", i.ise_id, "from db")
                    i.ise_id = None
                    i.ise_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                i.save()
                changed_objs.append(i)
            if src == "meraki" and i.meraki_id and i.meraki_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgpolicies::setting meraki", i.meraki_id, "for delete")
                    i.push_delete = True
                    i.last_update = make_aware(datetime.datetime.now())
                else:
                    append_log(log, "db_trustsec::clean_sgpolicies::removing meraki", i.meraki_id, "from db")
                    i.meraki_id = None
                    i.meraki_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                i.save()
                changed_objs.append(i)
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::clean_sgpolicies::Exception in clean_sgpolicies: ", e)


def merge_sgts(src, sgts, is_base, sync_session, log=None):
    try:
        changed_objs = []
        for s in sgts:
            tag_num = None
            if "value" in s:
                tag_num = s["value"]
            elif "tag" in s:
                tag_num = s["tag"]

            if tag_num is not None:
                if src == "meraki":
                    i = Tag.objects.filter(meraki_id=s["groupId"])
                elif src == "ise":
                    i = Tag.objects.filter(ise_id=s["id"])
                else:
                    i = []

                if len(i) == 0:
                    i = Tag.objects.filter(tag_number=tag_num)
                full_update = True
                if len(i) > 0:
                    if is_base:
                        append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                                   "exists in database; updating...")
                        t = i[0]
                    else:
                        append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                                   "exists in database; not base, only add data...")
                        t = i[0]
                        full_update = False
                else:
                    append_log(log, "db_trustsec::merge_sgts::creating tag", tag_num, "...")
                    t = Tag()

                if full_update:
                    t.tag_number = tag_num
                    if t.name != s["name"] and t.cleaned_name() != s["name"]:
                        t.name = s["name"]
                    t.description = s["description"].replace("'", "").replace('"', "")
                    t.push_delete = False
                    t.syncsession = sync_session
                    if not t.sourced_from:
                        t.sourced_from = src

                if tag_num != 0 and tag_num != 2:
                    default_dest = "meraki" if sync_session.ise_source else "ise"
                    update_dest = "meraki" if src == "ise" else "ise"
                    t.needs_update = default_dest if t.meraki_id and t.ise_id else update_dest

                if src == "meraki":
                    t.meraki_id = s["groupId"]
                    t.meraki_data = json.dumps(s)
                    if str(t.meraki_ver) != str(s["versionNum"]):
                        t.meraki_ver = s["versionNum"]
                elif src == "ise":
                    t.ise_id = s["id"]
                    t.ise_data = json.dumps(s)
                    if str(t.ise_ver) != str(s["generationId"]):
                        t.ise_ver = s["generationId"]
                t.last_update = make_aware(datetime.datetime.now())
                changed_objs.append(t)
                if t.in_sync():
                    t.needs_update = None
                t.save()
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::merge_sgts::Exception in merge_sgts: ", e, traceback.format_exc())


def merge_sgacls(src, sgacls, is_base, sync_session, log=None):
    try:
        changed_objs = []
        for s in sgacls:
            tag_name = s.get("name", "")
            if tag_name == "":
                append_log(log, "db_trustsec::merge_sgacls::sgacl doesn't have name; skipping", s)
                continue
            tn_ise = tag_name.replace(" ", "_")
            tn_mer = tag_name.replace("_", " ")

            if tag_name:
                if src == "meraki":
                    i = ACL.objects.filter(meraki_id=s["aclId"])
                elif src == "ise":
                    i = ACL.objects.filter(ise_id=s["id"])
                else:
                    i = []

                if len(i) == 0:
                    i = ACL.objects.filter(Q(name=tn_ise) | Q(name=tn_mer))

                full_update = True
                if len(i) > 0:
                    if is_base:
                        append_log(log, "db_trustsec::merge_sgacls::acl::" + src + "::", tag_name,
                                   "exists in database; updating...")
                        t = i[0]
                    else:
                        append_log(log, "db_trustsec::merge_sgacls::acl::" + src + "::", tag_name,
                                   "exists in database; not base, only add data...")
                        t = i[0]
                        full_update = False
                else:
                    append_log(log, "db_trustsec::merge_sgacls::creating acl", tag_name, "...")
                    t = ACL()

                if full_update:
                    if t.name != tag_name and t.cleaned_name() != tag_name:
                        t.name = tag_name
                    t.description = s["description"].replace("'", "").replace('"', "")
                    t.push_delete = False
                    t.syncsession = sync_session
                    if not t.sourced_from:
                        t.sourced_from = src

                default_dest = "meraki" if sync_session.ise_source else "ise"
                update_dest = "meraki" if src == "ise" else "ise"
                t.needs_update = default_dest if t.meraki_id and t.ise_id else update_dest

                if src == "meraki":
                    t.meraki_id = s["aclId"]
                    t.meraki_data = json.dumps(s)
                    if str(t.meraki_ver) != str(s["versionNum"]):
                        t.meraki_ver = s["versionNum"]
                        # t.do_sync = True
                elif src == "ise":
                    t.ise_id = s["id"]
                    t.ise_data = json.dumps(s)
                    if str(s.get("name", "")) == "Deny_IP_Log" or str(s.get("name", "")) == "Permit IP" or \
                            str(s.get("name", "")) == "Permit_IP_Log" or str(s.get("name", "")) == "Deny IP":
                        t.visible = False
                    if str(t.ise_ver) != str(s["generationId"]):
                        t.ise_ver = s["generationId"]
                        # if t.visible:
                        #     t.do_sync = True
                        # else:
                        if not t.visible:
                            t.needs_update = None
                t.last_update = make_aware(datetime.datetime.now())
                changed_objs.append(t)
                if t.in_sync():
                    t.needs_update = None
                t.save()
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::merge_sgacls::Exception in merge_sgacls: ", e, traceback.format_exc())


def merge_sgpolicies(src, sgpolicies, is_base, sync_session, log=None):
    try:
        changed_objs = []
        for s in sgpolicies:
            src_grp = dst_grp = binding_id = binding_name = binding_desc = policy_name = policy_desc = None
            if src == "meraki":
                p_src = Tag.objects.filter(meraki_id=s["srcGroupId"])
                p_dst = Tag.objects.filter(meraki_id=s["dstGroupId"])
                src_grp = p_src[0] if len(p_src) > 0 else None
                dst_grp = p_dst[0] if len(p_dst) > 0 else None
            elif src == "ise":
                p_src = Tag.objects.filter(ise_id=s["sourceSgtId"])
                p_dst = Tag.objects.filter(ise_id=s["destinationSgtId"])
                src_grp = p_src[0] if len(p_src) > 0 else None
                dst_grp = p_dst[0] if len(p_dst) > 0 else None
                if src_grp and dst_grp:
                    if src_grp.tag_number == 65535 and dst_grp.tag_number == 65535:
                        continue

            if src_grp and dst_grp:
                binding_name = str(src_grp.tag_number) + "-" + str(dst_grp.tag_number)
                # binding_id = "s" + str(src_grp.tag_number) + "-d" + str(dst_grp.tag_number)
                binding_id = "s" + str(src_grp.meraki_id) + "-d" + str(dst_grp.meraki_id)
                binding_desc = str(src_grp.name) + "-" + str(dst_grp.name)
                policy_name = s.get("name", "")
                policy_desc = s.get("description", "")

                policy_name = binding_name if (policy_name is None or policy_name == "") else policy_name
                policy_desc = binding_desc if (policy_desc is None or policy_desc == "") else policy_desc

                if src == "meraki":
                    i = Policy.objects.filter(meraki_id=binding_id)
                elif src == "ise":
                    i = Policy.objects.filter(ise_id=s["id"])
                else:
                    i = []

                if len(i) == 0:
                    i = Policy.objects.filter(mapping=binding_name)

                full_update = True
                if len(i) > 0:
                    if is_base:
                        append_log(log, "db_trustsec::merge_sgpolicies::" + src + "::policy", binding_name,
                                   "exists in database; updating...")
                        t = i[0]
                    else:
                        append_log(log, "db_trustsec::merge_sgpolicies::" + src + "::policy", binding_name,
                                   "exists in database; not base, only add data...")
                        t = i[0]
                        full_update = False
                else:
                    append_log(log, "db_trustsec::merge_sgacls::creating policy", binding_name, "...")
                    t = Policy()

                if full_update:
                    t.mapping = binding_name
                    if t.name != policy_name and t.cleaned_name() != policy_name:
                        t.name = policy_name
                    t.description = policy_desc
                    t.push_delete = False
                    t.syncsession = sync_session
                    if not t.sourced_from:
                        t.sourced_from = src

                t.source_group = src_grp
                t.dest_group = dst_grp
                t.save()

                default_dest = "meraki" if sync_session.ise_source else "ise"
                update_dest = "meraki" if src == "ise" else "ise"
                t.needs_update = default_dest if t.meraki_id and t.ise_id else update_dest

                if src == "meraki":
                    t.meraki_id = binding_id
                    t.meraki_data = json.dumps(s)
                    if str(t.meraki_ver) != str(s["versionNum"]):
                        t.meraki_ver = s["versionNum"]
                    acls = ACL.objects.filter(meraki_id__in=s["aclIds"])
                    for a in acls:
                        if a not in t.acl.all():
                            t.acl.add(a)
                elif src == "ise":
                    t.ise_id = s["id"]
                    t.ise_data = json.dumps(s)
                    acls = ACL.objects.filter(ise_id__in=s["sgacls"])
                    for a in acls:
                        if a not in t.acl.all():
                            t.acl.add(a)
                t.last_update = make_aware(datetime.datetime.now())
                changed_objs.append(t)
                if t.in_sync():
                    t.needs_update = None
                t.save()
            else:
                append_log(log, "db_trustsec::merge_sgpolicies::missing src or dst", s, src_grp, dst_grp)
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::merge_sgpolicies::Exception in merge_sgpolicies: ", e, traceback.format_exc())
