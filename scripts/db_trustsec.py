from sync.models import Tag, ACL, Policy, TagData, ACLData, PolicyData, Organization, ISEServer
import datetime
from django.utils.timezone import make_aware
from django.db.models import Q
import json
from scripts.dblog import append_log
import traceback

#
# def sync_object_data(iseserver=None, dashboard=None):
#     if dashboard:
#         base = Organization.objects.filter(dashboard=dashboard)
#         tags = TagData.objects.filter(organization__dashboard=dashboard)
#         acls = ACLData.objects.filter(organization__dashboard=dashboard)
#         pols = PolicyData.objects.filter(organization__dashboard=dashboard)
#     elif iseserver:
#         base = ISEServer.objects.filter(iseserver)
#         tags = TagData.objects.filter(iseserver=iseserver)
#         acls = ACLData.objects.filter(iseserver=iseserver)
#         pols = PolicyData.objects.filter(iseserver=iseserver)
#
#     return None


def clean_sgts(src, sgts, is_base, sync_session, log=None, obj=None):
    append_log(log, "db_trustsec::clean_sgts::", len(sgts))
    try:
        changed_objs = []
        active_id_list = []
        if src == "ise":
            for s in sgts:
                active_id_list.append(s["id"])
            # tags = TagData.objects.filter(Q(tag__origin_ise=obj) & Q(iseserver=obj))
            tags = TagData.objects.filter(iseserver=obj)
        else:
            for s in sgts:
                active_id_list.append(s["groupId"])
            # tags = TagData.objects.filter(Q(tag__origin_org=obj) & Q(organization=obj))
            tags = TagData.objects.filter(organization=obj)

        # print("@@@@@@", active_id_list)
        for i in tags:
            if src == "ise" and i.source_id and i.source_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgts::setting ise", i.source_id, "for delete")
                    i.tag.push_delete = True
                    i.tag.save()
                    # i.last_update = make_aware(datetime.datetime.now())
                    i.delete()
                else:
                    append_log(log, "db_trustsec::clean_sgts::removing ise", i.source_id, "from db")
                    i.source_id = None
                    i.source_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                    i.save()
                    changed_objs.append(i)
            if src == "meraki" and i.source_id and i.source_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgts::setting meraki", i.source_id, "for delete")
                    i.tag.push_delete = True
                    i.tag.save()
                    # i.last_update = make_aware(datetime.datetime.now())
                    i.delete()
                else:
                    append_log(log, "db_trustsec::clean_sgts::removing meraki", i.source_id, "from db")
                    i.source_id = None
                    i.source_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                    i.save()
                    changed_objs.append(i)

        dbobjs = Tag.objects.all()
        for dbo in dbobjs:
            if len(dbo.tagdata_set.all()) == 0:
                dbo.delete()

        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::clean_sgts::Exception in clean_sgts: ", e)


def clean_sgacls(src, sgacls, is_base, sync_session, log=None, obj=None):
    append_log(log, "db_trustsec::clean_sgacls::", len(sgacls))
    try:
        changed_objs = []
        active_id_list = []
        if src == "ise":
            for s in sgacls:
                active_id_list.append(s["id"])
            # acls = ACLData.objects.filter(Q(acl__origin_ise=obj) & Q(iseserver=obj))
            acls = ACLData.objects.filter(iseserver=obj)
        else:
            for s in sgacls:
                active_id_list.append(s["aclId"])
            # acls = ACLData.objects.filter(Q(acl__origin_org=obj) & Q(organization=obj))
            acls = ACLData.objects.filter(organization=obj)

        for i in acls:
            if src == "ise" and i.source_id and i.source_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgacls::setting ise", i.source_id, "for delete")
                    i.acl.push_delete = True
                    i.acl.save()
                    # i.last_update = make_aware(datetime.datetime.now())
                    i.delete()
                else:
                    append_log(log, "db_trustsec::clean_sgacls::removing ise", i.source_id, "from db")
                    i.source_id = None
                    i.source_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                    i.save()
                    changed_objs.append(i)
            if src == "meraki" and i.source_id and i.source_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgacls::setting meraki", i.source_id, "for delete")
                    i.acl.push_delete = True
                    i.acl.save()
                    # i.last_update = make_aware(datetime.datetime.now())
                    i.delete()
                else:
                    append_log(log, "db_trustsec::clean_sgacls::removing meraki", i.source_id, "from db")
                    i.source_id = None
                    i.source_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                    i.save()
                    changed_objs.append(i)

        dbobjs = ACL.objects.all()
        for dbo in dbobjs:
            if len(dbo.acldata_set.all()) == 0:
                dbo.delete()

        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::clean_sgacls::Exception in clean_sgacls: ", e)


def clean_sgpolicies(src, sgpolicies, is_base, sync_session, log=None, obj=None):
    append_log(log, "db_trustsec::clean_sgpolicies::", len(sgpolicies))
    try:
        changed_objs = []
        active_id_list = []
        if src == "ise":
            for s in sgpolicies:
                active_id_list.append(s["id"])
            # policies = PolicyData.objects.filter(Q(policy__origin_ise=obj) & Q(iseserver=obj))
            policies = PolicyData.objects.filter(iseserver=obj)
        else:
            for s in sgpolicies:
                active_id_list.append("s" + str(s["srcGroupId"]) + "-d" + str(s["dstGroupId"]))
            # policies = PolicyData.objects.filter(Q(policy__origin_org=obj) & Q(organization=obj))
            policies = PolicyData.objects.filter(organization=obj)

        for i in policies:
            if src == "ise" and i.source_id and i.source_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgpolicies::setting ise", i.source_id, "for delete")
                    i.policy.push_delete = True
                    i.policy.save()
                    # i.last_update = make_aware(datetime.datetime.now())
                    i.delete()
                else:
                    append_log(log, "db_trustsec::clean_sgpolicies::removing ise", i.source_id, "from db")
                    i.source_id = None
                    i.source_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                    i.save()
                    changed_objs.append(i)
            if src == "meraki" and i.source_id and i.source_id not in active_id_list:
                if is_base:
                    append_log(log, "db_trustsec::clean_sgpolicies::setting meraki", i.source_id, "for delete")
                    i.policy.push_delete = True
                    i.policy.save()
                    # i.last_update = make_aware(datetime.datetime.now())
                    i.delete()
                else:
                    append_log(log, "db_trustsec::clean_sgpolicies::removing meraki", i.source_id, "from db")
                    i.source_id = None
                    i.source_data = None
                    i.last_update = make_aware(datetime.datetime.now())
                    i.save()
                    changed_objs.append(i)

        dbobjs = Policy.objects.all()
        for dbo in dbobjs:
            if len(dbo.policydata_set.all()) == 0:
                dbo.delete()
        # print("#######", src, PolicyData.objects.exclude(iseserver=None))

        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::clean_sgpolicies::Exception in clean_sgpolicies: ", e)


def merge_sgts(src, sgts, is_base, sync_session, log=None, obj=None):
    try:
        iseservers = ISEServer.objects.all()
        organizations = Organization.objects.filter(dashboard__syncsession=sync_session)
        changed_objs = []
        for s in sgts:
            tag_num = None
            if isinstance(s, dict):
                if "value" in s:
                    tag_num = s["value"]
                elif "tag" in s:
                    tag_num = s["tag"]
            else:
                tag_num = None
            tid = s["id"] if "id" in s else s["groupId"]
            append_log(log, "db_trustsec::merge_sgts::evaluating", tag_num, "(", tid, ")...")

            if tag_num is not None:
                # Look up tag, and see if the source matches the current input. If so, check for updates...
                tagds = TagData.objects.filter(source_id=tid)
                if len(tagds) > 0:
                    tag = tagds[0].tag
                else:
                    tag = None

                if tag:
                    if is_base:
                        tag.tag_number = tag_num
                        # tag.name = s["name"]
                        # tag.description = s["description"]
                        if tag.name != s["name"] and tag.cleaned_name() != s["name"]:
                            tag.name = s["name"]
                        tag.description = s["description"].replace("'", "").replace('"', "")
                        tag.save()
                    created = False
                    # append_log(log, "db_trustsec::merge_sgts::updating tag", tag_num, "...")
                else:
                    if src == "meraki":
                        tag, created = Tag.objects.get_or_create(tag_number=tag_num,
                                                                 defaults={"name": s["name"],
                                                                           "description": s["description"],
                                                                           "origin_org": obj,
                                                                           "syncsession": sync_session})
                    else:
                        tag, created = Tag.objects.get_or_create(tag_number=tag_num,
                                                                 defaults={"name": s["name"],
                                                                           "description": s["description"],
                                                                           "origin_ise": obj,
                                                                           "syncsession": sync_session})
                if created:
                    append_log(log, "db_trustsec::merge_sgts::creating tag", tag_num, "...")
                # else:
                #     # if tag.origin_org == obj or tag.origin_ise == obj:
                #     if is_base:     # We aren't interested in the origin, but the base
                #         append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                #                    "exists in database; updating...")
                #         if tag.name != s["name"] and tag.cleaned_name() != s["name"]:
                #             tag.name = s["name"]
                #         tag.description = s["description"].replace("'", "").replace('"', "")
                #     else:
                #         append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                #                    "exists in database; not base, only add data...")
                # tag.save()

                # Ensure that all Data objects exist in DB
                if not tag.push_delete:
                    append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                               "writing raw data to database...")
                    if src == "meraki":
                        TagData.objects.update_or_create(tag=tag, organization=obj,
                                                         defaults={"source_id": s["groupId"],
                                                                   "source_data": json.dumps(s),
                                                                   "source_ver": s["versionNum"],
                                                                   "last_sync": make_aware(datetime.datetime.now())})
                        # Ensure TagData objects exist for ISE
                        for i in iseservers:
                            TagData.objects.get_or_create(tag=tag, iseserver=i)
                        # Ensure TagData objects exist for all Meraki Orgs
                        for o in organizations:
                            TagData.objects.get_or_create(tag=tag, organization=o)
                    elif src == "ise":
                        TagData.objects.update_or_create(tag=tag, iseserver=obj,
                                                         defaults={"source_id": s["id"],
                                                                   "source_data": json.dumps(s),
                                                                   "source_ver": s["generationId"],
                                                                   "last_sync": make_aware(datetime.datetime.now())})
                        # Ensure TagData objects exist for all Meraki Orgs
                        for o in organizations:
                            TagData.objects.get_or_create(tag=tag, organization=o)

                # if src == "meraki":
                #     i = TagData.objects.filter(source_id=s["groupId"]).\
                #         filter(organization__dashboard=sync_session.dashboard)
                #     if len(i) == 0:
                #         i = TagData.objects.filter(tag__tag_number=tag_num).\
                #             filter(organization__dashboard=sync_session.dashboard)
                # elif src == "ise":
                #     i = TagData.objects.filter(source_id=s["id"]).filter(iseserver=sync_session.iseserver)
                #     if len(i) == 0:
                #         i = TagData.objects.filter(tag__tag_number=tag_num).filter(iseserver=sync_session.iseserver)
                # else:
                #     i = []
                #
                # full_update = True
                # if len(i) > 0:
                #     if is_base:
                #         append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                #                    "exists in database; updating...")
                #         t = i[0]
                #     else:
                #         append_log(log, "db_trustsec::merge_sgts::sgt::" + src + "::", tag_num,
                #                    "exists in database; not base, only add data...")
                #         t = i[0]
                #         full_update = False
                # else:
                #     t = None
                #     append_log(log, "db_trustsec::merge_sgts::creating tag", tag_num, "...")
                #
                # if full_update and t:
                #     t.tag.tag_number = tag_num
                #     if t.tag.name != s["name"] and t.tag.cleaned_name() != s["name"]:
                #         t.tag.name = s["name"]
                #     t.tag.description = s["description"].replace("'", "").replace('"', "")
                #     t.tag.syncsession = sync_session
                #     # if not t.sourced_from:
                #     #     t.sourced_from = src
                # t.tag.save()
                #
                # if tag_num != 0 and tag_num != 2:
                #     default_dest = "meraki" if sync_session.ise_source else "ise"
                #     update_dest = "meraki" if src == "ise" else "ise"
                #     # TODO: fix this
                #     # t.needs_update = default_dest if t.meraki_id and t.ise_id else update_dest
                #
                # t.push_delete = False
                # if src == "meraki":
                #     t.source_id = s["groupId"]
                #     t.source_data = json.dumps(s)
                #     if str(t.source_ver) != str(s["versionNum"]):
                #         t.source_ver = s["versionNum"]
                # elif src == "ise":
                #     t.source_id = s["id"]
                #     t.source_data = json.dumps(s)
                #     if str(t.source_ver) != str(s["generationId"]):
                #         t.source_ver = s["generationId"]
                # t.last_update = make_aware(datetime.datetime.now())
                # changed_objs.append(t)
                # # if t.tag.in_sync():
                # #     t.needs_update = None
                # t.save()
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::merge_sgts::Exception in merge_sgts: ", e, traceback.format_exc())


def merge_sgacls(src, sgacls, is_base, sync_session, log=None, obj=None):
    try:
        iseservers = ISEServer.objects.all()
        organizations = Organization.objects.filter(dashboard__syncsession=sync_session)
        changed_objs = []
        for s in sgacls:
            tag_name = s.get("name", "")
            if tag_name == "":
                append_log(log, "db_trustsec::merge_sgacls::sgacl doesn't have name; skipping", s)
                continue
            tn_ise = tag_name.replace(" ", "_")
            tn_mer = tag_name.replace("_", " ")
            tid = s["id"] if "id" in s else s["aclId"]

            if tag_name:
                # Look up acl, and see if the source matches the current input. If so, check for updates...
                aclds = ACLData.objects.filter(source_id=tid)
                if len(aclds) > 0:
                    acls = [aclds[0].acl]
                else:
                    acls = ACL.objects.filter(Q(name=tn_mer) | Q(name=tn_ise))

                if len(acls) <= 0:
                    created = True

                    if tag_name in ("Deny_IP_Log", "Permit IP", "Permit_IP_Log", "Deny IP"):
                        isvisible = False
                    else:
                        isvisible = True

                    if src == "meraki":
                        acl = ACL.objects.create(name=tag_name, description=s["description"], origin_org=obj,
                                                 syncsession=sync_session, visible=isvisible)
                    else:
                        acl = ACL.objects.create(name=tag_name, description=s["description"], origin_ise=obj,
                                                 syncsession=sync_session, visible=isvisible)
                else:
                    created = False
                    acl = acls[0]

                if created:
                    append_log(log, "db_trustsec::merge_sgacls::creating acl", tag_name, "...")
                else:
                    # if acl.origin_org == obj or acl.origin_ise == obj:
                    if is_base:     # We aren't interested in the origin, but the base
                        append_log(log, "db_trustsec::merge_sgacls::sgacl::" + src + "::", tag_name,
                                   "exists in database; updating...")
                        if acl.name != s["name"] and acl.cleaned_name() != s["name"]:
                            acl.name = s["name"]
                        acl.description = s["description"].replace("'", "").replace('"', "")
                    else:
                        append_log(log, "db_trustsec::merge_sgacls::sgacl::" + src + "::", tag_name,
                                   "exists in database; not base, only add data...")
                acl.save()

                if not acl.push_delete:
                    if src == "meraki":
                        ACLData.objects.update_or_create(acl=acl, organization=obj,
                                                         defaults={"source_id": s["aclId"],
                                                                   "source_data": json.dumps(s),
                                                                   "source_ver": s["versionNum"],
                                                                   "last_sync": make_aware(datetime.datetime.now())})
                        # Ensure ACLData objects exist for ISE
                        for i in iseservers:
                            ACLData.objects.get_or_create(acl=acl, iseserver=i)
                        # Ensure ACLData objects exist for all Meraki Orgs
                        for o in organizations:
                            ACLData.objects.get_or_create(acl=acl, organization=o)
                    elif src == "ise":
                        ACLData.objects.update_or_create(acl=acl, iseserver=obj,
                                                         defaults={"source_id": s["id"],
                                                                   "source_data": json.dumps(s),
                                                                   "source_ver": s["generationId"],
                                                                   "last_sync": make_aware(datetime.datetime.now())})
                        # Ensure ACLData objects exist for all Meraki Orgs
                        for o in organizations:
                            ACLData.objects.get_or_create(acl=acl, organization=o)

                # if src == "meraki":
                #     i = ACLData.objects.filter(source_id=s["aclId"]).\
                #         filter(organization__dashboard=sync_session.dashboard)
                #     if len(i) == 0:
                #         i = ACLData.objects.filter(Q(acl__name=tn_ise) | Q(acl__name=tn_mer)).\
                #             filter(organization__dashboard=sync_session.dashboard)
                # elif src == "ise":
                #     i = ACLData.objects.filter(source_id=s["id"]).filter(iseserver=sync_session.iseserver)
                #     if len(i) == 0:
                #         i = ACLData.objects.filter(Q(acl__name=tn_ise) | Q(acl__name=tn_mer)).\
                #             filter(iseserver=sync_session.iseserver)
                # else:
                #     i = []
                #
                # full_update = True
                # if len(i) > 0:
                #     if is_base:
                #         append_log(log, "db_trustsec::merge_sgacls::acl::" + src + "::", tag_name,
                #                    "exists in database; updating...")
                #         t = i[0]
                #     else:
                #         append_log(log, "db_trustsec::merge_sgacls::acl::" + src + "::", tag_name,
                #                    "exists in database; not base, only add data...")
                #         t = i[0]
                #         full_update = False
                # else:
                #     append_log(log, "db_trustsec::merge_sgacls::creating acl", tag_name, "...")
                #     t = ACL()
                #
                # if full_update:
                #     if t.acl.name != tag_name and t.acl.cleaned_name() != tag_name:
                #         t.acl.name = tag_name
                #     t.acl.description = s["description"].replace("'", "").replace('"', "")
                #     t.push_delete = False
                #     t.acl.syncsession = sync_session
                #     # if not t.sourced_from:
                #     #     t.sourced_from = src
                #
                # default_dest = "meraki" if sync_session.ise_source else "ise"
                # update_dest = "meraki" if src == "ise" else "ise"
                # # TODO: fix this
                # # t.needs_update = default_dest if t.meraki_id and t.ise_id else update_dest
                #
                # if src == "meraki":
                #     t.source_id = s["aclId"]
                #     t.source_data = json.dumps(s)
                #     if str(t.source_ver) != str(s["versionNum"]):
                #         t.source_ver = s["versionNum"]
                #         # t.do_sync = True
                # elif src == "ise":
                #     t.source_id = s["id"]
                #     t.source_data = json.dumps(s)
                #     if str(s.get("name", "")) == "Deny_IP_Log" or str(s.get("name", "")) == "Permit IP" or \
                #             str(s.get("name", "")) == "Permit_IP_Log" or str(s.get("name", "")) == "Deny IP":
                #         t.visible = False
                #     if str(t.source_ver) != str(s["generationId"]):
                #         t.source_ver = s["generationId"]
                #         # if not t.visible:
                #         #     t.needs_update = None
                # t.last_update = make_aware(datetime.datetime.now())
                # changed_objs.append(t)
                # # if t.acl.in_sync():
                # #     t.needs_update = None
                # t.acl.save()
                # t.save()
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::merge_sgacls::Exception in merge_sgacls: ", e, traceback.format_exc())


def merge_sgpolicies(src, sgpolicies, is_base, sync_session, log=None, obj=None):
    try:
        iseservers = ISEServer.objects.all()
        organizations = Organization.objects.filter(dashboard__syncsession=sync_session)
        changed_objs = []
        for s in sgpolicies:
            src_grp = dst_grp = binding_id = binding_name = binding_desc = policy_name = policy_desc = None
            if src == "meraki":
                p_src = TagData.objects.filter(source_id=s["srcGroupId"]).\
                    filter(organization__dashboard=sync_session.dashboard)
                p_dst = TagData.objects.filter(source_id=s["dstGroupId"]).\
                    filter(organization__dashboard=sync_session.dashboard)
                src_grp = p_src[0] if len(p_src) > 0 else None
                dst_grp = p_dst[0] if len(p_dst) > 0 else None
            elif src == "ise":
                p_src = TagData.objects.filter(source_id=s["sourceSgtId"]).\
                    filter(iseserver=sync_session.iseserver)
                p_dst = TagData.objects.filter(source_id=s["destinationSgtId"]).\
                    filter(iseserver=sync_session.iseserver)
                src_grp = p_src[0] if len(p_src) > 0 else None
                dst_grp = p_dst[0] if len(p_dst) > 0 else None
                if src_grp and dst_grp:
                    if src_grp.tag.tag_number == 65535 and dst_grp.tag.tag_number == 65535:
                        continue

            if src_grp and dst_grp:
                binding_name = str(src_grp.tag.tag_number) + "-" + str(dst_grp.tag.tag_number)
                # binding_id = "s" + str(src_grp.tag_number) + "-d" + str(dst_grp.tag_number)
                binding_id = "s" + str(src_grp.source_id) + "-d" + str(dst_grp.source_id)
                binding_desc = str(src_grp.tag.name) + "-" + str(dst_grp.tag.name)
                policy_name = s.get("name", "")
                policy_desc = s.get("description", "")

                policy_name = binding_name if (policy_name is None or policy_name == "") else policy_name
                policy_desc = binding_desc if (policy_desc is None or policy_desc == "") else policy_desc

                # Look up policy, and see if the source matches the current input. If so, check for updates...
                full_update = False
                if src == "meraki":
                    pol, created = Policy.objects.get_or_create(mapping=binding_name,
                                                                defaults={"name": policy_name,
                                                                          "description": policy_desc,
                                                                          "origin_org": obj,
                                                                          "syncsession": sync_session})
                else:
                    pol, created = Policy.objects.get_or_create(mapping=binding_name,
                                                                defaults={"name": policy_name,
                                                                          "description": policy_desc,
                                                                          "origin_ise": obj,
                                                                          "syncsession": sync_session})
                if created:
                    append_log(log, "db_trustsec::merge_policies::creating policy", policy_name, "...")
                    full_update = True
                else:
                    # if pol.origin_org == obj or pol.origin_ise == obj:
                    if is_base:     # We aren't interested in the origin, but the base
                        append_log(log, "db_trustsec::merge_policies::policy::" + src + "::", policy_name,
                                   "exists in database; updating...")
                        full_update = True
                    else:
                        append_log(log, "db_trustsec::merge_policies::policy::" + src + "::", policy_name,
                                   "exists in database; not base, only add data...")

                if full_update:
                    pol.mapping = binding_name
                    if pol.name != policy_name and pol.cleaned_name() != policy_name:
                        pol.name = policy_name
                    pol.description = policy_desc
                    pol.source_group = src_grp.tag
                    pol.dest_group = dst_grp.tag
                    acl_set = []
                    if src == "meraki":
                        acls = ACLData.objects.filter(source_id__in=s["aclIds"])
                        for a in acls:
                            # if a.acl not in pol.acl.all():
                            acl_set.append(a.acl)
                        pol.acl.set(acl_set)
                    else:
                        acls = ACLData.objects.filter(source_id__in=s["sgacls"])
                        for a in acls:
                            # if a.acl not in pol.acl.all():
                            acl_set.append(a.acl)
                        pol.acl.set(acl_set)

                    # print("$$$merge_sgpolicies", pol.name, pol.acl.all(), s.get("aclIds"), s.get("sgacls"), acls)
                    # for ad in ACLData.objects.all():
                    #     print("$$$ACLData", ad.acl.name, ad.source_id)
                    pol.save()

                if not pol.push_delete:
                    if src == "meraki":
                        PolicyData.objects.update_or_create(policy=pol, organization=obj,
                                                            defaults={"source_id": binding_id,
                                                                      "source_data": json.dumps(s),
                                                                      "source_ver": s["versionNum"],
                                                                      "last_sync": make_aware(datetime.datetime.now())})
                        # Ensure PolicyData objects exist for ISE
                        for i in iseservers:
                            PolicyData.objects.get_or_create(policy=pol, iseserver=i)
                        # Ensure PolicyData objects exist for all Meraki Orgs
                        for o in organizations:
                            PolicyData.objects.get_or_create(policy=pol, organization=o)
                    elif src == "ise":
                        PolicyData.objects.update_or_create(policy=pol, iseserver=obj,
                                                            defaults={"source_id": s["id"],
                                                                      "source_data": json.dumps(s),
                                                                      "source_ver": s.get("generationId", None),
                                                                      "last_sync": make_aware(datetime.datetime.now())})
                        # Ensure PolicyData objects exist for all Meraki Orgs
                        for o in organizations:
                            PolicyData.objects.get_or_create(policy=pol, organization=o)

                # if src == "meraki":
                #     i = PolicyData.objects.filter(source_id=binding_id).\
                #         filter(organization__dashboard=sync_session.dashboard)
                #     if len(i) == 0:
                #         i = PolicyData.objects.filter(policy__mapping=binding_name).\
                #             filter(organization__dashboard=sync_session.dashboard)
                # elif src == "ise":
                #     i = PolicyData.objects.filter(source_id=s["id"]).filter(iseserver=sync_session.iseserver)
                #     if len(i) == 0:
                #         i = PolicyData.objects.filter(policy__mapping=binding_name).filter(iseserver=sync_session.iseserver)
                # else:
                #     i = []
                #
                # full_update = True
                # if len(i) > 0:
                #     if is_base:
                #         append_log(log, "db_trustsec::merge_sgpolicies::" + src + "::policy", binding_name,
                #                    "exists in database; updating...")
                #         t = i[0]
                #     else:
                #         append_log(log, "db_trustsec::merge_sgpolicies::" + src + "::policy", binding_name,
                #                    "exists in database; not base, only add data...")
                #         t = i[0]
                #         full_update = False
                # else:
                #     append_log(log, "db_trustsec::merge_sgacls::creating policy", binding_name, "...")
                #     t = PolicyData()
                #
                # if full_update:
                #     t.policy.mapping = binding_name
                #     if t.policy.name != policy_name and t.policy.cleaned_name() != policy_name:
                #         t.policy.name = policy_name
                #     t.policy.description = policy_desc
                #     t.policy.syncsession = sync_session
                #     t.push_delete = False
                #     # if not t.sourced_from:
                #     #     t.sourced_from = src
                #
                # t.policy.source_group = src_grp.tag
                # t.policy.dest_group = dst_grp.tag
                # t.policy.save()
                # t.save()
                #
                # default_dest = "meraki" if sync_session.ise_source else "ise"
                # update_dest = "meraki" if src == "ise" else "ise"
                # # TODO: fix this
                # # t.needs_update = default_dest if t.meraki_id and t.ise_id else update_dest
                #
                # if src == "meraki":
                #     t.source_id = binding_id
                #     t.source_data = json.dumps(s)
                #     if str(t.source_ver) != str(s["versionNum"]):
                #         t.source_ver = s["versionNum"]
                #     acls = ACLData.objects.filter(source_id__in=s["aclIds"])
                #     for a in acls:
                #         if a.acl not in t.policy.acl.all():
                #             t.policy.acl.add(a.acl)
                # elif src == "ise":
                #     t.source_id = s["id"]
                #     t.source_data = json.dumps(s)
                #     acls = ACLData.objects.filter(source_id__in=s["sgacls"])
                #     for a in acls:
                #         if a.acl not in t.policy.acl.all():
                #             t.policy.acl.add(a.acl)
                # t.last_update = make_aware(datetime.datetime.now())
                # changed_objs.append(t)
                # # if t.policy.in_sync():
                # #     t.needs_update = None
                # t.save()
            elif s.get("name", "") == "ANY-ANY":
                pass
            else:
                append_log(log, "db_trustsec::merge_sgpolicies::missing src or dst", s, src_grp, dst_grp)
        return changed_objs
    except Exception as e:    # pragma: no cover
        append_log(log, "db_trustsec::merge_sgpolicies::Exception in merge_sgpolicies: ", e, traceback.format_exc())
