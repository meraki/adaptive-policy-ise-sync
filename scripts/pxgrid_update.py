import json
from scripts.dblog import append_log, db_log
from asgiref.sync import sync_to_async
from sync.models import ISEServer, SyncSession
from scripts.meraki_addons import meraki_read_sgt, meraki_read_sgacl, meraki_update_sgt, \
    meraki_create_sgt, meraki_update_sgacl, meraki_create_sgacl, meraki_delete_sgt, \
    meraki_delete_sgacl
from django.utils.timezone import make_aware
import datetime
import meraki
from django.conf import settings
from sync.models import Tag, TagData, ACL, ACLData
from ise import ERS


@sync_to_async
def get_sync_account(ise_server_id):
    sa = SyncSession.objects.filter(iseserver__id=ise_server_id)
    if len(sa) >= 0:
        return sa[0]
    return None


@sync_to_async
def process_sgt_update(msg, sa):
    # {"operation": "UPDATE", "securityGroup": {"id": "34714b20-7a6f-11ea-a6b9-26b516ce162b", "name": "new_test_tag",
    # "description": "tttt", "tag": 867, "isReadOnly": false, "isServiceProvider": false, "defaultSgaclIds": []}}
    changed_tag = msg.get("securityGroup", {}).get("tag")
    changed_id = msg.get("securityGroup", {}).get("id")
    ise = ERS(ise_node=sa.iseserver.ipaddress, ers_user=sa.iseserver.username, ers_pass=sa.iseserver.password,
              verify=False, disable_warnings=True)
    op = msg.get("operation", "")
    if op == "DELETE" and changed_id:
        dashboard = meraki.DashboardAPI(base_url=sa.dashboard.baseurl, api_key=sa.dashboard.apikey,
                                        print_console=False, output_log=False,
                                        caller=settings.CUSTOM_UA, suppress_logging=True)

        # identify tagdata associated with delete request
        tds = TagData.objects.filter(source_id=changed_id)
        if len(tds) == 0:
            tds = TagData.objects.filter(tag__tag_number=changed_tag).filter(iseserver=sa.iseserver)

        # set delete flag on tag, then get all tagdata associated with meraki (assuming ise is auth source)
        if len(tds) == 1 and sa.ise_source:
            td = tds[0]
            td.tag.push_delete = True
            td.tag.save()
            mer_tds = TagData.objects.filter(tag=td.tag).filter(iseserver=None)
            for mer_td in mer_tds:
                # if we've stored the source id and the organization, we can execute the delete directly
                if mer_td.source_id and mer_td.organization:
                    meraki_delete_sgt(dashboard, mer_td.organization.orgid, mer_td.source_id)
                # otherwise, we can get a list of all tags, then find the one to delete
                elif mer_td.organization:
                    dash_sgts = meraki_read_sgt(dashboard, mer_td.organization.orgid)
                    for dash_sgt in dash_sgts:
                        if int(dash_sgt["value"]) == int(changed_tag):
                            meraki_delete_sgt(dashboard, mer_td.organization.orgid, dash_sgt["groupId"])
                mer_td.delete()
            td.tag.delete()
            td.delete()
    elif changed_id:
        # Since pxGrid doesn't send all the details available in ERS, make an ERS call to get the object
        isesgt = ise.get_sgt(changed_id)["response"]

        # In case tag is brand new and hasn't hit the database yet, we may need to create it...
        tag, created = Tag.objects.get_or_create(tag_number=changed_tag,
                                                 defaults={"name": isesgt["name"],
                                                           "description": isesgt["description"],
                                                           "origin_ise": sa.iseserver,
                                                           "syncsession": sa})
        # We didn't create it, so we will update as long as ISE is the source
        if not created and sa.ise_source:
            tag.name = isesgt["name"]
            tag.description = isesgt["description"]
            tag.save()

        # Regardless of source, we will update the data that is specific to ISE
        TagData.objects.update_or_create(tag=tag, iseserver=sa.iseserver,
                                         defaults={"source_id": isesgt["id"],
                                                   "source_data": json.dumps(isesgt),
                                                   "source_ver": isesgt["generationId"],
                                                   "last_sync":
                                                       make_aware(datetime.datetime.now())})

        # Now, if the tag is set to sync, we need to push the create/update to Dashboard - which may be one or
        #  more organizations
        if tag.do_sync:
            dashboard = meraki.DashboardAPI(base_url=sa.dashboard.baseurl, api_key=sa.dashboard.apikey,
                                            print_console=False, output_log=False,
                                            caller=settings.CUSTOM_UA, suppress_logging=True)
            for org in sa.dashboard.organization.all():
                td, created = TagData.objects.get_or_create(tag=tag, organization=org)
                dash_sgts = meraki_read_sgt(dashboard, org.orgid)
                match_tag = None
                for dash_sgt in dash_sgts:
                    # if we have tagdata, that means the tag should exist and we need to update it
                    if not created and td.source_id == str(dash_sgt["groupId"]):
                        match_tag = dash_sgt
                        break
                    # if we do not have tagdata (or if the source id is missing), the tag probably doesn't exist.
                    #  check by tag number to double check
                    if (created or td.source_id is None) and int(dash_sgt["value"]) == int(changed_tag):
                        match_tag = dash_sgt
                        break

                if match_tag:
                    if sa.ise_source:
                        ret = meraki_update_sgt(dashboard, org.orgid, match_tag["groupId"], name=isesgt["name"],
                                                description=isesgt["description"], value=changed_tag)
                    else:
                        ret = {"error": "Meraki is authoritative source; not pushing update from ISE"}
                else:
                    ret = meraki_create_sgt(dashboard, org.orgid, value=changed_tag, name=isesgt["name"],
                                            description=isesgt["description"])
                td.last_update_data = json.dumps(ret)
                if "groupId" in ret:
                    td.last_update_state = "True"
                    td.source_id = ret["groupId"]
                    td.source_data = json.dumps(ret)
                else:
                    td.last_update_state = "False"
                td.last_update = make_aware(datetime.datetime.now())
                td.save()
    else:
        print("Error parsing message")

    # ISE sends an update to /topic/com.cisco.ise.config.trustsec.security.group when Policy Group Matrices are updated
    # Since there isn't a direct way to detect these changes, schedule a policy re-sync
    sa.iseserver.force_rebuild = True
    sa.iseserver.save()

    return ""


@sync_to_async
def process_sgacl_update(msg, sa):
    # {"isDeleted": false, "timestamp": "2020-04-14T11:45:19.217Z", "id": "08a4f350-5e1a-11ea-a6b9-26b516ce162b",
    # "name": "new_ise_sgl", "description": "test", "ipVersion": "IPV4",
    # "acl": "permit tcp src eq 5060\npermit udp src eq 5060\ndeny ip", "generationId": "6", "isReadOnly": false}
    changed_id = msg.get("id")
    changed_name = msg.get("name")
    ise = ERS(ise_node=sa.iseserver.ipaddress, ers_user=sa.iseserver.username, ers_pass=sa.iseserver.password,
              verify=False, disable_warnings=True)
    if msg.get("isDeleted") and changed_id:
        dashboard = meraki.DashboardAPI(base_url=sa.dashboard.baseurl, api_key=sa.dashboard.apikey,
                                        print_console=False, output_log=False,
                                        caller=settings.CUSTOM_UA, suppress_logging=True)

        # identify tagdata associated with delete request
        tds = ACLData.objects.filter(source_id=changed_id)
        if len(tds) == 0:
            tds = ACLData.objects.filter(acl__name=changed_name).filter(iseserver=sa.iseserver)

        # set delete flag on tag, then get all tagdata associated with meraki (assuming ise is auth source)
        if len(tds) == 1 and sa.ise_source:
            td = tds[0]
            td.acl.push_delete = True
            td.acl.save()
            mer_tds = ACLData.objects.filter(acl=td.acl).filter(iseserver=None)
            for mer_td in mer_tds:
                # if we've stored the source id and the organization, we can execute the delete directly
                if mer_td.source_id and mer_td.organization:
                    meraki_delete_sgacl(dashboard, mer_td.organization.orgid, mer_td.source_id)
                # otherwise, we can get a list of all acls, then find the one to delete
                elif mer_td.organization:
                    dash_sgacls = meraki_read_sgacl(dashboard, mer_td.organization.orgid)
                    for dash_sgacl in dash_sgacls:
                        if dash_sgacl["name"] == changed_name:
                            meraki_delete_sgacl(dashboard, mer_td.organization.orgid, dash_sgacl["aclId"])
                mer_td.delete()
            td.acl.delete()
            td.delete()
    elif changed_id:
        # Since pxGrid doesn't send all the details available in ERS, make an ERS call to get the object
        isesgacl = ise.get_sgacl(changed_id)["response"]

        # In case tag is brand new and hasn't hit the database yet, we may need to create it...
        if changed_name in ("Deny_IP_Log", "Permit IP", "Permit_IP_Log", "Deny IP"):
            isvisible = False
        else:
            isvisible = True

        acl, created = ACL.objects.get_or_create(name=changed_name,
                                                 defaults={"description": isesgacl["description"],
                                                           "origin_ise": sa.iseserver,
                                                           "syncsession": sa, "visible": isvisible})
        # We didn't create it, so we will update as long as ISE is the source
        if not created and sa.ise_source:
            acl.name = isesgacl["name"]
            acl.description = isesgacl["description"]
            acl.save()

        # Regardless of source, we will update the data that is specific to ISE
        ACLData.objects.update_or_create(acl=acl, iseserver=sa.iseserver,
                                         defaults={"source_id": isesgacl["id"],
                                                   "source_data": json.dumps(isesgacl),
                                                   "source_ver": isesgacl["generationId"],
                                                   "last_sync":
                                                       make_aware(datetime.datetime.now())})

        # Now, if the acl is set to sync, we need to push the create/update to Dashboard - which may be one or
        #  more organizations
        if acl.do_sync:
            dashboard = meraki.DashboardAPI(base_url=sa.dashboard.baseurl, api_key=sa.dashboard.apikey,
                                            print_console=False, output_log=False,
                                            caller=settings.CUSTOM_UA, suppress_logging=True)
            for org in sa.dashboard.organization.all():
                td, created = ACLData.objects.get_or_create(acl=acl, organization=org)
                dash_sgacls = meraki_read_sgacl(dashboard, org.orgid)
                match_acl = None
                for dash_sgacl in dash_sgacls:
                    # if we have acldata, that means the acl should exist and we need to update it
                    if not created and td.source_id == str(dash_sgacl["aclId"]):
                        match_acl = dash_sgacl
                        break
                    # if we do not have acldata (or if the source id is missing), the acl probably doesn't exist.
                    #  check by acl name to double check
                    if (created or td.source_id is None) and dash_sgacl["name"] == changed_name:
                        match_acl = dash_sgacl
                        break

                if match_acl:
                    if sa.ise_source:
                        ret = meraki_update_sgacl(dashboard, org.orgid, match_acl["aclId"], name=isesgacl["name"],
                                                  description=isesgacl["description"], value=changed_name,
                                                  rules=td.lookup_rules(td), ipVersion=td.lookup_version(td))
                    else:
                        ret = {"error": "Meraki is authoritative source; not pushing update from ISE"}
                else:
                    ret = meraki_create_sgacl(dashboard, org.orgid, value=changed_name, name=isesgacl["name"],
                                              description=isesgacl["description"], rules=td.lookup_rules(td),
                                              ipVersion=td.lookup_version(td))
                td.last_update_data = json.dumps(ret)
                if "aclId" in ret:
                    td.last_update_state = "True"
                    td.source_id = ret["aclId"]
                    td.source_data = json.dumps(ret)
                else:
                    td.last_update_state = "False"
                td.last_update = make_aware(datetime.datetime.now())
                td.save()
    else:
        print("Error parsing message")
