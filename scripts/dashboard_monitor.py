from sync.models import SyncSession, TagData, ACLData, PolicyData
from django.db.models import F, Q
from django.utils.timezone import make_aware
import datetime
import json
from scripts.db_trustsec import clean_sgts, clean_sgacls, clean_sgpolicies, merge_sgts, merge_sgacls, merge_sgpolicies
from scripts.dblog import append_log, db_log
import meraki
from scripts.meraki_addons import meraki_read_sgt, meraki_read_sgacl, meraki_read_sgpolicy, meraki_update_sgt, \
    meraki_create_sgt, meraki_update_sgacl, meraki_create_sgacl, meraki_update_sgpolicy, meraki_delete_sgt, \
    meraki_delete_sgacl
from django.conf import settings
import traceback


def ingest_dashboard_data(accounts, log):
    append_log(log, "dashboard_monitor::ingest_dashboard_data::Accounts -", accounts)
    dt = make_aware(datetime.datetime.now())

    for sa in accounts:
        a = sa.dashboard
        append_log(log, "dashboard_monitor::ingest_dashboard_data::Resync -", a.description)
        dashboard = meraki.DashboardAPI(base_url=a.baseurl, api_key=a.apikey, print_console=False, output_log=False,
                                        caller=settings.CUSTOM_UA, suppress_logging=True)
        orgs = a.organization.all()
        if orgs:
            for org in orgs:
                org_id = org.orgid
                append_log(log, "dashboard_monitor::processing orgid::", org_id)
                sgts = meraki_read_sgt(dashboard, org_id)
                sgacls = meraki_read_sgacl(dashboard, org_id)
                sgpolicies = meraki_read_sgpolicy(dashboard, org_id)
                append_log(log, "dashboard_monitor::ingest_dashboard_data::SGTs - ", len(sgts))
                append_log(log, "dashboard_monitor::ingest_dashboard_data::SGACLs - ", len(sgacls))
                append_log(log, "dashboard_monitor::ingest_dashboard_data::Policies - ", len(sgpolicies))

                merge_sgts("meraki", sgts, not sa.ise_source, sa, log, org)
                merge_sgacls("meraki", sgacls, not sa.ise_source, sa, log, org)
                merge_sgpolicies("meraki", sgpolicies, not sa.ise_source, sa, log, org)

                clean_sgts("meraki", sgts, not sa.ise_source, sa, log, org)
                clean_sgacls("meraki", sgacls, not sa.ise_source, sa, log, org)
                clean_sgpolicies("meraki", sgpolicies, not sa.ise_source, sa, log, org)

                org.raw_data = json.dumps({"groups": sgts, "acls": sgacls, "bindings": sgpolicies})
                org.force_rebuild = False
                org.last_sync = dt
                org.last_update = dt
                org.skip_sync = True
                org.save()
                sa.dashboard.last_sync = dt
                sa.dashboard.save()
        else:
            append_log(log, "dashboard_monitor::ingest_dashboard_data::No OrgId present")


def digest_database_data(sa, log):
    append_log(log, "dashboard_monitor::digest_database_data::Account -", sa)
    dashboard = meraki.DashboardAPI(base_url=sa.dashboard.baseurl, api_key=sa.dashboard.apikey, print_console=False,
                                    output_log=False, caller=settings.CUSTOM_UA, suppress_logging=True)

    if not sa.apply_changes:
        append_log(log, "dashboard_monitor::digest_database_data::sync session not set to apply changes;")
        return

    tags = TagData.objects.filter(Q(tag__do_sync=True) & Q(update_failed=False)).\
        exclude(organization=None)
    for o in tags:
        if o.source_id and o.update_dest() == "meraki":
            if o.tag.push_delete:
                try:
                    ret = meraki_delete_sgt(dashboard, o.organization.orgid, o.source_id)
                    append_log(log, "dashboard_monitor::digest_database_data::SGT delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGT Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                    o.save()
            else:
                try:
                    ret = meraki_update_sgt(dashboard, o.organization.orgid, o.source_id, name=o.tag.name,
                                            description=o.tag.description, value=o.tag.tag_number)
                    o.last_update_data = json.dumps(ret)
                    if "groupId" in ret:
                        o.last_update_state = "True"
                        o.source_id = ret["groupId"]
                        o.source_data = json.dumps(ret)
                    else:
                        o.last_update_state = "False"
                    o.last_update = make_aware(datetime.datetime.now())
                    o.save()
                    append_log(log, "dashboard_monitor::digest_database_data::Push SGT update", o.source_id, o.tag.name,
                               o.tag.description, ret)
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGT Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                    o.save()
        elif o.update_dest() == "meraki":
            try:
                ret = meraki_create_sgt(dashboard, o.organization.orgid, value=o.tag.tag_number, name=o.tag.name,
                                        description=o.tag.description)
                o.last_update_data = json.dumps(ret)
                if "groupId" in ret:
                    o.last_update_state = "True"
                    o.source_id = ret["groupId"]
                    o.source_data = json.dumps(ret)
                else:
                    o.last_update_state = "False"
                o.last_update = make_aware(datetime.datetime.now())
                o.save()
                append_log(log, "dashboard_monitor::digest_database_data::Push SGT create", o.tag.tag_number,
                           o.tag.name, o.tag.description, ret)
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::SGT Create Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                o.save()

    acls = ACLData.objects.filter(Q(acl__do_sync=True) & Q(update_failed=False)).\
        exclude(organization=None)
    for o in acls:
        if o.source_id and o.update_dest() == "meraki":
            if o.acl.push_delete:
                try:
                    ret = meraki_delete_sgacl(dashboard, o.organization.orgid, o.source_id)
                    append_log(log, "dashboard_monitor::digest_database_data::SGACL delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGACL Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"acl": str(o), "error": "Exception: " + str(e)}
                    o.save()
            else:
                try:
                    ret = meraki_update_sgacl(dashboard, o.organization.orgid, o.source_id, name=o.acl.name,
                                              description=o.acl.description, rules=o.lookup_rules(o),
                                              ipVersion=o.lookup_version(o))
                    o.last_update_data = json.dumps(ret)
                    if "aclId" in ret:
                        o.last_update_state = "True"
                        o.source_id = ret["aclId"]
                        o.source_data = json.dumps(ret)
                    else:
                        o.last_update_state = "False"
                    o.last_update = make_aware(datetime.datetime.now())
                    o.save()
                    append_log(log, "dashboard_monitor::digest_database_data::Push SGACL update", o.source_id,
                               o.acl.name, o.acl.description, ret)
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGACL Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"acl": str(o), "error": "Exception: " + str(e)}
                    o.save()
        elif o.update_dest() == "meraki":
            try:
                ret = meraki_create_sgacl(dashboard, o.organization.orgid, name=o.acl.name,
                                          description=o.acl.description, rules=list(o.lookup_rules(o)),
                                          ipVersion=o.lookup_version(o))
                o.last_update_data = json.dumps(ret)
                if "aclId" in ret:
                    o.last_update_state = "True"
                    o.source_id = ret["aclId"]
                    o.source_data = json.dumps(ret)
                else:
                    o.last_update_state = "False"
                o.last_update = make_aware(datetime.datetime.now())
                o.save()
                append_log(log, "dashboard_monitor::digest_database_data::Push SGACL create", o.acl.name,
                           o.acl.description, ret)
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::SGACL Create Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"acl": str(o), "error": "Exception: " + str(e)}
                o.save()

    policies = PolicyData.objects.filter(Q(policy__do_sync=True) & Q(update_failed=False)).\
        exclude(organization=None)
    for o in policies:
        if o.policy.push_delete and o.update_dest() == "meraki":
            try:
                srcsgt, dstsgt = o.policy.lookup_sgts(o)
                orgs = sa.dashboard.organization.all()
                for org in orgs:
                    ret = meraki_update_sgpolicy(dashboard, org.orgid,
                                                 srcGroupId=srcsgt.source_id, dstGroupId=dstsgt.source_id, aclIds=None,
                                                 catchAllRule="global")
                    append_log(log, "dashboard_monitor::digest_database_data::Policy delete", ret)
                    o.delete()
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::Policy Delete Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"policy": str(o), "error": "Exception: " + str(e)}
                o.save()
        elif o.update_dest() == "meraki":
            try:
                srcsgt, dstsgt = o.lookup_sgt_data(o)
                sgacl = o.lookup_sgacl_data(o)
                acls = []
                if sgacl:
                    for s in sgacl:
                        acls.append(s.source_id)

                if not srcsgt or not dstsgt or sgacl is None:
                    o.update_failed = False     # was True; disabled for now
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"policy": str(o), "error": "Meraki: Unable to locate sgt/acl data;" +
                                                                     str(srcsgt) + ";" + str(dstsgt) + ";" + str(sgacl)}
                    o.save()
                    continue

                ret = meraki_update_sgpolicy(dashboard, o.organization.orgid, name=o.policy.name,
                                             description=o.policy.description,
                                             srcGroupId=srcsgt.source_id, dstGroupId=dstsgt.source_id,
                                             aclIds=acls,
                                             catchAllRule=o.lookup_acl_catchall(o),
                                             bindingEnabled=True, monitorModeEnabled=False)
                o.last_update_data = json.dumps(ret)
                if "srcGroupId" in ret:
                    o.last_update_state = "True"
                    o.source_id = "s" + str(ret["srcGroupId"]) + "-d" + str(ret["dstGroupId"])
                    o.source_data = json.dumps(ret)
                else:
                    o.last_update_state = "False"
                o.last_update = make_aware(datetime.datetime.now())
                o.save()
                append_log(log, "dashboard_monitor::digest_database_data::Push Policy update", o.source_id,
                           o.policy.name, o.policy.description, ret)
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::Policy Update Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"policy": str(o), "error": "Exception: " + str(e)}
                o.save()


def sync_dashboard():
    log = []
    msg = "SYNC_DASHBOARD-NO_ACTION_REQUIRED"
    append_log(log, "dashboard_monitor::sync_dashboard::Checking Dashboard Accounts for re-sync...")

    # If we know that something needs to be created, do that first.
    sss = SyncSession.objects.all()
    for ss in sss:
        digest_database_data(ss, log)
        ss.dashboard.force_rebuild = True
        ss.save()
        msg = "SYNC_DASHBOARD-CHANGES_MADE_FORCE_UPDATE"

    # Ensure that ISE has already completed a sync if it is the source of truth
    stat = SyncSession.objects.filter(Q(ise_source=False) |
                                      (Q(iseserver__last_sync__isnull=False) &
                                       Q(dashboard__last_sync__isnull=True)) |
                                      (Q(iseserver__last_sync__isnull=False) &
                                       Q(iseserver__last_sync__gte=F('dashboard__last_sync'))))
    if len(stat) <= 0:
        append_log(log, "dashboard_monitor::sync_dashboard::Skipping sync as ISE is primary and needs to sync first.")
        msg = "SYNC_DASHBOARD-ISE_NEEDS_SYNC"
    else:
        append_log(log, "dashboard_monitor::sync_dashboard::Running sync")

        for s in stat:
            ctime = make_aware(datetime.datetime.now()) - datetime.timedelta(seconds=s.sync_interval)
            # Perform sync if one of the following conditions is met
            # 1) The Sync Session is set to Force Rebuild (this one shouldn't be seen here. but just in case...)
            # 2) The Dashboard Instance is set to Force Rebuild
            # 3) The timestamp of the Dashboard database object isn't the same as the timestamp of it's last sync
            # 4) The timestamp of the Dashboard database object's last sync is beyond the configured manual sync timer
            dbs = SyncSession.objects.filter(Q(dashboard__force_rebuild=True) |
                                             Q(force_rebuild=True) |
                                             ~Q(dashboard__last_sync=F('dashboard__last_update')) |
                                             Q(dashboard__last_sync__lte=ctime))
            for d in dbs:
                # Log the reason(s) for the current sync
                if d.force_rebuild:     # pragma: no cover
                    append_log(log, "dashboard_monitor::sync_dashboard::Sync Session Force Rebuild", d)
                    msg = "SYNC_DASHBOARD-SYNCSESSION_FORCE_REBUILD"
                    d.force_rebuild = False
                    d.save()
                if d.dashboard.force_rebuild:
                    append_log(log, "dashboard_monitor::sync_dashboard::Dashboard Force Rebuild", d)
                    msg = "SYNC_DASHBOARD-DASHBOARD_FORCE_REBUILD"
                    d.dashboard.force_rebuild = False
                    d.dashboard.save()
                if d.dashboard.last_sync != d.dashboard.last_update:
                    append_log(log, "dashboard_monitor::sync_dashboard::Database Config / Sync Timestamp Mismatch", d)
                    msg = "SYNC_DASHBOARD-CONFIG_SYNC_TIMESTAMP_MISMATCH"
                if d.dashboard.last_sync and (d.dashboard.last_sync <= ctime):
                    append_log(log, "dashboard_monitor::sync_dashboard::Past Manual Sync Interval", d)
                    msg = "SYNC_DASHBOARD-PAST_SYNC_INTERVAL"

                ingest_dashboard_data(dbs, log)

    # After ingesting data, more updates may be required (Should these have been caught elsewhere?)
    sss = SyncSession.objects.all()
    for ss in sss:
        digest_database_data(ss, log)

    append_log(log, "dashboard_monitor::sync_dashboard::Done")
    db_log("dashboard_monitor", log)
    return msg, log


def run():     # pragma: no cover
    sync_dashboard()
