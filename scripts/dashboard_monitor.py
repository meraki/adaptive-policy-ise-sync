# import atexit
# from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.jobstores import register_events

from sync.models import SyncSession, Tag, ACL, Policy
from django.db.models import F, Q
from django.utils.timezone import make_aware
import sys
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

scheduler = BackgroundScheduler()
scheduler.add_jobstore(DjangoJobStore(), "default")


def ingest_dashboard_data(accounts, log):
    append_log(log, "dashboard_monitor::ingest_dashboard_data::Accounts -", accounts)
    dt = make_aware(datetime.datetime.now())

    for sa in accounts:
        dashboard = None
        a = sa.dashboard
        append_log(log, "dashboard_monitor::ingest_dashboard_data::Resync -", a.description)
        dashboard = meraki.DashboardAPI(base_url=a.baseurl, api_key=a.apikey, print_console=False, output_log=False,
                                        caller=settings.CUSTOM_UA)
        sgts = meraki_read_sgt(dashboard, a.orgid)
        sgacls = meraki_read_sgacl(dashboard, a.orgid)
        sgpolicies = meraki_read_sgpolicy(dashboard, a.orgid)
        append_log(log, "dashboard_monitor::ingest_dashboard_data::SGTs - ", sgts)
        append_log(log, "dashboard_monitor::ingest_dashboard_data::SGACLs - ", sgacls)
        append_log(log, "dashboard_monitor::ingest_dashboard_data::Policies - ", sgpolicies)

        merge_sgts("meraki", sgts, not sa.ise_source, sa, log)
        merge_sgacls("meraki", sgacls, not sa.ise_source, sa, log)
        merge_sgpolicies("meraki", sgpolicies, not sa.ise_source, sa, log)

        clean_sgts("meraki", sgts, not sa.ise_source, sa, log)
        clean_sgacls("meraki", sgacls, not sa.ise_source, sa, log)
        clean_sgpolicies("meraki", sgpolicies, not sa.ise_source, sa, log)

        a.raw_data = json.dumps({"groups": sgts, "acls": sgacls, "bindings": sgpolicies})
        a.force_rebuild = False
        a.last_sync = dt
        a.last_update = dt
        a.skip_sync = True
        a.save()


def digest_database_data(sa, log):
    append_log(log, "dashboard_monitor::digest_database_data::Account -", sa)
    dashboard = meraki.DashboardAPI(base_url=sa.dashboard.baseurl, api_key=sa.dashboard.apikey, print_console=False,
                                    output_log=False, caller=settings.CUSTOM_UA)

    if not sa.apply_changes:
        append_log(log, "dashboard_monitor::digest_database_data::sync session not set to apply changes;")
        return

    tags = Tag.objects.filter(Q(needs_update="meraki") & Q(do_sync=True) & Q(update_failed=False))
    for o in tags:
        if o.meraki_id:
            if o.push_delete:
                try:
                    ret = meraki_delete_sgt(dashboard, sa.dashboard.orgid, o.meraki_id)
                    append_log(log, "dashboard_monitor::digest_database_data::SGT delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGT Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
            else:
                try:
                    ret = meraki_update_sgt(dashboard, sa.dashboard.orgid, o.meraki_id, name=o.name,
                                            description=o.description, value=o.tag_number)
                    o.last_update_data = json.dumps(ret)
                    o.last_update_state = "True" if "groupId" in ret else "False"
                    o.save()
                    # Value update causes a delete/create combination, so immediately update with new ID
                    Tag.objects.filter(id=o.id).update(meraki_id=ret["groupId"])
                    merge_sgts("meraki", [ret], not sa.ise_source, sa, log)
                    append_log(log, "dashboard_monitor::digest_database_data::Push SGT update", o.meraki_id, o.name,
                               o.description, ret)
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGT Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
        else:
            try:
                ret = meraki_create_sgt(dashboard, sa.dashboard.orgid, value=o.tag_number, name=o.name,
                                        description=o.description)
                o.last_update_data = json.dumps(ret)
                o.last_update_state = "True" if "groupId" in ret else "False"
                o.save()
                merge_sgts("meraki", [ret], not sa.ise_source, sa, log)
                append_log(log, "dashboard_monitor::digest_database_data::Push SGT create", o.tag_number, o.name,
                           o.description, ret)
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::SGT Create Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.save()

    acls = ACL.objects.filter(Q(needs_update="meraki") & Q(do_sync=True) & Q(update_failed=False))
    for o in acls:
        if o.meraki_id:
            if o.push_delete:
                try:
                    ret = meraki_delete_sgacl(dashboard, sa.dashboard.orgid, o.meraki_id)
                    append_log(log, "dashboard_monitor::digest_database_data::SGACL delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGACL Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
            else:
                try:
                    ret = meraki_update_sgacl(dashboard, sa.dashboard.orgid, o.meraki_id, name=o.name,
                                              description=o.description, rules=o.get_rules("meraki"),
                                              ipVersion=o.get_version("meraki"))
                    o.last_update_data = json.dumps(ret)
                    o.last_update_state = "True" if "aclId" in ret else "False"
                    o.save()
                    merge_sgacls("meraki", [ret], not sa.ise_source, sa, log)
                    append_log(log, "dashboard_monitor::digest_database_data::Push SGACL update", o.meraki_id, o.name,
                               o.description, ret)
                except Exception as e:  # pragma: no cover
                    append_log(log, "dashboard_monitor::digest_database_data::SGACL Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
        else:
            try:
                ret = meraki_create_sgacl(dashboard, sa.dashboard.orgid, name=o.name,
                                          description=o.description, rules=list(o.get_rules("meraki")),
                                          ipVersion=o.get_version("meraki"))
                o.last_update_data = json.dumps(ret)
                o.last_update_state = "True" if "aclId" in ret else "False"
                o.save()
                merge_sgacls("meraki", [ret], not sa.ise_source, sa, log)
                append_log(log, "dashboard_monitor::digest_database_data::Push SGACL create", o.name,
                           o.description, ret)
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::SGACL Create Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.save()

    policies = Policy.objects.filter(Q(needs_update="meraki") & Q(do_sync=True) & Q(update_failed=False))
    for o in policies:
        if o.push_delete:
            try:
                srcsgt, dstsgt = o.lookup_ise_sgts()
                ret = meraki_update_sgpolicy(dashboard, sa.dashboard.orgid, name=o.name, description=o.description,
                                             srcGroupId=srcsgt.meraki_id, dstGroupId=dstsgt.meraki_id, aclIds=None,
                                             catchAllRule="global")
                append_log(log, "dashboard_monitor::digest_database_data::Policy delete", ret)
                o.delete()
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::Policy Delete Exception", e,
                           traceback.format_exc())
        else:
            try:
                srcsgt, dstsgt = o.lookup_ise_sgts()
                ret = meraki_update_sgpolicy(dashboard, sa.dashboard.orgid, name=o.name, description=o.description,
                                             srcGroupId=srcsgt.meraki_id, dstGroupId=dstsgt.meraki_id,
                                             aclIds=o.get_sgacls("meraki"), catchAllRule=o.get_catchall("meraki"),
                                             bindingEnabled=True, monitorModeEnabled=False)
                o.last_update_data = json.dumps(ret)
                o.last_update_state = "True" if "srcGroupId" in ret else "False"
                o.save()
                merge_sgpolicies("meraki", [ret], not sa.ise_source, sa, log)
                append_log(log, "dashboard_monitor::digest_database_data::Push Policy update", o.meraki_id, o.name,
                           o.description, ret)
            except Exception as e:  # pragma: no cover
                append_log(log, "dashboard_monitor::digest_database_data::Policy Update Exception", e,
                           traceback.format_exc())


def sync_dashboard():
    log = []
    msg = ""
    append_log(log, "dashboard_monitor::sync_dashboard::Checking Dashboard Accounts for re-sync...")

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

    ss = SyncSession.objects.all()
    if len(ss) > 0:
        digest_database_data(ss[0], log)

    append_log(log, "dashboard_monitor::sync_dashboard::Done")
    db_log("dashboard_monitor", log)
    return msg, log


def run():     # pragma: no cover
    sync_dashboard()


@scheduler.scheduled_job("interval", seconds=10, id="dashboard_monitor")
def job():     # pragma: no cover
    sync_dashboard()


if 'test' not in sys.argv and 'test' not in sys.argv[0]:     # pragma: no cover
    register_events(scheduler)
    scheduler.start()
