# import atexit
# from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.jobstores import register_events

from sync.models import SyncSession, Tag, ACL, Policy
from django.db.models import F, Q
from django.utils.timezone import make_aware
import json
import datetime
import sys
from scripts.db_trustsec import clean_sgts, clean_sgacls, clean_sgpolicies, merge_sgts, merge_sgacls, merge_sgpolicies
from scripts.dblog import append_log, db_log
from ise import ERS
import traceback

scheduler = BackgroundScheduler()
scheduler.add_jobstore(DjangoJobStore(), "default")


def ingest_ise_data(accounts, log):
    append_log(log, "ise_monitor::ingest_dashboard_data::Accounts -", accounts)
    dt = make_aware(datetime.datetime.now())

    for sa in accounts:
        ise = None
        a = sa.iseserver
        append_log(log, "ise_monitor::ingest_dashboard_data::Resync -", a.description)
        ise = ERS(ise_node=a.ipaddress, ers_user=a.username, ers_pass=a.password, verify=False, disable_warnings=True)
        sgts = ise.get_sgts(detail=True)
        sgacls = ise.get_sgacls(detail=True)
        sgpolicies = ise.get_egressmatrixcells(detail=True)
        append_log(log, "ise_monitor::ingest_dashboard_data::SGTs - ", sgts)
        append_log(log, "ise_monitor::ingest_dashboard_data::SGACLs - ", sgacls)
        append_log(log, "ise_monitor::ingest_dashboard_data::Policies - ", sgpolicies)
        ise = {"sgts": sgts, "sgacls": sgacls, "sgpolicies": sgpolicies}

        merge_sgts("ise", sgts["response"], sa.ise_source, sa, log)
        merge_sgacls("ise", sgacls["response"], sa.ise_source, sa, log)
        merge_sgpolicies("ise", sgpolicies["response"], sa.ise_source, sa, log)

        clean_sgts("ise", sgts["response"], sa.ise_source, sa, log)
        clean_sgacls("ise", sgacls["response"], sa.ise_source, sa, log)
        clean_sgpolicies("ise", sgpolicies["response"], sa.ise_source, sa, log)

        a.raw_data = json.dumps(ise)
        a.force_rebuild = False
        a.last_sync = dt
        a.last_update = dt
        a.skip_sync = True
        a.save()


def digest_database_data(sa, log):
    append_log(log, "ise_monitor::digest_database_data::Account -", sa)
    ise = ERS(ise_node=sa.iseserver.ipaddress, ers_user=sa.iseserver.username, ers_pass=sa.iseserver.password,
              verify=False, disable_warnings=True)

    if not sa.apply_changes:
        append_log(log, "ise_monitor::digest_database_data::sync session not set to apply changes")
        return

    policies = Policy.objects.filter(Q(needs_update="ise") & Q(do_sync=True) & Q(update_failed=False))
    for o in policies:
        if o.ise_id:
            if o.push_delete:
                try:
                    ret = ise.delete_egressmatrixcell(o.ise_id)
                    append_log(log, "ise_monitor::digest_database_data::Policy delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::Policy Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()

    tags = Tag.objects.filter(Q(needs_update="ise") & Q(do_sync=True) & Q(update_failed=False))
    for o in tags:
        if o.ise_id:
            if o.push_delete:
                try:
                    ret = ise.delete_sgt(o.ise_id)
                    append_log(log, "ise_monitor::digest_database_data::SGT delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGT Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
            else:
                try:
                    ret = ise.update_sgt(o.ise_id, o.cleaned_name(), o.description, o.tag_number, return_object=True)
                    o.last_update_data = ret
                    o.last_update_state = str(ret.get("success", False))
                    o.save()
                    if ret["response"]:
                        merge_sgts("ise", [ret["response"]], sa.ise_source, sa, log)
                        append_log(log, "ise_monitor::digest_database_data::Push SGT update", o.ise_id,
                                   o.cleaned_name(), o.description, o.tag_number, ret)
                    else:     # pragma: no cover
                        append_log(log, "ise_monitor::digest_database_data::SGT Null Return", ret)
                        o.update_failed = True
                        o.save()
                except Exception as e:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGT Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
        else:
            try:
                ret = ise.add_sgt(o.cleaned_name(), o.description, o.tag_number, return_object=True)
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                o.save()
                if ret["response"]:
                    merge_sgts("ise", [ret["response"]], sa.ise_source, sa, log)
                    append_log(log, "ise_monitor::digest_database_data::Push SGT create", o.cleaned_name(),
                               o.description, o.tag_number, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGT Null Return", ret)
                    o.update_failed = True
                    o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::SGT Create Exception", e, traceback.format_exc())
                o.update_failed = True
                o.save()

    acls = ACL.objects.filter(Q(needs_update="ise") & Q(do_sync=True) & Q(update_failed=False))
    for o in acls:
        if o.ise_id:
            if o.push_delete:
                try:
                    ret = ise.delete_sgacl(o.ise_id)
                    append_log(log, "ise_monitor::digest_database_data::SGACL delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGACL Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
            else:
                try:
                    ret = ise.update_sgacl(o.ise_id, o.cleaned_name(), o.description, o.get_version("ise"),
                                           o.get_rules("ise").split("\n"), return_object=True)
                    o.last_update_data = ret
                    o.last_update_state = str(ret.get("success", False))
                    o.save()
                    if ret["response"]:
                        merge_sgacls("ise", [ret["response"]], sa.ise_source, sa, log)
                        append_log(log, "ise_monitor::digest_database_data::Push SGACL update", o.ise_id,
                                   o.cleaned_name(), o.description, ret)
                    else:     # pragma: no cover
                        append_log(log, "ise_monitor::digest_database_data::SGACL Null Return", ret)
                        o.update_failed = True
                        o.save()
                except Exception as e:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGACL Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.save()
        else:
            try:
                ret = ise.add_sgacl(o.cleaned_name(), o.description, o.get_version("ise"),
                                    o.get_rules("ise").split("\n"), return_object=True)
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                o.save()
                if ret["response"]:
                    merge_sgacls("ise", [ret["response"]], sa.ise_source, sa, log)
                    append_log(log, "ise_monitor::digest_database_data::Push SGACL create", o.cleaned_name(),
                               o.description, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGACL Null Return", ret)
                    o.update_failed = True
                    o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::SGACL Create Exception", e, traceback.format_exc())
                o.update_failed = True
                o.save()

    policies = Policy.objects.filter(Q(needs_update="ise") & Q(do_sync=True) & Q(update_failed=False))
    for o in policies:
        if o.ise_id and not o.push_delete:
            try:
                srcsgt, dstsgt = o.lookup_ise_sgts()
                ret = ise.update_egressmatrixcell(o.ise_id, srcsgt.ise_id, dstsgt.ise_id, o.get_catchall("ise"),
                                                  acls=o.get_sgacls("ise"), description=o.description,
                                                  return_object=True)
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                o.save()
                if ret["response"]:
                    merge_sgpolicies("ise", [ret["response"]], sa.ise_source, sa, log)
                    append_log(log, "ise_monitor::digest_database_data::Push Policy update", o.ise_id, o.name,
                               o.description, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::Policy Null Return", ret)
                    o.update_failed = True
                    o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::Policy Update Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.save()
        else:
            try:
                srcsgt, dstsgt = o.lookup_meraki_sgts()
                ret = ise.add_egressmatrixcell(srcsgt.ise_id, dstsgt.ise_id, o.get_catchall("ise"),
                                               acls=o.get_sgacls("ise"), description=o.description, return_object=True)
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                o.save()
                if ret["response"]:
                    merge_sgpolicies("ise", [ret["response"]], sa.ise_source, sa, log)
                    append_log(log, "ise_monitor::digest_database_data::Push Policy create", o.name,
                               o.description, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::Policy Null Return", ret)
                    o.update_failed = True
                    o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::Policy Create Exception", e, traceback.format_exc())
                o.update_failed = True
                o.save()


def sync_ise():
    log = []
    msg = ""
    append_log(log, "ise_monitor::sync_ise::Checking ISE Accounts for re-sync...")

    # Ensure that Meraki Dashboard has already completed a sync if it is the source of truth
    stat = SyncSession.objects.filter(Q(ise_source=True) |
                                      (Q(dashboard__last_sync__isnull=False) &
                                       Q(iseserver__last_sync__isnull=True)) |
                                      (Q(dashboard__last_sync__isnull=False) &
                                       Q(dashboard__last_sync__gte=F('iseserver__last_sync'))))

    if len(stat) <= 0:
        append_log(log, "ise_monitor::sync_ise::Skipping sync as Meraki is primary and hasn't synced.")
        msg = "SYNC_ISE-DASHBOARD_NEEDS_SYNC"
    else:
        append_log(log, "ise_monitor::sync_ise::Running sync")

        for s in stat:
            ctime = make_aware(datetime.datetime.now()) - datetime.timedelta(seconds=s.sync_interval)
            # Perform sync if one of the following conditions is met
            # 1) The Sync Session is set to Force Rebuild (this one shouldn't be seen here. but just in case...)
            # 2) The Dashboard Instance is set to Force Rebuild
            # 3) The timestamp of the ISE Server database object isn't the same as the timestamp of it's last sync
            # 4) The timestamp of the ISE Server database object's last sync is beyond the configured manual sync timer
            dbs = SyncSession.objects.filter(Q(iseserver__force_rebuild=True) |
                                             Q(force_rebuild=True) |
                                             ~Q(iseserver__last_sync=F('iseserver__last_update')) |
                                             Q(iseserver__last_sync__lte=ctime))
            for d in dbs:
                # Log the reason(s) for the current sync
                if d.force_rebuild:     # pragma: no cover
                    append_log(log, "ise_monitor::sync_ise::Sync Session Force Rebuild", d)
                    msg = "SYNC_ISE-SYNCSESSION_FORCE_REBUILD"
                    d.force_rebuild = False
                    d.save()
                if d.iseserver.force_rebuild:
                    append_log(log, "ise_monitor::sync_ise::Dashboard Force Rebuild", d)
                    msg = "SYNC_ISE-ISE_FORCE_REBUILD"
                    d.iseserver.force_rebuild = False
                    d.iseserver.save()
                if d.iseserver.last_sync and (d.iseserver.last_sync != d.iseserver.last_update):
                    append_log(log, "ise_monitor::sync_ise::Database Config / Sync Timestamp Mismatch", d)
                    msg = "SYNC_ISE-CONFIG_SYNC_TIMESTAMP_MISMATCH"
                if d.iseserver.last_sync and (d.iseserver.last_sync <= ctime):
                    append_log(log, "ise_monitor::sync_ise::Past Manual Sync Interval", d)
                    msg = "SYNC_ISE-PAST_SYNC_INTERVAL"

                ingest_ise_data(dbs, log)

    ss = SyncSession.objects.all()
    if len(ss) > 0:
        digest_database_data(ss[0], log)

    append_log(log, "ise_monitor::sync_ise::Done")
    db_log("ise_monitor", log)
    return msg, log


def run():     # pragma: no cover
    sync_ise()


@scheduler.scheduled_job("interval", seconds=10, id="ise_monitor")
def job():     # pragma: no cover
    sync_ise()


if 'test' not in sys.argv and 'test' not in sys.argv[0]:     # pragma: no cover
    register_events(scheduler)
    scheduler.start()
