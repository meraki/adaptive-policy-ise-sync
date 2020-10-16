# import atexit
# from apscheduler.schedulers.background import BackgroundScheduler
# from apscheduler.schedulers.background import BackgroundScheduler
# from django_apscheduler.jobstores import DjangoJobStore
# from django_apscheduler.jobstores import register_events

from sync.models import SyncSession, TagData, ACLData, PolicyData
from django.db.models import F, Q
from django.utils.timezone import make_aware
import json
import datetime
from scripts.db_trustsec import clean_sgts, clean_sgacls, clean_sgpolicies, merge_sgts, merge_sgacls, merge_sgpolicies
from scripts.dblog import append_log, db_log
from ise import ERS
import traceback

# scheduler = BackgroundScheduler()
# scheduler.add_jobstore(DjangoJobStore(), "default")


def ingest_ise_data(accounts, log):
    append_log(log, "ise_monitor::ingest_server_data::Accounts -", accounts)
    dt = make_aware(datetime.datetime.now())

    for sa in accounts:
        ise = None
        a = sa.iseserver
        append_log(log, "ise_monitor::ingest_server_data::Resync -", a.description)
        ise = ERS(ise_node=a.ipaddress, ers_user=a.username, ers_pass=a.password, verify=False, disable_warnings=True)
        sgts = ise.get_sgts(detail=True)
        sgacls = ise.get_sgacls(detail=True)
        sgpolicies = ise.get_egressmatrixcells(detail=True)
        append_log(log, "ise_monitor::ingest_server_data::SGTs - ", len(sgts))
        append_log(log, "ise_monitor::ingest_server_data::SGACLs - ", len(sgacls))
        append_log(log, "ise_monitor::ingest_server_data::Policies - ", len(sgpolicies))
        ise = {"sgts": sgts, "sgacls": sgacls, "sgpolicies": sgpolicies}

        merge_sgts("ise", sgts["response"], sa.ise_source, sa, log, a)
        merge_sgacls("ise", sgacls["response"], sa.ise_source, sa, log, a)
        merge_sgpolicies("ise", sgpolicies["response"], sa.ise_source, sa, log, a)

        clean_sgts("ise", sgts["response"], sa.ise_source, sa, log, a)
        clean_sgacls("ise", sgacls["response"], sa.ise_source, sa, log, a)
        clean_sgpolicies("ise", sgpolicies["response"], sa.ise_source, sa, log, a)

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

    policies = PolicyData.objects.filter(Q(policy__do_sync=True) & Q(update_failed=False)).exclude(iseserver=None)
    for o in policies:
        if o.source_id and o.update_dest() == "ise":
            if o.policy.push_delete:
                try:
                    ret = ise.delete_egressmatrixcell(o.source_id)
                    append_log(log, "ise_monitor::digest_database_data::Policy delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::Policy Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                    o.save()

    append_log(log, "ise_monitor::digest_database_data::Tag check")
    from django.forms.models import model_to_dict
    # for sgt in TagData.objects.exclude(iseserver=None):
    #     append_log(log, "ise_monitor::digest_database_data::Tag", sgt.tag.name, sgt.tag.do_sync, model_to_dict(sgt))
    tags = TagData.objects.filter(Q(tag__do_sync=True) & Q(update_failed=False)).exclude(iseserver=None)
    for o in tags:
        append_log(log, "ise_monitor::digest_database_data::Tag", o.tag.name, o.tag.do_sync, o.tag.in_sync(), o.update_dest(), model_to_dict(o))
        if o.source_id and o.update_dest() == "ise":
            if o.tag.push_delete:
                try:
                    ret = ise.delete_sgt(o.source_id)
                    append_log(log, "ise_monitor::digest_database_data::SGT delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGT Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                    o.save()
            else:
                try:
                    ret = ise.update_sgt(o.source_id, o.tag.cleaned_name(), o.tag.description, o.tag.tag_number,
                                         return_object=True)
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_data = ret
                    o.last_update_state = str(ret.get("success", False))
                    if ret["response"] and isinstance(ret["response"], dict):
                        o.source_id = ret["response"]["id"]
                        o.source_data = json.dumps(ret["response"])
                        append_log(log, "ise_monitor::digest_database_data::Push SGT update", o.source_id,
                                   o.tag.cleaned_name(), o.tag.description, o.tag.tag_number, ret)
                    else:
                        append_log(log, "ise_monitor::digest_database_data::SGT Invalid Return", ret)
                        o.update_failed = True
                        o.last_update_state = "False"
                        o.last_update_data = {"tag": str(o), "error": "SGT Invalid return"}
                    o.save()
                except Exception as e:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGT Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                    o.save()
        elif o.update_dest() == "ise":
            try:
                ret = ise.add_sgt(o.tag.cleaned_name(), o.tag.description, o.tag.tag_number, return_object=True)
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                if ret["response"] and isinstance(ret["response"], dict):
                    o.source_id = ret["response"]["id"]
                    o.source_data = json.dumps(ret["response"])
                    append_log(log, "ise_monitor::digest_database_data::Push SGT create", o.tag.cleaned_name(),
                               o.tag.description, o.tag.tag_number, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGT Invalid Return", ret)
                    o.update_failed = True
                    o.last_update_state = "False"
                    o.last_update_data = {"tag": str(o), "error": "SGT Invalid Return"}
                o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::SGT Create Exception", e, traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"tag": str(o), "error": "Exception: " + str(e)}
                o.save()

    acls = ACLData.objects.filter(Q(acl__do_sync=True) & Q(update_failed=False)).exclude(iseserver=None)
    for o in acls:
        if o.source_id and o.update_dest() == "ise":
            if o.acl.push_delete:
                try:
                    ret = ise.delete_sgacl(o.source_id)
                    append_log(log, "ise_monitor::digest_database_data::SGACL delete", ret)
                    o.delete()
                except Exception as e:  # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGACL Delete Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"acl": str(o), "error": "Exception: " + str(e)}
                    o.save()
            else:
                try:
                    ret = ise.update_sgacl(o.source_id, o.acl.cleaned_name(), o.acl.description, o.lookup_version(o),
                                           o.lookup_rules(o).split("\n"), return_object=True)
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_data = ret
                    o.last_update_state = str(ret.get("success", False))
                    if ret["response"] and isinstance(ret["response"], dict):
                        o.source_id = ret["response"]["id"]
                        o.source_data = json.dumps(ret["response"])
                        append_log(log, "ise_monitor::digest_database_data::Push SGACL update", o.source_id,
                                   o.acl.cleaned_name(), o.acl.description, ret)
                    else:     # pragma: no cover
                        append_log(log, "ise_monitor::digest_database_data::SGACL Invalid Return", ret)
                        o.update_failed = True
                        o.last_update_state = "False"
                        o.last_update_data = {"acl": str(o), "error": "SGACL Invalid Return"}
                    o.save()
                except Exception as e:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGACL Update Exception", e,
                               traceback.format_exc())
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"acl": str(o), "error": "Exception: " + str(e)}
                    o.save()
        elif o.update_dest() == "ise":
            try:
                ret = ise.add_sgacl(o.acl.cleaned_name(), o.acl.description, o.lookup_version(o),
                                    o.lookup_rules(o).split("\n"), return_object=True)
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                if ret["response"] and isinstance(ret["response"], dict):
                    o.source_id = ret["response"]["id"]
                    o.source_data = json.dumps(ret["response"])
                    append_log(log, "ise_monitor::digest_database_data::Push SGACL create", o.acl.cleaned_name(),
                               o.acl.description, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::SGACL Null Return", ret)
                    o.update_failed = True
                    o.last_update_state = "False"
                    o.last_update_data = {"acl": str(o), "error": "SGACL Null Return"}
                o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::SGACL Create Exception", e, traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"acl": str(o), "error": "Exception: " + str(e)}
                o.save()

    policies = PolicyData.objects.filter(Q(policy__do_sync=True) & Q(update_failed=False)).exclude(iseserver=None)
    for o in policies:
        if o.source_id and not o.policy.push_delete and o.update_dest() == "ise":
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
                    o.last_update_data = {"policy": str(o), "error": "ISE Update: Unable to locate sgt/sgacl data;" +
                                                                     str(srcsgt) + ";" + str(dstsgt) + ";" + str(sgacl)}
                    o.save()
                    continue

                ret = ise.update_egressmatrixcell(o.source_id, srcsgt.source_id, dstsgt.source_id,
                                                  o.lookup_acl_catchall(o),
                                                  acls=acls, description=o.policy.description,
                                                  return_object=True)
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                if ret["response"] and isinstance(ret["response"], dict):
                    o.source_id = ret["response"]["id"]
                    o.source_data = json.dumps(ret["response"])
                    append_log(log, "ise_monitor::digest_database_data::Push Policy update", o.source_id, o.policy.name,
                               o.policy.description, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::Policy Null Return", ret)
                    o.update_failed = True
                    o.last_update_state = "False"
                    o.last_update_data = {"policy": str(o), "error": "Policy Null Return"}
                o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::Policy Update Exception", e,
                           traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"policy": str(o), "error": "Exception: " + str(e)}
                o.save()
        elif o.update_dest() == "ise":
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
                    o.last_update_data = {"policy": str(o), "error": "ISE Create: Unable to locate sgt/sgacl data;" +
                                                                     str(srcsgt) + ";" + str(dstsgt) + ";" + str(sgacl)}
                    o.save()
                    continue

                ret = ise.add_egressmatrixcell(srcsgt.source_id, dstsgt.source_id, o.lookup_acl_catchall(o),
                                               acls=acls, description=o.policy.description,
                                               return_object=True)
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                if ret["response"] and isinstance(ret["response"], dict):
                    o.source_id = ret["response"]["id"]
                    o.source_data = json.dumps(ret["response"])
                    append_log(log, "ise_monitor::digest_database_data::Push Policy create", o.policy.name,
                               o.policy.description, ret)
                else:     # pragma: no cover
                    append_log(log, "ise_monitor::digest_database_data::Policy Null Return", ret)
                    o.update_failed = True
                    o.last_update_state = "False"
                    o.last_update_data = {"policy": str(o), "error": "Policy Null Return"}
                o.save()
            except Exception as e:     # pragma: no cover
                append_log(log, "ise_monitor::digest_database_data::Policy Create Exception", e, traceback.format_exc())
                o.update_failed = True
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_state = "False"
                o.last_update_data = {"policy": str(o), "error": "Exception: " + str(e)}
                o.save()


def sync_ise():
    log = []
    msg = "SYNC_ISE-NO_ACTION_REQUIRED"
    append_log(log, "ise_monitor::sync_ise::Checking ISE Accounts for re-sync...")

    # If we know that something needs to be created, do that first.
    sss = SyncSession.objects.all()
    for ss in sss:
        digest_database_data(ss, log)
        ss.iseserver.force_rebuild = True
        ss.save()
        msg = "SYNC_ISE-CHANGES_MADE_FORCE_UPDATE"

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

    # After ingesting data, more updates may be required (Should these have been caught elsewhere?)
    sss = SyncSession.objects.all()
    for ss in sss:
        digest_database_data(ss, log)

    append_log(log, "ise_monitor::sync_ise::Done")
    db_log("ise_monitor", log)
    return msg, log


def run():     # pragma: no cover
    print("sync_ise::run")
    sync_ise()


# @scheduler.scheduled_job("interval", seconds=10, id="ise_monitor")
# def job():     # pragma: no cover
#     sync_ise()
#
#
# if 'test' not in sys.argv and 'test' not in sys.argv[0]:     # pragma: no cover
#     register_events(scheduler)
#     scheduler.start()
