from sync.models import SyncSession, TagData, ACLData, PolicyData, ISEServer, DataPipeline
from django.db.models import F, Q
from django.utils.timezone import make_aware
import json
import datetime
from scripts.db_trustsec import clean_sgts, clean_sgacls, clean_sgpolicies, merge_sgts, merge_sgacls, \
    merge_sgpolicies, parse_sgt_data, parse_sgacl_data, parse_sgpolicy_data, clean_sgt_data, clean_sgacl_data, \
    clean_sgpolicy_data
from scripts.dblog import append_log, db_log
from ise import ERS
import traceback


def new_ingest_ise_data(server, log):
    append_log(log, "ise_monitor::new_ingest_ise_data::Server -", server)
    dt = make_aware(datetime.datetime.now())

    append_log(log, "ise_monitor::new_ingest_ise_data::Resync -", server.description)
    ise = ERS(ise_node=server.ipaddress, ers_user=server.username, ers_pass=server.password, verify=False,
              disable_warnings=True)
    sgts = ise.get_sgts(detail=True)
    sgacls = ise.get_sgacls(detail=True)
    sgpolicies = ise.get_egressmatrixcells(detail=True)
    append_log(log, "ise_monitor::new_ingest_ise_data::SGTs - ", len(sgts))
    append_log(log, "ise_monitor::new_ingest_ise_data::SGACLs - ", len(sgacls))
    append_log(log, "ise_monitor::new_ingest_ise_data::Policies - ", len(sgpolicies))
    ise = {"sgts": sgts, "sgacls": sgacls, "sgpolicies": sgpolicies}

    server.raw_data = ise
    server.force_rebuild = False
    server.last_read = dt
    server.skip_sync = True
    server.skip_update = True
    server.save()


def process_ise_data(server, log):
    if server.raw_data:
        parse_sgt_data("ise", server, server.raw_data["sgts"].get("response"), log)
        parse_sgacl_data("ise", server, server.raw_data["sgacls"].get("response"), log)
        parse_sgpolicy_data("ise", server, server.raw_data["sgpolicies"].get("response"), log)

        clean_sgt_data("ise", server, server.raw_data["sgts"].get("response"), log)
        clean_sgacl_data("ise", server, server.raw_data["sgacls"].get("response"), log)
        clean_sgpolicy_data("ise", server, server.raw_data["sgpolicies"].get("response"), log)


def ingest_ise_data(accounts, log, server_only=False):
    append_log(log, "ise_monitor::ingest_server_data::Accounts -", accounts)
    dt = make_aware(datetime.datetime.now())

    for sync_account in accounts:
        if not server_only:
            if not sync_account.sync_enabled:
                append_log(log, "ise_monitor::ingest_server_data::sync session not set to allow sync;")
                return

            ise = None
            a = sync_account.iseserver
            src = sync_account.ise_source
            sa = sync_account
        else:
            a = sync_account
            src = False
            sa = None

        append_log(log, "ise_monitor::ingest_server_data::Resync -", a.description)
        ise = ERS(ise_node=a.ipaddress, ers_user=a.username, ers_pass=a.password, verify=False, disable_warnings=True)
        sgts = ise.get_sgts(detail=True)
        sgacls = ise.get_sgacls(detail=True)
        sgpolicies = ise.get_egressmatrixcells(detail=True)
        append_log(log, "ise_monitor::ingest_server_data::SGTs - ", len(sgts))
        append_log(log, "ise_monitor::ingest_server_data::SGACLs - ", len(sgacls))
        append_log(log, "ise_monitor::ingest_server_data::Policies - ", len(sgpolicies))
        ise = {"sgts": sgts, "sgacls": sgacls, "sgpolicies": sgpolicies}

        merge_sgts("ise", sgts["response"], src, sa, log, a)
        merge_sgacls("ise", sgacls["response"], src, sa, log, a)
        merge_sgpolicies("ise", sgpolicies["response"], src, sa, log, a)

        clean_sgts("ise", sgts["response"], src, sa, log, a)
        clean_sgacls("ise", sgacls["response"], src, sa, log, a)
        clean_sgpolicies("ise", sgpolicies["response"], src, sa, log, a)

        a.raw_data = ise
        a.force_rebuild = False
        a.last_sync = dt
        a.last_update = dt
        a.skip_sync = True
        a.skip_update = True
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
                                                  acls=acls, description=o.lookup_description(o),
                                                  return_object=True)
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                if ret["response"] and isinstance(ret["response"], dict):
                    o.source_id = ret["response"]["id"]
                    o.source_data = json.dumps(ret["response"])
                    append_log(log, "ise_monitor::digest_database_data::Push Policy update", o.source_id, o.policy.name,
                               o.lookup_description(o), ret)
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
                    o.update_failed = True
                    o.last_update = make_aware(datetime.datetime.now())
                    o.last_update_state = "False"
                    o.last_update_data = {"policy": str(o), "error": "ISE Create: Unable to locate sgt/sgacl data;" +
                                                                     str(srcsgt) + ";" + str(dstsgt) + ";" + str(sgacl)}
                    o.save()
                    continue

                ret = ise.add_egressmatrixcell(srcsgt.source_id, dstsgt.source_id, o.lookup_acl_catchall(o),
                                               acls=acls, description=o.lookup_description(o),
                                               return_object=True)
                o.last_update = make_aware(datetime.datetime.now())
                o.last_update_data = ret
                o.last_update_state = str(ret.get("success", False))
                if ret["response"] and isinstance(ret["response"], dict):
                    o.source_id = ret["response"]["id"]
                    o.source_data = json.dumps(ret["response"])
                    append_log(log, "ise_monitor::digest_database_data::Push Policy create", o.policy.name,
                               o.lookup_description(o), ret)
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

    no_ss = ISEServer.objects.filter(syncsession__isnull=True)
    append_log(log, "ise_monitor::sync_ise::Servers not in session...", no_ss)
    ingest_ise_data(no_ss, log, server_only=True)

    # If we know that something needs to be created, do that first.
    sss = SyncSession.objects.all()
    for ss in sss:
        digest_database_data(ss, log)
        ss.iseserver.force_rebuild = True
        ss.iseserver.skip_update = True
        ss.iseserver.save()
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
                    d.iseserver.skip_update = True
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
    # print("sync_ise::run")
    # sync_ise()
    read_ise()


def run_ise_processing():
    servers = ISEServer.objects.all()
    for server in servers:
        log = []
        append_log(log, "ise_monitor::run_ise_processing::Parsing data into individual elements...")
        try:
            process_ise_data(server, log)
            DataPipeline.objects.update_or_create(iseserver=server, stage=2, defaults={"state": 5})

            dt = make_aware(datetime.datetime.now())
            server.last_processed = dt
            server.save()
        except Exception:
            append_log(log, "ise_monitor::run_ise_processing::Exception caught:", traceback.format_exc())
            DataPipeline.objects.update_or_create(iseserver=server, stage=2, defaults={"state": 4})

        append_log(log, "ise_monitor::run_ise_processing::Done")
        db_log("ise_monitor", log, iseserver=server, append_old=False)


def run_ise_ingestion():
    servers = ISEServer.objects.all()
    for server in servers:
        log = []
        append_log(log, "ise_monitor::run_ise_ingestion::Checking ISE Accounts for re-sync...")
        if server.enabled:
            DataPipeline.objects.update_or_create(iseserver=server, stage=1, defaults={"state": 2})
            try:
                new_ingest_ise_data(server, log)
                DataPipeline.objects.update_or_create(iseserver=server, stage=1, defaults={"state": 5})
            except Exception:
                append_log(log, "ise_monitor::run_ise_ingestion::Exception caught:", traceback.format_exc())
                DataPipeline.objects.update_or_create(iseserver=server, stage=1, defaults={"state": 4})
                continue

            dt = make_aware(datetime.datetime.now())
            server.last_read = dt
            server.save()
        else:
            append_log(log, "ise_monitor::run_ise_ingestion::This server is disabled; skipping.")
            DataPipeline.objects.update_or_create(iseserver=server, stage=1, defaults={"state": 3})

        append_log(log, "ise_monitor::run_ise_ingestion::Done")
        db_log("ise_monitor", log, iseserver=server, append_old=False)


def read_ise(data=None):
    run_ise_ingestion()
    run_ise_processing()
