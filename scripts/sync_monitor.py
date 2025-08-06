from sync.models import DataPipeline, ElementSync, GenericData, Generic
# from sync.models import SyncSession, TagData, ACLData, PolicyData, Tag, ACL, Policy
from scripts.dblog import append_log, db_log
from django.utils.timezone import make_aware
import datetime
import traceback
from django.db.models import Q


mod_name = "sync_monitor"


def calculate_sync_objects(sync, log):
    tags = []
    acls = []
    pols = []
    origin = None
    src = None
    if sync.src_iseserver:
        src = sync.src_iseserver
        origin = "origin_ise"
        tags = TagData.objects.filter(iseserver=src)
        acls = ACLData.objects.filter(iseserver=src)
        pols = PolicyData.objects.filter(iseserver=src)
    elif sync.src_organization:
        src = sync.src_organization
        origin = "origin_org"
        tags = TagData.objects.filter(organization=src)
        acls = ACLData.objects.filter(organization=src)
        pols = PolicyData.objects.filter(organization=src)

    append_log(log, mod_name + "::calculate_sync_objects::Syncing", str(len(tags)), "tags...")
    for o in tags:
        v, _ = Tag.objects.update_or_create(tag_number=o.get_data("value"), syncsession=sync,
                                            defaults={"name": o.get_data("name"),
                                                      "description": o.get_data("description"), origin: src})
        o.tag = v
        o.save()
        associate_dest_items(sync, log, sgt=v)

    append_log(log, mod_name + "::calculate_sync_objects::Syncing", str(len(acls)), "acls...")
    for o in acls:
        v, _ = ACL.objects.update_or_create(name=o.get_data("name"), syncsession=sync,
                                            defaults={"description": o.get_data("description"), origin: src})
        o.acl = v
        o.save()
        associate_dest_items(sync, log, sgacl=v)

    append_log(log, mod_name + "::calculate_sync_objects::Syncing", str(len(acls)), "policies...")
    for o in pols:
        v, _ = Policy.objects.update_or_create(mapping=o.get_data("mapping"), syncsession=sync,
                                               defaults={"description": o.get_data("description"), origin: src,
                                                         "name": o.get_data("name"),
                                                         "source_group": o.get_data("sourcetag"),
                                                         "dest_group": o.get_data("desttag")})
        v.acl.add(*o.get_data("acl"))
        v.save()
        o.policy = v
        o.save()
        associate_dest_items(sync, log, sgpolicy=v)


def calculate_gen_sync_objects(sync, log):
    fn_name = "calc_sync_objs"
    src = sync.src_element
    auto_enabled = sync.auto_sync_new
    objs = GenericData.objects.filter(element=src)

    append_log(log, mod_name + "::" + fn_name + "::Syncing", str(len(objs)), "objects...")
    for o in objs:
        sig_key = o.generictype.significant_name_key
        sig_desc = o.generictype.significant_key_label
        sig_val = o.get_data(sig_key)
        def_val = sig_desc + " " + str(sig_val)
        v, created = Generic.objects.update_or_create(key_value=sig_val, elementsync=sync, generictype=o.generictype,
                                                      defaults={"name": o.get_data("name", default_val=sig_val),
                                                                "description": o.get_data("description",
                                                                                          default_val=def_val),
                                                                "element": src})
        if created and auto_enabled:
            v.do_sync = True
            v.save()

        o.generic = v
        o.save()
        associate_gen_dest_items(sync, log, elm=v, elmdata=o)


def associate_dest_items(sync, log, sgt=None, sgacl=None, sgpolicy=None):
    tags = []
    acls = []
    pols = []
    for d in sync.dst_iseserver.all():
        if sgt:
            append_log(log, mod_name + "::associate_dest_items::Checking for ISE destination SGTs for", sgt, "...")
            tags = TagData.objects.filter(iseserver=d).filter(source_data__value=sgt.tag_number)
            append_log(log, mod_name + "::associate_dest_items::count=", len(tags))
            for v in tags:
                v.tag = sgt
                v.save()
        if sgacl:
            append_log(log, mod_name + "::associate_dest_items::Checking for ISE destination SGACLs for", sgacl, "...")
            acls = ACLData.objects.filter(iseserver=d)
            append_log(log, mod_name + "::associate_dest_items::count=", len(acls))
            for v in acls:
                if v.cleaned_name() == sgacl.cleaned_name():
                    v.acl = sgacl
                    v.save()
        if sgpolicy:
            append_log(log, mod_name + "::associate_dest_items::Checking for ISE destination Policies for", sgpolicy,
                       "...")
            pols = PolicyData.objects.filter(iseserver=d)
            append_log(log, mod_name + "::associate_dest_items::count=", len(pols))
            for v in pols:
                if v.get_data("mapping") == sgpolicy.mapping:
                    v.policy = sgpolicy
                    v.save()

    for d in sync.dst_organization.all():
        if sgt:
            append_log(log, mod_name + "::associate_dest_items::Checking for Meraki destination SGTs for", sgt, "...")
            tags = TagData.objects.filter(organization=d).filter(source_data__value=sgt.tag_number)
            append_log(log, mod_name + "::associate_dest_items::count=", len(tags))
            for v in tags:
                v.tag = sgt
                v.save()
        if sgacl:
            append_log(log, mod_name + "::associate_dest_items::Checking for Meraki destination SGACLs for", sgacl,
                       "...")
            acls = ACLData.objects.filter(organization=d).filter(source_data__name=sgacl.name)
            append_log(log, mod_name + "::associate_dest_items::count=", len(acls))
            for v in acls:
                v.acl = sgacl
                v.save()
        if sgpolicy:
            append_log(log, mod_name + "::associate_dest_items::Checking for Meraki destination Policies for", sgacl,
                       "...")
            pols = PolicyData.objects.filter(organization=d).filter(source_data__mapping=sgpolicy.mapping)
            append_log(log, mod_name + "::associate_dest_items::count=", len(pols))
            for v in pols:
                v.policy = sgpolicy
                v.save()


def associate_gen_dest_items(sync, log, elm=None, elmdata=None):
    fn_name = "assoc_dest_objs"
    for d in sync.dst_element.all():
        if elm:
            append_log(log, mod_name + "::" + fn_name + "::Checking for Element destination Objects for", elm, "...")
            sig_key = elm.generictype.significant_name_key
            sig_val = elmdata.get_data(sig_key, safe=False)
            sig_val_2 = elmdata.get_data(sig_key, safe=True)
            if "::" in sig_key:
                sig_list = sig_key.split("::")
                sig_key = sig_list[2]
                my_filter = {"source_data__" + sig_key + "__iexact": sig_val}
                my_filter_2 = {"source_data__" + sig_key + "__iexact": sig_val_2}
            else:
                my_filter = {"source_data__" + sig_key: sig_val}
                my_filter_2 = {"source_data__" + sig_key: sig_val_2}
            objs = GenericData.objects.filter(element=d).filter(Q(**my_filter) | Q(**my_filter_2))
            # print(my_filter, objs)
            append_log(log, mod_name + "::" + fn_name + "::count=", len(objs))
            objs.update(generic=elm)
            # for v in objs:
            #     v.generic = elm
            #     v.save()


def run():     # pragma: no cover
    monitor_sync()


def run_sync_check():
    syncs = SyncSession.objects.all()
    for sync in syncs:
        log = []
        append_log(log, mod_name + "::run_sync_check::Checking Sync Sessions...")
        if sync.src_element:
            if sync.enabled:
                obj = None
                # if sync.src_iseserver:
                #     obj, _ = DataPipeline.objects.update_or_create(iseserver=sync.src_iseserver, stage=3,
                #                                                    defaults={"state": 2})
                # elif sync.src_organization:
                #     obj, _ = DataPipeline.objects.update_or_create(organization=sync.src_organization, stage=3,
                #                                                    defaults={"state": 2})
                obj, _ = DataPipeline.objects.update_or_create(element=sync.src_element, stage=3,
                                                               defaults={"state": 2})

                try:
                    calculate_sync_objects(sync, log)
                    obj.state = 5
                    obj.save()
                except Exception:
                    append_log(log, mod_name + "::run_sync_check::Exception caught:", traceback.format_exc())
                    obj.state = 4
                    obj.save()

                dt = make_aware(datetime.datetime.now())
                sync.last_read = dt
                sync.last_processed = dt
                sync.save()
            else:
                append_log(log, mod_name + "::run_sync_check::This account is disabled; skipping.")
                # if sync.src_iseserver:
                #     DataPipeline.objects.update_or_create(iseserver=sync.src_iseserver, stage=3,
                #                                           defaults={"state": 3})
                # elif sync.src_organization:
                #     DataPipeline.objects.update_or_create(organization=sync.src_organization, stage=3,
                #                                           defaults={"state": 3})
                obj, _ = DataPipeline.objects.update_or_create(element=sync.src_element, stage=3,
                                                               defaults={"state": 3})
        else:
            append_log(log, mod_name + "::run_sync_check::Missing source element!")

        append_log(log, mod_name + "::run_sync_check::Done")
        db_log(mod_name, log, syncsession=sync, append_old=False)


def run_sync_gen_check():
    fn_name = "run_sync"
    syncs = ElementSync.objects.all()
    for sync in syncs:
        log = []
        append_log(log, mod_name + "::" + fn_name + "::Checking Sync Sessions...")
        if sync.src_element:
            if sync.enabled:
                # due_barrier_time = make_aware(datetime.datetime.now()) -datetime.timedelta(seconds=sync.sync_interval)
                # if not sync.last_read or sync.last_read < due_barrier_time:
                if sync.needs_resync("last_processed"):
                    obj, _ = DataPipeline.objects.update_or_create(element=sync.src_element, stage=3,
                                                                   defaults={"state": 2})
                    # try:
                    calculate_gen_sync_objects(sync, log)
                    obj.state = 5
                    obj.save()
                    # except Exception:
                    #     append_log(log, mod_name + "::" + fn_name + "::Exception caught:", traceback.format_exc())
                    #     obj.state = 4
                    #     obj.save()

                    dt = make_aware(datetime.datetime.now())
                    sync.last_read = dt
                    sync.last_processed = dt
                    sync.save()
                else:
                    append_log(log, mod_name + "::" + fn_name + "::Not time for re-sync; skipping.")
            else:
                append_log(log, mod_name + "::" + fn_name + "::This account is disabled; skipping.")
                if sync.src_element:
                    DataPipeline.objects.update_or_create(element=sync.src_element, stage=3,
                                                          defaults={"state": 3})
        else:
            append_log(log, mod_name + "::" + fn_name + "::Missing source element!")

        append_log(log, mod_name + "::" + fn_name + "::Done")
        db_log(mod_name, log, elementsync=sync, append_old=False)


def monitor_sync(data=None):
    # run_sync_check()
    run_sync_gen_check()
