from sync.models import DataPipeline, ElementSync, GenericData
from scripts.dblog import append_log, db_log
from django.utils.timezone import make_aware
import datetime
# import traceback
# import requests
from requests.auth import HTTPBasicAuth
import requests
requests.urllib3.disable_warnings()


mod_name = "push_monitor"


def get_json_path(json_body, parse_path):
    """
    This function will walk down a dot separated JSON path to return only the data
    at the tail of the path
    """

    # If no path was specified, or if we aren't working with a dict, return the full blob
    if not parse_path or not isinstance(json_body, dict):
        return json_body

    # Make a copy of the data structure
    new_json_body = {**json_body}
    parse_list = parse_path.split(".")
    for p in parse_list:
        if p in new_json_body:
            new_json_body = new_json_body[p]
        else:
            return None
    return new_json_body


def make_api_call(api_call_details, log):
    fn_name = "make_api_call"
    method = api_call_details[0]
    url = api_call_details[1]
    data = api_call_details[2]
    auth = api_call_details[3]
    headers = api_call_details[4]
    second_run = api_call_details[5]
    second_run_parse = api_call_details[6]
    generic = api_call_details[7]
    element = api_call_details[8]
    api_template = api_call_details[9]

    if generic.err_disabled:
        append_log(log, mod_name + "::" + fn_name + "::ERR_DISABLED; Skipping:", generic)
        return None, None, generic, element, None

    if auth:
        req = requests.request(method, url, auth=HTTPBasicAuth(auth[0], auth[1]),
                               headers=headers, json=data, verify=False)
    else:
        req = requests.request(method, url, headers=headers, json=data,
                               verify=False)

    try:
        data_out = req.json()
    except Exception:
        data_out = req.content.decode("utf-8")

    # if needed, this flag will cycle through all elements in a list-get, calling each individually.
    # this is useful if a list-get doesn't return all details and you neeed to call the element
    # individually to get all of it's details
    if req.ok and second_run:
        if req.status_code == 201:
            new_url = req.headers.get("Location")
        else:
            new_url = url
        _, d_out, _, _, _ = make_api_call(("GET", new_url, None, auth, headers, None, None, generic, element,
                                           api_template), log)
        data_out = get_json_path(d_out, second_run_parse)
        new_id = new_url.split("/")[-1]
    elif req.ok and api_template.id_field:
        find_id = api_template.id_field
        if find_id[:1] == "_":
            fake_id = find_id[1:]
            for k in data_out:
                fake_id = fake_id.replace("{{" + k + "}}", str(data_out[k]))
            id_val = fake_id
        else:
            id_val = data_out.get(find_id)

        # new_id = data_out[api_template.id_field]
        new_id = id_val
        # print("1", api_template.id_field, new_id)
    else:
        new_id = None

    return req, data_out, generic, element, new_id


def process_api_changes(api_change_list, log):
    fn_name = "process_api_changes"
    for api_calls in api_change_list:
        set_disabled = False
        active_generic = None
        history_content = ""
        for api_call in api_calls:
            if api_call[0] == "ERROR":
                append_log(log, mod_name + "::" + fn_name + "::Unable to process:", api_call)
                continue

            req_obj, body, generic, element, source_id = make_api_call(api_call, log)
            active_generic = generic
            if req_obj is None:
                continue

            # print(api_call, code, msg)
            append_log(log, mod_name + "::" + fn_name + "::API Call Result", req_obj.status_code, body)

            if not req_obj.ok:
                set_disabled = True
            history_content += str(element) + "::" + str(body) + "\n"

            dt = make_aware(datetime.datetime.now())
            generic.last_api_push = dt
            generic.save()

            if source_id:
                GenericData.objects.update_or_create(source_id=source_id, element=element,
                                                     generictype=generic.generictype,
                                                     defaults={"generic": generic, "source_data": body})

        active_generic.check_for_update()
        if active_generic.update_history:
            active_generic.update_history += history_content
        else:
            active_generic.update_history = history_content
        if set_disabled:
            active_generic.err_disabled = True
        active_generic.save()


def run():     # pragma: no cover
    sync_push()


def run_push_check():
    fn_name = "run_push_check"
    syncs = ElementSync.objects.all()
    for sync in syncs:
        log = []
        append_log(log, mod_name + "::" + fn_name + "::Checking Sync Sessions...")
        if sync.enabled:
            needs_update, updates = sync.needs_update()
            append_log(log, mod_name + "::" + fn_name + "::Needed updates:", needs_update)      # remove updates
            # process_api_changes(updates, log)
            # break
            if sync.apply_changes:
                if needs_update:
                    obj, _ = DataPipeline.objects.update_or_create(element=sync.src_element, stage=4,
                                                                   defaults={"state": 2})
                    # try:
                    process_api_changes(updates, log)
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
                append_log(log, mod_name + "::" + fn_name + "::This account won't push changes; skipping.")
                DataPipeline.objects.update_or_create(element=sync.src_element, stage=4,
                                                      defaults={"state": 3})
        else:
            append_log(log, mod_name + "::" + fn_name + "::This account is disabled; skipping.")
            DataPipeline.objects.update_or_create(element=sync.src_element, stage=4,
                                                  defaults={"state": 3})

        append_log(log, mod_name + "::" + fn_name + "::Done")
        db_log(mod_name, log, elementsync=sync, append_old=False)


def sync_push(data=None):
    run_push_check()
