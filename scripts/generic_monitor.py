from sync.models import GenericData, DataPipeline, Element, APICallTemplate
from django.utils.timezone import make_aware
import datetime
from scripts.dblog import append_log, db_log
# from django.conf import settings
# import traceback
import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


mod_name = "gen_monitor"


def make_api_call(api_template, url, element):
    headers = api_template.elementtype.static_headers
    if api_template.elementtype.auth_type == 1:
        headers = {api_template.elementtype.token_header_name: element.get_api_key()}
        req = requests.request(api_template.get_method_name(), url, headers=headers,
                               verify=False)
    else:
        username, password = element.get_auth_info()
        req = requests.request(api_template.get_method_name(), url,
                               auth=HTTPBasicAuth(username, password),
                               headers=headers, verify=False)
    return req


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


def ingest_generic_data(el, log):
    fn_name = "ingest_data"
    append_log(log, mod_name + "::" + fn_name + "::Element -", el)
    dt = make_aware(datetime.datetime.now())
    # Grab all API templates for GET (=2) for this elementtype
    api_get_call = APICallTemplate.objects.filter(action_type=2).filter(elementtype=el.elementtype).order_by("sequence")
    raw_data = {}
    for a in api_get_call:
        api_url = a.generate_url(None, element=el)
        attr_list = []
        attr_dict = {}
        # Wrap the API call function in a loop so that we can handle pagination if necessary
        while api_url is not None:
            append_log(log, mod_name + "::" + fn_name + "::API URL -", api_url)
            req = make_api_call(a, api_url, el)
            append_log(log, mod_name + "::" + fn_name + "::API Response -", str(req.status_code))
            # Drill down into the JSON if necessary to remove unnecessary outer keys
            try:
                resp = get_json_path(req.json(), a.parse_path)
            except json.decoder.JSONDecodeError:
                print("Exception parsing JSON. (Not JSON?)", el, req.status_code, req.content.decode("UTF-8"))
                break

            # Aggregate lists and dicts if we are paginating
            if isinstance(resp, list):
                attr_list += resp
            elif isinstance(resp, dict):
                attr_dict.update(resp)

            # This prepares the next URL if pagination is enabled
            if a.api_pagination == 3:
                api_url = get_json_path(req.json(), a.api_next_page_path)
            elif a.api_pagination == 2:
                api_url = req.links.get("next", {}).get("url")
            else:
                api_url = None

        # if needed, this flag will cycle through all elements in a list-get, calling each individually.
        # this is useful if a list-get doesn't return all details and you neeed to call the element
        # individually to get all of it's details
        if a.rerun_list_with_id:
            url = a.generate_url(None, element=el)
            new_list = []
            for attr_i in attr_list:
                req = make_api_call(a, url + "/" + attr_i.get("id"), el)
                resp = get_json_path(req.json(), a.rerun_parse_path)
                new_list.append(resp)
            attr_list = new_list

        # Base value depending on whether we are using a list or a dict
        attr = attr_list if len(attr_list) > 0 else attr_dict
        raw_data[str(a.generictype).lower()] = attr

    el.raw_data = raw_data
    el.last_read = dt
    el.save()


def process_generic_data(el, log):
    fn_name = "process_data"
    append_log(log, mod_name + "::" + fn_name + "::Element -", el)
    if el.raw_data:
        api_get_call = APICallTemplate.objects.filter(action_type=2).filter(elementtype=el.elementtype)
        for a in api_get_call:
            items = el.raw_data.get(str(a.generictype).lower())
            # print(el, len(items))
            # print(a, str(a.generictype).lower(), items)
            # if not items:
            #     append_log(log, mod_name + "::" + fn_name + "::Error processing items")
            #     continue
            find_id = a.id_field if a.id_field else "id"
            append_log(log, mod_name + "::" + fn_name + "::Processing", str(len(items)),
                       str(a.generictype).lower(), "items...")
            for i in items:
                if find_id[:1] == "_":
                    fake_id = find_id[1:]
                    for k in i:
                        fake_id = fake_id.replace("{{" + k + "}}", str(i[k]))
                    id_val = fake_id
                else:
                    id_val = i.get(find_id)
                GenericData.objects.update_or_create(source_id=id_val, element=el, generictype=a.generictype,
                                                     defaults={"source_data": i})


def run():     # pragma: no cover
    read_generic()


def run_generic_processing():
    fn_name = "run_processing"
    elements = Element.objects.all()
    for element in elements:
        log = []
        append_log(log, mod_name + "::" + fn_name + "::Processing Data from Elements...")
        # try:
        if element.needs_resync("last_processed"):
            process_generic_data(element, log)
            DataPipeline.objects.update_or_create(element=element, stage=2, defaults={"state": 5})

            dt = make_aware(datetime.datetime.now())
            element.last_processed = dt
            element.save()
            # except Exception:
            #     append_log(log, mod_name + "::" + fn_name + "::Exception caught:", traceback.format_exc())
            #     DataPipeline.objects.update_or_create(element=element, stage=2, defaults={"state": 4})
        else:
            append_log(log, mod_name + "::" + fn_name + "::Not time for re-sync; skipping.")

        append_log(log, mod_name + "::" + fn_name + "::Done")
        db_log(mod_name, log, element=element, append_old=False)


def run_generic_ingestion():
    fn_name = "run_ingestion"
    elements = Element.objects.all()
    for element in elements:
        log = []
        append_log(log, mod_name + "::" + fn_name + "::Reading Data from Elements...")
        if element.enabled:
            if element.needs_resync("last_read", skip_reset=True):
                DataPipeline.objects.update_or_create(element=element, stage=1, defaults={"state": 2})
                # try:
                ingest_generic_data(element, log)
                DataPipeline.objects.update_or_create(element=element, stage=1, defaults={"state": 5})
                # except Exception:
                #     append_log(log, mod_name + "::" + fn_name + "::Exception caught:", traceback.format_exc())
                #     DataPipeline.objects.update_or_create(element=element, stage=1, defaults={"state": 4})

                dt = make_aware(datetime.datetime.now())
                element.last_read = dt
                element.save()
            else:
                append_log(log, mod_name + "::" + fn_name + "::Not time for re-sync; skipping.")
        else:
            element.raw_data = element.iseserver.raw_data if element.iseserver else element.organization.raw_data
            element.save()
            append_log(log, mod_name + "::" + fn_name + "::This account is disabled; skipping.")
            DataPipeline.objects.update_or_create(element=element, stage=1, defaults={"state": 3})

        append_log(log, mod_name + "::" + fn_name + "::Done")
        db_log(mod_name, log, element=element, append_old=False)


def read_generic(data=None):
    run_generic_ingestion()
    run_generic_processing()
