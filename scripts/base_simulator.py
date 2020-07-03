from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
import json
import os
import uuid
import string
import random


def string_num_generator(size):
    chars = string.digits
    return ''.join(random.choice(chars) for _ in range(size))


def string_generator(size):
    chars = string.digits + string.ascii_uppercase + string.ascii_lowercase
    return ''.join(random.choice(chars) for _ in range(size))


def write_file(out_filename, content):
    with open(os.path.join("scripts", out_filename), 'w') as out_file:
        out_file.write(content)


def read_file(in_filename):
    with open(os.path.join("scripts", in_filename), 'r+') as in_file:
        return in_file.read().splitlines()


def read_file_all(in_filename):
    with open(os.path.join("scripts", in_filename), 'r+') as in_file:
        return in_file.read()


def fix_urls(json_txt, baseurl):
    return json.loads(json.dumps(json_txt).replace("{{url}}", baseurl))


def handle_request(method, postdata, baseurl, endpoint, elem_id, dataset, fixedvals, postvals, info):
    out_data = {}
    if postdata is None:
        postdata = {}
    r = {}, HttpResponseBadRequest("An Error Ocurred")
    if method == 'POST' or method == 'PUT' or method == 'DELETE':
        # If data has headers, unwrap headers to get raw data
        chkhead = info.get(endpoint, {}).get("single_header", None)

        if chkhead:
            datain = datapos = {**chkhead}
            headtest = chkhead
            while isinstance(headtest, dict):
                for k, v in headtest.items():
                    if isinstance(v, dict):
                        datapos = datapos[k]
                    headtest = v
                    if v == "{{results}}":
                        datain = postdata.get(k, {})
        else:
            datain = postdata

        # Now, iterate raw data structure to get incoming data
        for post_keys in postvals[endpoint]:
            postvals[endpoint][post_keys] = datain.get(post_keys, None)

        # Prepare fixed values with any variables
        u = str(uuid.uuid4())
        ftxt = json.dumps({**fixedvals[endpoint]})
        ftxt = ftxt.replace("{{url}}", baseurl)
        ftxt = ftxt.replace("{{uuid}}", u)
        if ftxt.find("{{id") > 0:
            while ftxt.find("{{id") > 0:
                idstart = ftxt.find("{{id")
                idend = ftxt.find("}}", idstart)
                idarr = ftxt[idstart + 5:idend].split(":")
                if idarr[0] == "num":
                    newid = string_num_generator(int(idarr[1]))
                elif idarr[0] == "mix":
                    newid = string_generator(int(idarr[1]))
                else:
                    newid = str(uuid.uuid4())

                ftxt = ftxt.replace(ftxt[idstart:idend+2], newid)
        updated_fixed_vals = json.loads(ftxt)

        # If there are unique key constraints (see 'info' above), iterate the data set to get a list of all
        #  current values, which will be appended to 'info'
        if "unique" in info[endpoint]:
            for unique_num in range(0, len(info[endpoint]["unique"])):
                uname = list(info[endpoint]["unique"][unique_num].keys())[0]
                for dataset_record in range(0, len(dataset)):
                    if str(elem_id) != str(dataset[dataset_record][info[endpoint]["id"]]):
                        info[endpoint]["unique"][unique_num][uname].append(dataset[dataset_record][uname])

        # Iterate all records in the dataset
        for dataset_record in range(0, len(dataset)):
            # Conduct uniqueness test if necessary
            if method == 'PUT' or method == 'POST':
                for post_keys in postvals[endpoint]:
                    if "unique" in info[endpoint]:
                        for unique_num in range(0, len(info[endpoint]["unique"])):
                            uname = list(info[endpoint]["unique"][unique_num].keys())[0]
                            if (post_keys == uname) and \
                                    (postvals[endpoint][post_keys] in info[endpoint]["unique"][unique_num][uname]):
                                return None, HttpResponseBadRequest(
                                    json.dumps({"errors": ["Value has already been taken"]}, indent=4))

            # Handle PUT/DELETE (if they have a trailing ID in the URL)
            if elem_id and info[endpoint].get("id", "id") in dataset[dataset_record]:
                if str(elem_id) == str(dataset[dataset_record][info[endpoint]["id"]]):
                    if method == 'PUT':
                        for post_keys in postvals[endpoint]:
                            dataset[dataset_record][post_keys] = postvals[endpoint][post_keys]
                        out_data = dataset[dataset_record]
                    elif method == 'DELETE':
                        del dataset[dataset_record]
                        return dataset, HttpResponse("", status=204)
                    break
            elif method == 'PUT':
                # PUT without ID... first step is to decide whether this is existing record or new record...
                # so, make a list of existing records and put it in info[endpoint]["unique_results"]
                chkputlst = info.get(endpoint, {}).get("put_unique", None)
                fake_lst = []
                for chkputu in chkputlst:
                    fake_lst.append(str(dataset[dataset_record][chkputu]))
                info[endpoint]["unique_results"].append({"-".join(fake_lst): dataset[dataset_record]})

        # PUT without ID... Now, determine what the submitted "id" is...
        chkputlst = info.get(endpoint, {}).get("put_unique", None)
        if chkputlst:
            post_lst = []
            for chkputu in chkputlst:
                post_lst.append(str(postdata[chkputu]))
            fake_id = "-".join(post_lst)
            matches = next((item for item in info[endpoint]["unique_results"] if list(item.keys())[0] == fake_id), None)
            unmatches = list(item for item in info[endpoint]["unique_results"] if list(item.keys())[0] != fake_id)
            original_list = []
            for un in unmatches:
                original_list.append(un[list(un.keys())[0]])

            do_delete = False
            if matches:
                none_delete = info.get(endpoint, {}).get("none_as_delete_key", None)
                for post_keys in postvals[endpoint]:
                    if none_delete and none_delete == post_keys and postvals[endpoint][post_keys] is None:
                        do_delete = True
                    matches[fake_id][post_keys] = postvals[endpoint][post_keys]
                if do_delete:
                    return original_list, JsonResponse(fix_urls(matches[fake_id], baseurl), safe=False)
                else:
                    out_data = original_list + [matches[fake_id]]
                    return out_data, JsonResponse(fix_urls(matches[fake_id], baseurl), safe=False)
            else:
                newpostdata = {**postvals[endpoint], **updated_fixed_vals}
                out_data = original_list + [newpostdata]
                return out_data, JsonResponse(fix_urls(newpostdata, baseurl), safe=False)

        # Construct json for POST based on 'fixedvals' and 'postvals'.
        if method == 'POST':
            newpostdata = {**postvals[endpoint], **updated_fixed_vals}
            for k, v in newpostdata.items():
                if v == "{{length}}":
                    newpostdata[k] = len(dataset)

            out_data = newpostdata
            dataset.append(newpostdata)

        r = dataset, JsonResponse(fix_urls(out_data, baseurl), safe=False)
    else:
        # Iterate all records in the dataset
        tempdata = {}
        if elem_id:
            chkhead = info.get(endpoint, {}).get("single_header", None)
            for dataset_record in range(0, len(dataset)):
                # Look for matching record
                if ("id" in info[endpoint]) and (str(elem_id) == str(dataset[dataset_record][info[endpoint]["id"]])):
                    tempdata = {**dataset[dataset_record]}
                    break
        else:
            chkhead = info.get(endpoint, {}).get("multi_header", None)
            # Some GET all / list endpoints only show certain fields. Trim the ones that shouldn't be there.
            chkfields = info.get(endpoint, {}).get("list_get_fields", None)
            if chkfields:
                tempdata = []
                for t in dataset:
                    outf = {}
                    for f in t:
                        if f in chkfields:
                            outf[f] = t[f]
                    tempdata.append(outf)
            else:
                tempdata = dataset[:]

        if chkhead:
            dataout = datapos = {**chkhead}
            headtest = chkhead
            while isinstance(headtest, dict):
                for k, v in headtest.items():
                    if isinstance(v, dict):
                        datapos = datapos[k]
                    headtest = v
                    if v == "{{length}}":
                        datapos[k] = len(tempdata)
                    if v == "{{results}}":
                        datapos[k] = tempdata
        else:
            dataout = tempdata

        r = None, JsonResponse(fix_urls(dataout, baseurl), safe=False)

    return r
