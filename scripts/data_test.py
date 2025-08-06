from sync.models import normalize_data_objects, GenericData, ElementSync
# import json


def run():
    lcount = 0
    l_dict = {}
    for ss in ElementSync.objects.all():
        lcount += 1
        l_dict[str(lcount)] = ss
        print("(" + str(lcount) + ") -- " + str(ss))
    print()
    sel_num = input("Enter the number of the Sync Session to evaluate: ")

    this_ss = l_dict[sel_num]
    # src = Generic.objects.filter(elementsync=this_ss)
    objs = GenericData.objects.filter(element=this_ss.src_element)
    # objs = GenericData.objects.all()
    out = normalize_data_objects(objs, this_ss)
    print(out)
    # print(json.dumps(o.source_data, indent=4))
