import datetime
from sync.models import Task
dodebug = False


def append_log(log, *data):
    if log is None:
        log = []
    if not isinstance(log, list):
        log = [log]

    if (isinstance(data, list) or isinstance(data, tuple)) and len(data) > 1:
        if dodebug:
            print(data)
        ldata = ""
        for ld in data:
            ldata += str(ld) + " "
        log.append(datetime.datetime.now().isoformat() + " - " + ldata)
    else:
        if dodebug:
            print(data[0])
        log.append(datetime.datetime.now().isoformat() + " - " + str(data[0]))


def db_log(logtype, logdata, iseserver=None, organization=None, syncsession=None, element=None, elementsync=None,
           append_old=True):
    try:
        ld = str("\n".join(logdata))
    except Exception:
        ld = str(logdata)

    if iseserver:
        t = Task.objects.filter(description=logtype, iseserver=iseserver)
    elif organization:
        t = Task.objects.filter(description=logtype, organization=organization)
    elif syncsession:
        t = Task.objects.filter(description=logtype, syncsession=syncsession)
    elif elementsync:
        t = Task.objects.filter(description=logtype, elementsync=elementsync)
    elif element:
        t = Task.objects.filter(description=logtype, element=element)
    else:
        t = Task.objects.filter(description=logtype)
    if len(t) > 0 and append_old:
        t[0].task_data += "\n" + ld
        t[0].save()
    else:
        if iseserver:
            Task.objects.create(description=logtype, iseserver=iseserver, task_data=ld)
        elif organization:
            Task.objects.create(description=logtype, organization=organization, task_data=ld)
        elif syncsession:
            Task.objects.create(description=logtype, syncsession=syncsession, task_data=ld)
        elif elementsync:
            Task.objects.create(description=logtype, elementsync=elementsync, task_data=ld)
        elif element:
            Task.objects.create(description=logtype, element=element, task_data=ld)
        else:
            Task.objects.create(description=logtype, task_data=ld)
