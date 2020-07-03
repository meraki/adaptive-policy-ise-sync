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


def db_log(logtype, logdata):
    try:
        ld = str("\n".join(logdata))
    except Exception:
        ld = str(logdata)

    t = Task.objects.filter(description=logtype)
    if len(t) > 0:
        t[0].task_data += "\n" + ld
        t[0].save()
    else:
        Task.objects.create(description=logtype, task_data=ld)
