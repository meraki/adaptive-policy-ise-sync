from sync.models import ACL, Tag, Policy, Dashboard, SyncSession, Task
import scripts.dashboard_simulator as dashboard_simulator
import scripts.ise_ers_simulator as ise_ers_simulator
import json
import os
from django_apscheduler.models import DjangoJobExecution


def read_file_all(in_filename):
    with open(os.path.join("scripts", in_filename), 'r+') as in_file:
        return in_file.read()


def run():
    DjangoJobExecution.objects.delete_old_job_executions(0)
    Task.objects.all().delete()
    Tag.objects.all().delete()
    ACL.objects.all().delete()
    Policy.objects.all().delete()

    dashboard_simulator.run(1, 15, 10, 10)
    ise_ers_simulator.run(50, 30, 45)

    o = json.loads(read_file_all("orgs.json"))
    orgid = o[0]["id"]

    d = Dashboard.objects.all()
    if len(d) > 0:
        d[0].orgid = str(orgid)
        d[0].save()

    ss = SyncSession.objects.all()
    if len(ss) > 0:
        ss[0].force_rebuild = True
        ss[0].save()
