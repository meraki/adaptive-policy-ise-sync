from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.jobstores import register_events
from django.core import management
import time
import os


scheduler = BackgroundScheduler()
scheduler.add_jobstore(DjangoJobStore(), "default")


def backup():
    file = time.strftime("%Y%m%d-%H%M%S.json")
    fn = os.path.join("config", file)
    with open(fn, 'w') as f:
        # management.call_command('dumpdata', indent=4, exclude=["sync.Task"], stdout=f)
        management.call_command('dumpdata', stdout=f)
    print("Created backup:", file)


def run():
    backup()


@scheduler.scheduled_job("interval", hours=24, id="db_backup")
def job():
    backup()


register_events(scheduler)
scheduler.start()
