from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.jobstores import register_events
from django_apscheduler.models import DjangoJobExecution

scheduler = BackgroundScheduler()
scheduler.add_jobstore(DjangoJobStore(), "default")


def cleanup():
    DjangoJobExecution.objects.delete_old_job_executions(3600)


def run():
    cleanup()


@scheduler.scheduled_job("interval", hours=8, id="clean_tasks")
def job():
    cleanup()


register_events(scheduler)
scheduler.start()
