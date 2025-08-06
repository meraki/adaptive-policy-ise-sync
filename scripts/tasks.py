# import atexit
import time
# from apscheduler.schedulers.background import BackgroundScheduler
# from apscheduler.executors.pool import ProcessPoolExecutor
import scripts.sync_monitor
import scripts.generic_monitor
import scripts.push_monitor
import traceback
# import scripts.dashboard_monitor
# import scripts.ise_monitor
# import scripts.px_subscribe
# import scripts.dashboard_webhook  # noqa: F401
# import scripts.db_backup  # noqa: F401

# from sync.models import TaskQueue
# from django.db.models import Q
# import django.utils.timezone
# import importlib

# cron = BackgroundScheduler(executors={'processpool': ProcessPoolExecutor(1)}, job_defaults={'coalesce': True})


# def startup_task_queue():
#     # populate default tasks
#     default_resync_timer = 600
#     print("tasks::start")
#
#     TaskQueue.objects.update_or_create(description="Ingest ISE Data", function="scripts.ise_monitor.read_ise",
#                                        defaults={"priority": 100, "state": 1, "task_data": "", "run_now": True,
#                                                  "minimum_interval_secs": default_resync_timer})
#     TaskQueue.objects.update_or_create(description="Ingest Meraki Data",
#                                        function="scripts.dashboard_monitor.read_meraki",
#                                        defaults={"priority": 100, "state": 1, "task_data": "", "run_now": True,
#                                                  "minimum_interval_secs": default_resync_timer})
#     TaskQueue.objects.update_or_create(description="Generate Sync Data",
#                                        function="scripts.sync_monitor.monitor_sync",
#                                        defaults={"priority": 200, "state": 1, "task_data": "", "run_now": True,
#                                                  "minimum_interval_secs": default_resync_timer})
#     monitor_task_queue()
#
#
# def monitor_task_queue():
#     tqs = TaskQueue.objects.filter(state=1).order_by('priority')
#     for tq in tqs:
#         if tq.needs_run():
#             tq.run_now = False
#             tq.state = 2
#             tq.save()
#
#             print("tasks::call::", tq.description)
#             fxn = tq.function
#             fxn_list = fxn.split(".")
#             imp = ".".join(fxn_list[0:-1])
#             v = getattr(importlib.import_module(imp), fxn_list[-1:][0])
#             v()
#             print("tasks::return::", tq.description)
#
#     print("tasks::end")


def task_loop():
    print("task_loop::Start")
    print("task_loop::running generic_monitor")
    scripts.generic_monitor.read_generic()
    print("task_loop::running sync_monitor")
    scripts.sync_monitor.monitor_sync()
    print("task_loop::running push_monitor")
    scripts.push_monitor.sync_push()
    print("task_loop::End")


# def run_now():
#     return cron.get_jobs()
#     # cron.add_job(task_loop, id="task_run")
#     cron.add_job(task_loop, id="task_loop", replace_existing=True)
#     time.sleep(2)
#     cron.add_job(task_loop, 'interval', id="task_loop", seconds=60, replace_existing=True)


def run():     # pragma: no cover
    # cron.remove_all_jobs()
    # # cron.add_job(monitor_task_queue, 'interval', id="task_queue", seconds=30)
    # # cron.add_job(startup_task_queue, id="task_queue_start")
    # # cron.add_job(scripts.dashboard_monitor.sync_dashboard, 'interval', id="dashboard_monitor", seconds=30)
    # # cron.add_job(scripts.ise_monitor.sync_ise, 'interval', id="ise_monitor", seconds=30)
    # # cron.add_job(scripts.db_backup.backup, 'interval', id="db_backup", hours=24)
    # # # cron.add_job(scripts.px_subscribe.task, 'interval', id="pxgrid_monitor", kwargs={"scheduler": cron}, seconds=60)
    # # cron.add_job(scripts.px_subscribe.task, id="pxgrid_monitor")
    # # cron.add_job(scripts.sync_monitor.monitor_sync, 'interval', id="sync_monitor", seconds=60)
    # # cron.add_job(scripts.generic_monitor.read_generic, 'interval', id="generic_monitor", seconds=60)
    # cron.add_job(task_loop, id="task_loop")
    #
    # cron.start()
    # atexit.register(lambda: cron.shutdown(wait=False))
    #
    # cron.add_job(task_loop, 'interval', id="task_loop", seconds=60, replace_existing=True)
    # while True:
    #     pass
    while True:
        try:
            task_loop()
        except Exception as e:
            print("An exception occurred while running the task loop:", e)
            print(traceback.format_exc())

        time.sleep(60)
