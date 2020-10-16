import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import scripts.dashboard_monitor
import scripts.ise_monitor
import scripts.pxgrid_websocket
import scripts.dashboard_webhook  # noqa: F401
import scripts.db_backup  # noqa: F401

cron = BackgroundScheduler()


def run():     # pragma: no cover
    cron.remove_all_jobs()
    cron.add_job(scripts.dashboard_monitor.sync_dashboard, 'interval', id="dashboard_monitor", seconds=10)
    cron.add_job(scripts.ise_monitor.sync_ise, 'interval', id="ise_monitor", seconds=10)
    cron.add_job(scripts.db_backup.backup, 'interval', id="db_backup", hours=24)

    cron.start()
    atexit.register(lambda: cron.shutdown(wait=False))

    while True:
        pass
