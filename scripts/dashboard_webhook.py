from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.jobstores import register_events

# import threading
# import asyncio
from sync.models import Dashboard
from pyngrok import ngrok
import sys
import meraki
from scripts.dblog import append_log, db_log

scheduler = BackgroundScheduler()
scheduler.add_jobstore(DjangoJobStore(), "default")
# loop = asyncio.new_event_loop()


def run():
    log = []
    dbs = Dashboard.objects.filter(webhook_enable=True)
    if dbs and len(dbs) > 0:
        db = dbs[0]
        dashboard = meraki.DashboardAPI(api_key=db.apikey, print_console=False, output_log=False)
        if db.webhook_ngrok:
            try:
                public_url = ngrok.connect(sys.argv[-1], "http")
            except Exception:
                try:
                    public_url = ngrok.connect(8000, "http")
                except Exception:
                    print("# Unable to launch ngrok")
                    return None

            db.webhook_url = public_url.replace("http://", "https://") + "/webhook/"
            db.save()

        orgs = db.organization.all()
        for org in orgs:
            nets = dashboard.networks.getOrganizationNetworks(org.orgid)
            for n in nets:
                whid = None
                whurl = dashboard.networks.getNetworkHttpServers(networkId=n["id"])
                if len(whurl) <= 0:
                    append_log(log, "creating new webhook for network", n["id"])
                    wh = dashboard.networks.createNetworkHttpServer(networkId=n["id"], name="adaptive-policy-sync",
                                                                    url=db.webhook_url)
                    whid = wh["id"]
                else:
                    for w in whurl:
                        if w["name"] == "adaptive-policy-sync":
                            append_log(log, "updating for network", n["id"])
                            dashboard.networks.updateNetworkHttpServer(networkId=n["id"], id=w["id"],
                                                                       url=db.webhook_url)
                            whid = w["id"]

                if whid:
                    al = dashboard.networks.getNetworkAlertSettings(networkId=n["id"])
                    for a in al["alerts"]:
                        if a["type"] == "settingsChanged":
                            a["alertDestinations"]["httpServerIds"].append(whid)
                            a["enabled"] = True

                    append_log(log, "updating alert settings", al)
                    r = dashboard.networks.updateNetworkAlertSettings(networkId=n["id"],
                                                                      defaultDestinations=al["defaultDestinations"],
                                                                      alerts=al["alerts"])
                    append_log(log, "update response", r)
    else:
        append_log(log, "Dashboard webhooks are not configured")
        db_log("dashboard_webhook", log)
        raise Exception("Dashboard webhooks are not configured")

    db_log("dashboard_webhook", log)


@scheduler.scheduled_job("interval", seconds=60, id="dashboard_webhook")
def job():
    log = []
    try:
        ret = run()
        if ret is not False:
            scheduler.remove_job("dashboard_webhook")
            append_log(log, "Webhook Monitor started")
        else:
            append_log(log, "Dashboard webhook configuration not present. Will check again...")
        db_log("dashboard_webhook", log)
    except Exception as e:
        append_log(log, "#### Dashboard webhooks are not configured: dashboard_webhook", e)
        db_log("dashboard_webhook", log)


register_events(scheduler)
scheduler.start()
