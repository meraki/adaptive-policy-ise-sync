from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from sync.models import Dashboard
import json
from scripts.dblog import append_log, db_log


@csrf_exempt
def process_webhook(request):
    log = []
    if request.method == 'POST':
        whdata = json.loads(request.body)
        append_log(log, "webhook post", whdata)

        dbs = Dashboard.objects.filter(webhook_enable=True)
        if len(dbs) > 0:
            db = dbs[0]
            db.force_rebuild = True
            db.save()
            append_log(log, "setting dashboard to force rebuild")

        db_log("dashboard_webhook", log)

    return HttpResponse("Send webhooks here as POST requests.")
