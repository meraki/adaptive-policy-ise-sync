import sys
import os
from django_apscheduler.models import DjangoJob

if ('runscript' not in sys.argv) and ('makemigrations' not in sys.argv) and ('migrate' not in sys.argv) and \
        ('dumpdata' not in sys.argv) and ('loaddata' not in sys.argv) and ('test' not in sys.argv) and \
        (os.getenv('SKIPTASKS', '').upper() != "TRUE"):
    import scripts.dashboard_monitor
    import scripts.ise_monitor
    import scripts.clean_tasks
    import scripts.pxgrid_websocket
    import scripts.dashboard_webhook   # noqa: F401
    import scripts.db_backup           # noqa: F401
elif os.getenv('SKIPTASKS', '').upper() == "TRUE":
    for j in DjangoJob.objects.all():
        j.delete()
else:
    pass
