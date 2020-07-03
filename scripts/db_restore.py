from django.core import management
import os


def run(backupname):
    fn = os.path.join("config", backupname)
    management.call_command('loaddata', fn)
