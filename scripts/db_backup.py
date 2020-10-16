from django.core import management
import time
import os


def backup():
    file = time.strftime("%Y%m%d-%H%M%S.json")
    fn = os.path.join("config", file)
    with open(fn, 'w') as f:
        management.call_command('dumpdata', stdout=f)
    print("Created backup:", file)
    return file


def run():
    backup()
