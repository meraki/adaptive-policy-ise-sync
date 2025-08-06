from django.core import management
import time
import os
import io
import zipfile


def backup():
    file = time.strftime("%Y%m%d-%H%M%S.json")
    fn = os.path.join("config", file)
    with open(fn, 'w') as f:
        management.call_command('dumpdata', stdout=f)
    print("Created backup:", file)
    return file


def generate_zip(files):
    mem_zip = io.BytesIO()

    with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.writestr(f[0], f[1])

    return mem_zip.getvalue()


def tech_backup():
    files = []
    dumpdata = io.StringIO()
    management.call_command('dumpdata', stdout=dumpdata, exclude=["admin", "contenttypes", "sessions", "auth",
                                                                  "authtoken"])
    dumpdata.seek(0)
    jsondata = dumpdata.read()

    files.append(("tech_support.json", jsondata))
    full_zip_in_memory = generate_zip(files)
    return full_zip_in_memory


def run():
    backup()
