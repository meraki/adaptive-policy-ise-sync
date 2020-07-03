# import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler.jobstores import register_events

import threading
import asyncio
from asyncio.tasks import FIRST_COMPLETED
from scripts.pxgrid import PxgridControl
import sys
import time
from websockets import ConnectionClosed
from scripts.ws_stomp import WebSocketStomp
import ssl
import json
from types import SimpleNamespace as Namespace
from scripts.db_trustsec import clean_sgts, clean_sgacls, merge_sgts, merge_sgacls
from scripts.dblog import append_log, db_log
from asgiref.sync import sync_to_async
from sync.models import ISEServer, SyncSession

scheduler = BackgroundScheduler()
scheduler.add_jobstore(DjangoJobStore(), "default")
loop = asyncio.new_event_loop()


class Config:
    def __init__(self, log=None):
        dbs = ISEServer.objects.filter(pxgrid_enable=True)
        c = '{"hostname": [], "nodename": "", "clientcert": "", "clientkey": "", "clientkeypassword": "",' \
            '"servercert": "", "password": "", "description": ""}'
        self.config = json.loads(c, object_hook=lambda d: Namespace(**d))

        if len(dbs) > 0:
            append_log(log, "pxgrid_monitor::pxgrid_config::Establishing websocket for pxGrid...")
            db = dbs[0]
            self.config.hostname = [db.pxgrid_ip]
            self.config.nodename = db.pxgrid_cliname
            self.config.clientcert = str(db.pxgrid_clicert.file)
            self.config.clientkey = str(db.pxgrid_clikey.file)
            self.config.clientkeypassword = db.pxgrid_clipw
            self.config.servercert = str(db.pxgrid_isecert.file)
            self.config.id = db.id
        else:
            self.config.id = None
            append_log(log, "pxgrid_monitor::pxgrid_config::No pxGrid servers configured...")

    def get_id(self):
        return self.config.id

    def get_host_name(self):
        return self.config.hostname

    def get_node_name(self):
        return self.config.nodename

    def get_password(self):
        if self.config.password is not None:
            return self.config.password
        else:
            return ''

    def get_description(self):
        return self.config.description

    def get_ssl_context(self):
        # context = ssl.create_default_context()
        context = ssl._create_unverified_context()
        if self.config.clientcert is not None:
            context.load_cert_chain(certfile=self.config.clientcert,
                                    keyfile=self.config.clientkey,
                                    password=self.config.clientkeypassword)
        context.load_verify_locations(cafile=self.config.servercert)
        return context


def key_enter_callback(event):
    sys.stdin.readline()
    event.set()


async def future_read_message(ws, future, log=None):
    try:
        message = await ws.stomp_read_message()
        future.set_result(message)
    except ConnectionClosed:
        append_log(log, "pxgrid_websocket::subscribe_loop::Websocket connection closed")


async def subscribe_loop(config, secret, ws_url, tlist, pubsub_node_name, log):
    ws = WebSocketStomp(ws_url, config.get_node_name(), secret, config.get_ssl_context())
    await ws.connect()
    await ws.stomp_connect(pubsub_node_name)
    for topic in tlist:
        await ws.stomp_subscribe(topic)
        append_log(log, "subscribing to", topic)
    # setup keyboard callback
    await process_log_update("pxgrid_websocket", log)
    stop_event = asyncio.Event()
    asyncio.get_event_loop().add_reader(sys.stdin, key_enter_callback, stop_event)
    while True:
        future = asyncio.Future()
        future_read = future_read_message(ws, future, log)
        await asyncio.wait([stop_event.wait(), future_read], return_when=FIRST_COMPLETED)
        if not stop_event.is_set():
            log = []
            try:
                message = json.loads(future.result())
                if "securityGroup" in message:
                    append_log(log, "pxgrid_websocket::subscribe_loop::received message", json.dumps(message))
                    await process_sgt_update(message, await get_sync_account(config.get_id()), log)
                elif "acl" in message:
                    append_log(log, "pxgrid_websocket::subscribe_loop::received message", json.dumps(message))
                    await process_sgacl_update(message, await get_sync_account(config.get_id()), log)
                else:
                    append_log(log, "pxgrid_websocket::subscribe_loop::unhandled message", json.dumps(message))
                await process_log_update("pxgrid_websocket", log)
            except asyncio.exceptions.InvalidStateError:
                pass
        else:
            await ws.stomp_disconnect('123')
            # wait for receipt
            await asyncio.sleep(3)
            await ws.disconnect()
            await process_log_update("pxgrid_websocket", ["Disconnecting pxgrid websocket"])
            break


@sync_to_async
def get_sync_account(ise_server_id):
    sa = SyncSession.objects.filter(iseserver__id=ise_server_id)
    if len(sa) >= 0:
        return sa[0]
    return None


@sync_to_async
def process_log_update(ln, ld):
    db_log(ln, ld)
    return None


@sync_to_async
def process_sgt_update(msg, sa, log):
    # {"operation": "UPDATE", "securityGroup": {"id": "34714b20-7a6f-11ea-a6b9-26b516ce162b", "name": "new_test_tag",
    # "description": "tttt", "tag": 867, "isReadOnly": false, "isServiceProvider": false, "defaultSgaclIds": []}}
    if msg.get("operation", "") == "DELETE":
        tags = clean_sgts("ise", [msg["securityGroup"]], sa.ise_source, sa)
    else:
        tags = merge_sgts("ise", [msg["securityGroup"]], sa.ise_source, sa)

    if len(tags) > 0 and sa.apply_changes:
        for t in tags:
            # m, u, d = t.push_config()
            # if m != "":
            #     headers = {"X-Cisco-Meraki-API-Key": sa.dashboard.apikey, "Content-Type": "application/json"}
            #     append_log(log, "pxgrid_websocket::process_sgt_update::dashboard API push", t.push_config())
            #     ret = exec_api_action(m, u, d, headers)
            #     t.last_update_data = ret
            #     t.meraki_data = ret
            #     t.save()
            if t.push_delete:
                t.delete()

    # ISE sends an update to /topic/com.cisco.ise.config.trustsec.security.group when Policy Group Matrices are updated
    # Since there isn't a direct way to detect these changes, schedule a policy re-sync
    sa.iseserver.force_rebuild = True
    sa.iseserver.save()

    return ""


@sync_to_async
def process_sgacl_update(msg, sa, log):
    # {"isDeleted": false, "timestamp": "2020-04-14T11:45:19.217Z", "id": "08a4f350-5e1a-11ea-a6b9-26b516ce162b",
    # "name": "new_ise_sgl", "description": "test", "ipVersion": "IPV4",
    # "acl": "permit tcp src eq 5060\npermit udp src eq 5060\ndeny ip", "generationId": "6", "isReadOnly": false}
    if msg.get("isDeleted", False) is True:
        tags = clean_sgacls("ise", [msg], sa.ise_source, sa)
    else:
        tags = merge_sgacls("ise", [msg], sa.ise_source, sa)

    if len(tags) > 0 and sa.apply_changes:
        for t in tags:
            # m, u, d = t.push_config()
            # if m != "":
            #     headers = {"X-Cisco-Meraki-API-Key": sa.dashboard.apikey, "Content-Type": "application/json"}
            #     append_log(log, "pxgrid_websocket::process_sgacl_update::dashboard API push", t.push_config())
            #     ret = exec_api_action(m, u, d, headers)
            #     t.last_update_data = ret
            #     t.meraki_data = ret
            #     t.save()
            if t.push_delete:
                t.delete()

    return ""


# if __name__ == '__main__':
def run_sync_pxgrid(config):
    pxgrid = PxgridControl(config=config)

    while pxgrid.account_activate()['accountState'] != 'ENABLED':
        time.sleep(60)

    # lookup for session service
    service_lookup_response = pxgrid.service_lookup('com.cisco.ise.session')
    service = service_lookup_response['services'][0]
    pubsub_service_name = service['properties']['wsPubsubService']
    # topic = service['properties']['sessionTopic']
    topic = []
    trustsec_services = pxgrid.service_lookup("com.cisco.ise.config.trustsec")
    for s in trustsec_services["services"][0]["properties"]:
        if s == "securityGroupTopic" or s == "securityGroupAclTopic":
            topic.append(trustsec_services["services"][0]["properties"][s])

    # lookup for pubsub service
    service_lookup_response = pxgrid.service_lookup(pubsub_service_name)
    pubsub_service = service_lookup_response['services'][0]
    pubsub_node_name = pubsub_service['nodeName']
    secret = pxgrid.get_access_secret(pubsub_node_name)['secret']
    ws_url = pubsub_service['properties']['wsUrl']

    asyncio.get_event_loop().run_until_complete(subscribe_loop(config, secret, ws_url, topic, pubsub_node_name, None))


def run():
    log = []
    cfg = Config(log)
    run_sync_pxgrid(cfg)


def sync_pxgrid(loop, log=None):
    cfg = Config(log)
    if cfg.config.id:
        loop_pxgrid(Config(log), loop)
    else:
        return False

    return None


def loop_pxgrid(config, loop):
    log = []
    append_log(log, "pxgrid_websocket::loop_pxgrid::Attempting to start pxGrid websocket...")
    pxgrid = PxgridControl(config=config)

    while pxgrid.account_activate()['accountState'] != 'ENABLED':
        time.sleep(60)

    # lookup for session service
    service_lookup_response = pxgrid.service_lookup('com.cisco.ise.session')
    service = service_lookup_response['services'][0]
    pubsub_service_name = service['properties']['wsPubsubService']
    # topic = service['properties']['sessionTopic']
    topic = []
    trustsec_services = pxgrid.service_lookup("com.cisco.ise.config.trustsec")
    for s in trustsec_services["services"][0]["properties"]:
        if s == "securityGroupTopic" or s == "securityGroupAclTopic":
            topic.append(trustsec_services["services"][0]["properties"][s])

    # lookup for pubsub service
    service_lookup_response = pxgrid.service_lookup(pubsub_service_name)
    pubsub_service = service_lookup_response['services'][0]
    pubsub_node_name = pubsub_service['nodeName']
    secret = pxgrid.get_access_secret(pubsub_node_name)['secret']
    ws_url = pubsub_service['properties']['wsUrl']

    # atexit.register(lambda: loop.stop())
    asyncio.run_coroutine_threadsafe(subscribe_loop(config, secret, ws_url, topic, pubsub_node_name, log), loop)
    # asyncio.get_event_loop().run_until_complete(subscribe_loop(config, secret, ws_url, topic, pubsub_node_name))


def start_background_loop(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    loop.run_forever()


@scheduler.scheduled_job("interval", seconds=60, id="pxgrid_monitor")
def job():
    log = []
    try:
        loop = asyncio.new_event_loop()
        th = threading.Thread(target=start_background_loop, args=(loop,))
        th.start()
        ret = sync_pxgrid(loop, log)
        if ret is not False:
            scheduler.remove_job("pxgrid_monitor")
            append_log(log, "pxGrid Monitor started")
        else:
            append_log(log, "pxGrid configuration not present. Will check again...")
        db_log("pxgrid_monitor", log)
    except Exception as e:
        append_log(log, "#### Exception starting scheduled job: sync_pxgrid", e)
        db_log("pxgrid_monitor", log)


register_events(scheduler)
scheduler.start()
