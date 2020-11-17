import asyncio
from .pxgrid import PxgridControl
from .config import Config
from sync.models import ISEServer
import json
import sys
import time
import logging
import threading
import hashlib
from websockets import ConnectionClosed, ConnectionClosedOK
from .ws_stomp import WebSocketStomp
from signal import SIGINT, SIGTERM
from .pxgrid_update import process_sgt_update, process_sgacl_update, process_emc_update, get_sync_account
import traceback
# from contextlib import suppress
from asgiref.sync import async_to_sync
# import concurrent.futures


class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped() condition."""
    #
    # the global logger
    #
    logger = logging.getLogger(__name__)

    #
    # lock for deduplicating session events received
    #
    dedup_lock = threading.Lock()

    #
    # dictionary for storing event keys in
    #
    # TODO: this really needs a cleaner to remove old events
    #
    event_keys = {}

    #
    # definitions of service names possible when this script was was written
    # or updated
    #
    SERVICE_NAMES = [
        "com.cisco.ise.mdm",
        "com.cisco.ise.trustsec",
        "com.cisco.ise.config.trustsec",
        "com.cisco.ise.session",
        "com.cisco.ise.config.anc",
        "com.cisco.endpoint.asset",
        "com.cisco.ise.radius",
        "com.cisco.ise.system",
        "com.cisco.ise.sxp",
        "com.cisco.ise.config.profiler",
        "com.cisco.ise.pubsub",
    ]
    loop = None

    def __init__(self, external_loop):
        super(StoppableThread, self).__init__()
        self._stop_event = threading.Event()
        self.loop = external_loop
        self.ws = None

    def stop(self):
        self._stop_event.set()
        # for task in asyncio.Task.all_tasks():
        #     task.cancel()
        # asyncio.ensure_future(self.ws.stomp_disconnect('123'))
        # asyncio.ensure_future(asyncio.sleep(2.0))
        # asyncio.ensure_future(self.ws.disconnect())
        asyncio.run_coroutine_threadsafe(self.ws.stomp_disconnect('123'), self.loop)
        # asyncio.run_coroutine_threadsafe(asyncio.sleep(2.0), self.loop)
        asyncio.run_coroutine_threadsafe(self.ws.disconnect(), self.loop)
        # self.loop.stop()
        # self.loop.close()

    def stopped(self):
        return self._stop_event.is_set()

    async def future_read_message(self, ws, future):
        try:
            message = await ws.stomp_read_message()
            future.set_result(message)
        except ConnectionClosed:
            self.logger.debug('Websocket connection closed')

    @async_to_sync
    async def default_subscription_loop(self, config, secret, ws_url, topic, pubsub_node_name):
        '''
        Simple subscription loop just to display whatever events arrive.
        '''
        self.logger.debug('starting subscription to %s at %s', topic, ws_url)
        ws = WebSocketStomp(ws_url, config.node_name, secret, config.ssl_context)
        self.ws = ws
        await ws.connect()
        await ws.stomp_connect(pubsub_node_name)
        for topic_item in topic:
            await ws.stomp_subscribe(topic_item)
        try:
            while True:
                if self.stopped():
                    break
                message = json.loads(await ws.stomp_read_message())
                print(json.dumps(message, indent=2, sort_keys=True), file=sys.stdout)
                sys.stdout.flush()
                if "securityGroup" in message:
                    await process_sgt_update(message, await get_sync_account(config.config_id))
                    await process_emc_update(message, await get_sync_account(config.config_id))
                elif "acl" in message:
                    await process_sgacl_update(message, await get_sync_account(config.config_id))

        except asyncio.CancelledError:
            pass
        self.logger.debug('shutting down listener...')
        await ws.stomp_disconnect('123')
        await asyncio.sleep(2.0)
        await ws.disconnect()

    @async_to_sync
    async def session_dedup_loop(self, config, secret, ws_url, topic, pubsub_node_name):
        '''
        Subscription loop specifically for ISE pxGrid sessionTopic events. The
        logic for de-duplication is based around callingStationId, timestamp and
        event content. Multiple events may have the same callimgStationId and
        timestamp, but attribute changes, like profiling determining the operating
        system for a device, may result in events that have the same timestamp but
        different contents.

        The algorithm in this routine takes this into account, and will "de-
        duplicate" the events (i.e. tell you when a duplicate event arrived). It
        uses MD5 (for speed) on a key-sorted dump of the event (which ensures that
        duplicate events are detected by the hash digest differing.)
        '''
        self.logger.debug('starting subscription to %s at %s', topic, ws_url)
        assert topic == '/topic/com.cisco.ise.session', '%s is not the sessionTopic'

        ws = WebSocketStomp(ws_url, config.node_name, secret, config.ssl_context)
        await ws.connect()
        await ws.stomp_connect(pubsub_node_name)
        for topic_item in topic:
            await ws.stomp_subscribe(topic_item)
        try:
            while True:
                if self.stopped():
                    break
                message = json.loads(await ws.stomp_read_message())
                with self.dedup_lock:
                    for s in message['sessions']:
                        event_text = json.dumps(s, indent=2, sort_keys=True)
                        event_hash = hashlib.md5(event_text.encode()).hexdigest()
                        event_key = '{}:{}:{}'.format(
                            s['callingStationId'], s['timestamp'], event_hash)
                        if self.event_keys.get(event_key):
                            self.event_keys[event_key]['count'] = self.event_keys[event_key]['count'] + 1
                            print('duplicate mac:timestamp:hash event, count {}'.format(
                                self.event_keys[event_key]['count']))
                            print('    --> {}'.format(ws_url))
                        else:
                            self.event_keys[event_key] = {}
                            self.event_keys[event_key]['count'] = 1
                            self.event_keys[event_key]['time'] = time.time()
                            self.event_keys[event_key]['event'] = event_text
                            self.event_keys[event_key]['md5'] = event_hash
                            print('{}\nevent from {}'.format('-' * 75, ws_url))
                            print(json.dumps(s, indent=2, sort_keys=True))
                sys.stdout.flush()
        except asyncio.CancelledError:
            pass
        self.logger.debug('shutting down listener...')
        await ws.stomp_disconnect('123')
        await asyncio.sleep(2.0)
        await ws.disconnect()

    # subscribe to topic on ALL service nodes returned
    async def run_subscribe_all(self, task_list):
        self.logger.debug('run_subscribe_all')
        if len(task_list) > 0:
            try:
                return await asyncio.gather(*task_list)
            except asyncio.CancelledError:
                for t in task_list:
                    t.cancel()
                return await asyncio.gather(*task_list)

    # if __name__ == '__main__':
    def run(self):
        #
        # this will parse all the CLI options, and there **must** be EITHER
        # a '--services' OR '--subscribe'
        #
        config = Config()

        #
        # verbose logging if configured
        #
        if config.verbose:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG)

            # and set for stomp and ws_stomp modules also
            for stomp_mod in ['stomp', 'ws_stomp', 'pxgrid']:
                s_logger = logging.getLogger(stomp_mod)
                handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s:%(message)s'))
                s_logger.addHandler(handler)
                s_logger.setLevel(logging.DEBUG)

        #
        # if we jst have a request for services and no hostname, we can only
        # list out the services we know about
        #
        if config.services and (not config.hostname):
            print("Known services:")
            for service in sorted(self.SERVICE_NAMES):
                print('    %s' % service)
            sys.exit(0)

        #
        # if we at least have a hostname, we can move forward and set up the
        # px grid control object and look at either deeper service discovery
        # or just subscribing to what we're asked to subscribe to
        #
        pxgrid = PxgridControl(config=config)

        #
        # in case we need to go appropve in the ISE UI
        #
        while pxgrid.account_activate()['accountState'] != 'ENABLED':
            time.sleep(60)

        # lookup for session service
        if config.services:
            slr_responses = []
            for service in self.SERVICE_NAMES:
                service_lookup_response = pxgrid.service_lookup(service)
                slr_responses.append(service_lookup_response)

                #
                # log for debug
                #
                slr_string = json.dumps(service_lookup_response, indent=2, sort_keys=True)
                self.logger.debug('service %s lookup response:', service)
                slr_string = json.dumps(service_lookup_response, indent=2, sort_keys=True)
                self.logger.debug('service lookup response:')
                for s in slr_string.splitlines():
                    self.logger.debug('  %s', s)

            #
            # dump all services as a json array pretty-printed
            #
            print(json.dumps(slr_responses, indent=2, sort_keys=True))
            sys.exit(0)

        # get the details of a specific service and then exit
        if config.service_details:

            # first, the basic service
            service_lookup_response = pxgrid.service_lookup(config.service_details)
            print(json.dumps(service_lookup_response, indent=2, sort_keys=True))

            # check if any of tje services have a "wsPubsubService", and, if so,
            # also list out those services
            if "services" in service_lookup_response:
                topics = []
                for s in service_lookup_response['services']:
                    pubsub_service = s['properties'].get('wsPubsubService')
                    if pubsub_service:
                        for p, v in s['properties'].items():
                            if 'topic' in p.lower():
                                topics.append({p: v, 'wsPubsubService': pubsub_service})
                        break

                # lookup the pubsub service if there is one
                pubsub_slr = pxgrid.service_lookup(pubsub_service)
                if pubsub_slr:
                    print(json.dumps(pubsub_slr, indent=2, sort_keys=True))

            # now exit
            sys.exit(0)

        # if we drop through to here, we must be subscribing, so do some initial
        # checks to make sure we have enough parameters
        if config.service is None or config.topic is None:
            self.logger.error('must have a service and a topic!')
            sys.exit(1)

        #
        # now subscribe
        #
        service_lookup_response = pxgrid.service_lookup(config.service)
        slr_string = json.dumps(service_lookup_response, indent=2, sort_keys=True)
        self.logger.debug('service lookup response:')
        for s in slr_string.splitlines():
            self.logger.debug('  %s', s)
        service = service_lookup_response['services'][0]
        pubsub_service_name = service['properties']['wsPubsubService']
        try:
            topic = []
            topic_list = config.topic.split(",")
            for topic_item in topic_list:
                topic.append(service['properties'][topic_item])
        except KeyError:
            self.logger.debug('invald topic %s', config.topic)
            possible_topics = [k for k in service['properties'].keys() if
                               k != 'wsPubsubService' and k != 'restBaseUrl' and k != 'restBaseURL']
            self.logger.debug('possible topic handles: %s', ', '.join(possible_topics))
            sys.exit(1)

        # lookup the pubsub service
        service_lookup_response = pxgrid.service_lookup(pubsub_service_name)

        # select the subscription loop
        subscription_loop = self.default_subscription_loop
        if config.session_dedup:
            subscription_loop = self.session_dedup_loop

        if not config.subscribe_all:

            # just subscribe to first pubsub service node returned
            pubsub_service = service_lookup_response['services'][0]
            pubsub_node_name = pubsub_service['nodeName']
            secret = pxgrid.get_access_secret(pubsub_node_name)['secret']
            ws_url = pubsub_service['properties']['wsUrl']

            if self.loop:
                # asyncio.set_event_loop(self.loop)
                # main_task = asyncio.call_soon_threadsafe(subscription_loop(config, secret, ws_url, topic, pubsub_node_name))
                # main_task = asyncio.run_coroutine_threadsafe(subscription_loop(config, secret, ws_url, topic, pubsub_node_name), self.loop)
                # main_task = asyncio.ensure_future(subscription_loop(config, secret, ws_url, topic, pubsub_node_name))
                # asyncio.set_event_loop(self.loop)
                # loop = asyncio.get_running_loop()
                main_task = self.loop.run_in_executor(None, subscription_loop, config, secret, ws_url, topic, pubsub_node_name)
                # pass
            else:
                self.loop = asyncio.get_event_loop()
                main_task = asyncio.ensure_future(subscription_loop(config, secret, ws_url, topic, pubsub_node_name))
                self.loop.add_signal_handler(SIGINT, main_task.cancel)
                self.loop.add_signal_handler(SIGTERM, main_task.cancel)
            try:
                # asyncio.set_event_loop(self.loop)
                self.loop.run_until_complete(main_task)
                # self.loop.create_task(subscription_loop(config, secret, ws_url, topic, pubsub_node_name))
                # self.loop.call_soon_threadsafe(asyncio.ensure_future, subscription_loop(config, secret, ws_url, topic, pubsub_node_name))

            except ConnectionClosedOK:
                pass
            except Exception:  # pragma: no cover
                print(traceback.format_exc())

        else:

            # create all subscription tasks
            subscriber_tasks = []
            if self.loop:
                loop = self.loop
            else:
                loop = asyncio.get_event_loop()
            for pubsub_service in service_lookup_response['services']:
                pubsub_node_name = pubsub_service['nodeName']
                secret = pxgrid.get_access_secret(pubsub_node_name)['secret']
                ws_url = pubsub_service['properties']['wsUrl']
                task = asyncio.ensure_future(subscription_loop(config, secret, ws_url, topic, pubsub_node_name))
                subscriber_tasks.append(task)

            # create the run all task and graceful termination handling
            try:
                self.logger.debug('Create run all task')
                run_all_task = asyncio.ensure_future(self.run_subscribe_all(subscriber_tasks))
                self.logger.debug('Add signal handlers to run all task')
                loop.add_signal_handler(SIGINT, run_all_task.cancel)
                loop.add_signal_handler(SIGTERM, run_all_task.cancel)
                loop.run_until_complete(run_all_task)
            except Exception:
                pass


# def start_background_loop(loop: asyncio.AbstractEventLoop) -> None:
#     asyncio.set_event_loop(loop)
#     loop.run_forever()
#
#
# def job():
#     # this should be used when we are sure pxgrid is running
#     loop = asyncio.new_event_loop()
#     th = threading.Thread(target=start_background_loop, args=(loop,))
#     th.start()
#     run(loop)
#
#
# def job_try(scheduler=None):
#     # this should be used when we don't know if pxgrid has been configured yet
#     try:
#         loop = asyncio.new_event_loop()
#         th = threading.Thread(target=start_background_loop, args=(loop,))
#         th.start()
#         ret = run(loop)
#         if ret is not False and scheduler:
#             pxgrid_job = scheduler.get_job("pxgrid_monitor")
#             if pxgrid_job:
#                 pxgrid_job.remove()
#             print("pxGrid Monitor started")
#         else:
#             print("pxGrid configuration not present. Will check again...")
#     except Exception as e:
#         print("#### Exception starting scheduled job: sync_pxgrid", e)
#         print(traceback.format_exc())


def run():
    loop = asyncio.new_event_loop()
    testthread = StoppableThread(loop)
    loop.add_signal_handler(SIGINT, testthread.stop)
    loop.add_signal_handler(SIGTERM, testthread.stop)
    testthread.start()


def task():
    testthread = None
    servers = ISEServer.objects.all()
    while True:
        if len(servers) > 0:
            server = servers[0]
            if testthread:
                print("Restarting pxGrid for", server, "...")
                testthread.stop()
                time.sleep(10)
            else:
                print("Starting pxGrid for", server, "...")

            loop = asyncio.new_event_loop()
            testthread = StoppableThread(loop)
            try:
                loop.add_signal_handler(SIGINT, testthread.stop)
                loop.add_signal_handler(SIGTERM, testthread.stop)
            except Exception:
                print("Unable to assign signal handler.")
            testthread.start()
            server.pxgrid_reset = False
            server.skip_update = True
            server.save()

        servers = ISEServer.objects.filter(pxgrid_reset=True)
        time.sleep(60)
