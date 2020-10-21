import argparse
import ssl
import warnings
from sync.models import ISEServer
import json
from types import SimpleNamespace as Namespace
from scripts.dblog import append_log, db_log


class Config:
    def __init__(self, log=None):
        self.__ssl_context = None
        dbs = ISEServer.objects.filter(pxgrid_enable=True)
        c = '{"hostname": [], "nodename": "", "clientcert": "", "clientkey": "", "clientkeypassword": "",' \
            '"servercert": "", "password": "", "description": "", "id": null, "verbose": true, "services": null,' \
            '"port": 8910, "service_details": null, "service": "com.cisco.ise.config.trustsec",' \
            '"topic": "securityGroupTopic,securityGroupAclTopic", "session_dedup": false,' \
            '"subscribe_all": false}'
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

    # def get_id(self):
    #     return self.config.id
    #
    # def get_host_name(self):
    #     return self.config.hostname
    #
    # def get_node_name(self):
    #     return self.config.nodename
    #
    # def get_password(self):
    #     if self.config.password is not None:
    #         return self.config.password
    #     else:
    #         return ''
    #
    # def get_description(self):
    #     return self.config.description
    #
    # def get_ssl_context(self):
    #     # context = ssl.create_default_context()
    #     context = ssl._create_unverified_context()
    #     if self.config.clientcert is not None:
    #         context.load_cert_chain(certfile=self.config.clientcert,
    #                                 keyfile=self.config.clientkey,
    #                                 password=self.config.clientkeypassword)
    #     context.load_verify_locations(cafile=self.config.servercert)
    #     return context

    @property
    def subscribe(self):
        return self.config.subscribe

    @property
    def config_id(self):
        return self.config.id

    @property
    def subscribe_all(self):
        return self.config.subscribe_all

    @property
    def session_dedup(self):
        return self.config.session_dedup

    @property
    def services(self):
        return self.config.services

    @property
    def service_details(self):
        return self.config.service_details

    @property
    def verbose(self):
        return self.config.verbose

    @property
    def hostname(self):
        return self.config.hostname

    @property
    def port(self):
        return self.config.port

    @property
    def node_name(self):
        return self.config.nodename

    @property
    def password(self):
        if self.config.password is not None:
            return self.config.password
        else:
            return ''

    @property
    def service(self):
        return self.config.service

    @property
    def topic(self):
        return self.config.topic

    @property
    def ip(self):
        return self.config.ip

    @property
    def start_timestamp(self):
        return self.config.start_timestamp

    @property
    def apply_anc_policy(self):
        return self.config.apply_anc_policy

    @property
    def clear_anc_policy(self):
        return self.config.clear_anc_policy

    @property
    def mac_address(self):
        return self.config.mac_address

    @property
    def anc_policy(self):
        return self.config.anc_policy

    @property
    def nas_ip_address(self):
        return self.config.nas_ip_address

    @property
    def description(self):
        return self.config.description

    @property
    def ssl_context(self):
        if self.__ssl_context == None:
            # self.__ssl_context = ssl.create_default_context()
            self.__ssl_context = ssl._create_unverified_context()
            if self.config.clientcert is not None:
                self.__ssl_context.load_cert_chain(
                    certfile=self.config.clientcert,
                    keyfile=self.config.clientkey,
                    password=self.config.clientkeypassword)
            if self.config.servercert:
                self.__ssl_context.load_verify_locations(cafile=self.config.servercert)
            elif self.config.insecure:
                self.__ssl_context.check_hostname = False
                self.__ssl_context.verify_mode = ssl.CERT_NONE
        return self.__ssl_context
