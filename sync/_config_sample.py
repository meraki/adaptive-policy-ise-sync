merakiapi = {
    "apikey": "<meraki-api-key-goes-here>",
    "testorg1_id": "1234567890",
    "testorg2_id": "0987654321",
    "testorg1_name": "AdP Testing 1",
    "testorg2_name": "AdP Testing 2"
}

test_user = {
    "username": "unittests",
    "email": "unittests@test.com",
    "password": "P@ssw0rd",
    "apikey": "1234567890abcdefghijklmnopqrstuvwxyz1234"
}

whitelisted_sgts = [0, 2]
whitelisted_sgacls = ["Permit IP", "Deny IP", "Permit_IP_Log", "Deny_IP_Log"]
whitelisted_policies = ["ANY-ANY"]

sync_tags = [5, 11, 500, 501]
expected_sgacls = ["Permit_MQTT", "Permit_FTP"]
expected_policies = ["IoT_Devices-IoT_Servers", "IoT_Servers-IoT_Devices", "Contractors-Production_Servers"]

ise_default_sgts = [
    {
        "value": 3,
        "name": "Network_Services",
        "description": "Network Services Security Group"
    },
    {
        "value": 4,
        "name": "Employees",
        "description": "Employee Security Group"
    },
    {
        "value": 5,
        "name": "Contractors",
        "description": "Contractor Security Group"
    },
    {
        "value": 6,
        "name": "Guests",
        "description": "Guest Security Group"
    },
    {
        "value": 7,
        "name": "Production_Users",
        "description": "Production User Security Group"
    },
    {
        "value": 8,
        "name": "Developers",
        "description": "Developer Security Group"
    },
    {
        "value": 9,
        "name": "Auditors",
        "description": "Auditor Security Group"
    },
    {
        "value": 10,
        "name": "Point_of_Sale_Systems",
        "description": "Point of Sale Security Group"
    },
    {
        "value": 11,
        "name": "Production_Servers",
        "description": "Production Servers Security Group"
    },
    {
        "value": 12,
        "name": "Development_Servers",
        "description": "Development Servers Security Group"
    },
    {
        "value": 13,
        "name": "Test_Servers",
        "description": "Test Servers Security Group"
    },
    {
        "value": 14,
        "name": "PCI_Servers",
        "description": "PCI Servers Security Group"
    },
    {
        "value": 15,
        "name": "BYOD",
        "description": "BYOD Security Group"
    },
    {
        "value": 255,
        "name": "Quarantined_Systems",
        "description": "Quarantine Security Group"
    },
    {
        "value": 500,
        "name": "IoT_Servers",
        "description": "IoT Server Security Group"
    },
    {
        "value": 501,
        "name": "IoT_Devices",
        "description": "IoT Device Security Group"
    },
]

ise_default_sgacls = [
    {
        "name": "Permit_MQTT",
        "description": "Allow MQTT Traffic",
        "version": "IP_AGNOSTIC",
        "aclcontent": ["permit tcp dst eq 1833", "permit udp dst eq 1833", "permit tcp dst eq 8883"]
    },
    {
        "name": "Permit_FTP",
        "description": "Allow FTP Traffic",
        "version": "IPV4",
        "aclcontent": ["permit tcp dst eq 21", "permit tcp dst eq 22"]
    },
    {
        "name": "Permit_HTTP",
        "description": "Allow HTTP Traffic",
        "version": "IPV4",
        "aclcontent": ["permit tcp dst eq 80", "permit tcp dst eq 443"]
    },
]

ise_default_policies = [
    {
        "name": "IoT_Devices-IoT_Servers",
        "description": "Permit IoT Devices to access IoT Servers via MQTT",
        "src": "IoT_Devices",
        "dst": "IoT_Servers",
        "default": "NONE",
        "acls": ["Permit_MQTT"]
    },
    {
        "name": "IoT_Servers-IoT_Devices",
        "description": "Restrict IoT Servers from access IoT Devices",
        "src": "IoT_Servers",
        "dst": "IoT_Devices",
        "default": "DENY_IP",
        "acls": []
    },
    {
        "name": "Contractors-Production_Servers",
        "description": "Only Allow Contractors to FTP to Production Servers",
        "src": "Contractors",
        "dst": "Production_Servers",
        "default": "NONE",
        "acls": ["Permit_FTP"]
    },
]

update_sgt = {
    "search": "IoT_Devices",
    "value": 502,
    "name": "IoT_Clients",
    "description": "IoT Client Security Group"
}

update_sgacl = {
    "search": "Permit_FTP",
    "name": "Permit_FTP_HTTP",
    "description": "Allow FTP and HTTP Traffic",
    "version": "IP_AGNOSTIC",
    "version_meraki": "agnostic",
    "aclcontent": ["permit tcp dst eq 21", "permit tcp dst eq 22", "permit tcp dst eq 80", "permit tcp dst eq 443"],
    "aclcontent_meraki": [{"policy": "allow", "protocol": "tcp", "srcPort": "any", "dstPort": "21"},
                          {"policy": "allow", "protocol": "tcp", "srcPort": "any", "dstPort": "22"},
                          {"policy": "allow", "protocol": "tcp", "srcPort": "any", "dstPort": "80"},
                          {"policy": "allow", "protocol": "tcp", "srcPort": "any", "dstPort": "443"}
                          ]
}

update_policy = {
    "search": "Only Allow Contractors to FTP to Production Servers",
    "name": "Contractors-Production_Servers",
    "description": "Allow Contractors to HTTP to Production Servers",
    "src": "Contractors",
    "dst": "Production_Servers",
    "default": "NONE",
    "default_meraki": "global",
    "acls": ["Permit_FTP"]
}

servers = {
    "2.4": {
        "desc": "ISE 2.4 Patch 12",
        "ip": "1.1.2.4",
        "user": "admin",
        "pass": "password",
        "cert": "sync/ise24_cert.zip"
    },
    "2.6": {
        "desc": "ISE 2.6 Patch 6",
        "ip": "1.1.2.6",
        "user": "admin",
        "pass": "password",
        "cert": "sync/ise26_cert.zip"
    },
    "2.7": {
        "desc": "ISE 2.7 Patch 1",
        "ip": "1.1.2.7",
        "user": "admin",
        "pass": "password",
        "cert": "sync/ise27_cert.zip"
    },
    "3.0": {
        "desc": "ISE 3.0 Beta",
        "ip": "1.1.3.0",
        "user": "admin",
        "pass": "password",
        "cert": "sync/ise30_cert.zip"
    }
}
