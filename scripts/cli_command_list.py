context = {}
context["global"] = [
    {
        "command": "quit",
        "function": "exec_quit",
        "help": "Exit from the program"
    }, {
        "command": "do-exec",
        "special": "merge_context=root:show;dir",
        "help": "To run exec commands in config mode"
    }, {
        "command": "!",
        "function": "exec_up_context",
        "special": "hidden"
    }
]

context["root"] = [
    {
        "command": "exit",
        "function": "exec_quit",
        "help": "Exit from the program"
    }, {
        "command": "dir",
        "function": "exec_show_files",
        "help": "List files in the database"
    }, {
        "command": "config",
        "function": "exec_config_mode",
        "help": "Enter configuration mode",
        "subcommands": [{
            "command": "terminal",
            "help": "Configure from the terminal",
            "function": "exec_config_mode"
        }]
    }, {
        "command": "show",
        "subcommands": [{
            "command": "debug",
            "function": "exec_show_debug",
            "help": "Show Debug Information",
            "subcommands": [{
                "command": "context",
                "help": "Debug Current Context"
            }]
        }, {
            "command": "running-configuration",
            "help": "Current operating configuration",
            "function": "exec_get_config",
            "subcommands": [{
                "optional": True,
                "command": "unmask",
                "help": "don't mask passwords/api keys",
                "function": "exec_get_config"
            }]
        }, {
            "command": "ise-server",
            "help": "ISE Server show commands",
            "subcommands": [{
                "optional": True,
                "command": "%W",
                "help": "ISE Server \"description\"",
                "subcommands": [{
                    "command": "raw",
                    "help": "ISE Server raw data",
                    "function": "exec_show_ise",
                }, {
                    "command": "objects",
                    "help": "ISE Server parsed objects",
                    "function": "exec_show_ise",
                    "subcommands": [{
                        "optional": True,
                        "command": "tags",
                        "help": "ISE Server parsed SGTs",
                        "function": "exec_show_ise",
                    }, {
                        "optional": True,
                        "command": "acls",
                        "help": "ISE Server parsed SGACLs",
                        "function": "exec_show_ise",
                    }, {
                        "optional": True,
                        "command": "policies",
                        "help": "ISE Server parsed Policies",
                        "function": "exec_show_ise",
                    }]
                }]
            }],
            "function": "exec_show_ise"
        }, {
            "command": "meraki-account",
            "help": "Meraki Account show commands",
            "subcommands": [{
                "optional": True,
                "command": "%W",
                "help": "Meraki Account \"description\"",
                "subcommands": [{
                    "command": "raw",
                    "help": "Meraki Account raw data",
                    "function": "exec_show_meraki",
                }, {
                    "command": "organizations",
                    "help": "Meraki Account Organizations",
                    "function": "exec_show_meraki",
                    "subcommands": [{
                        "optional": True,
                        "command": "%W",
                        "help": "Meraki Organization id",
                        "subcommands": [{
                            "command": "raw",
                            "help": "Meraki Organization raw data",
                            "function": "exec_show_meraki",
                        }, {
                            "command": "objects",
                            "help": "Meraki Organization parsed objects",
                            "function": "exec_show_meraki",
                            "subcommands": [{
                                    "optional": True,
                                    "command": "tags",
                                    "help": "Meraki Organization parsed SGTs",
                                    "function": "exec_show_meraki",
                                }, {
                                    "optional": True,
                                    "command": "acls",
                                    "help": "Meraki Organization parsed SGACLs",
                                    "function": "exec_show_meraki",
                                }, {
                                    "optional": True,
                                    "command": "policies",
                                    "help": "Meraki Organization parsed Policies",
                                    "function": "exec_show_meraki",
                                }]
                        }]
                    }]
                }]
            }],
            "function": "exec_show_meraki"
        }, {
            "command": "sync-session",
            "help": "Sync Session show commands",
            "function": "exec_show_sync"
        }, {
            "command": "tags",
            "help": "Tag (SGT) show commands",
            "function": "exec_show_tag",
            "subcommands": [
                {
                    "command": "organization",
                    "optional": True,
                    "help": "Tag (SGT) Organization show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "organization",
                        "_lookup": {"table": "Organization", "val1": "orgid", "val2": "orgid"},
                        "help": "Meraki \"Organization ID\""
                    }]
                }, {
                    "command": "meraki-account",
                    "optional": True,
                    "help": "Tag (SGT) Meraki Account show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "meraki-account",
                        "help": "Meraki Account \"description\""
                    }]
                }, {
                    "command": "ise-server",
                    "optional": True,
                    "help": "Tag (SGT) ISE Server show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "ise-server",
                        "help": "ISE Server \"description\""
                    }]
                }, {
                    "command": "sync-session",
                    "optional": True,
                    "help": "Tag (SGT) Sync Session show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "sync-session",
                        "help": "Sync Server \"description\""
                    }]
                }
            ]
        }, {
            "command": "acls",
            "help": "ACL (SGACL) show commands",
            "function": "exec_show_acl",
            "subcommands": [
                {
                    "command": "organization",
                    "optional": True,
                    "help": "ACL (SGACL) Organization show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "organization",
                        "_lookup": {"table": "Organization", "val1": "orgid", "val2": "orgid"},
                        "help": "Meraki \"Organization ID\""
                    }]
                }, {
                    "command": "meraki-account",
                    "optional": True,
                    "help": "ACL (SGACL) Meraki Account show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "meraki-account",
                        "help": "Meraki Account \"description\""
                    }]
                }, {
                    "command": "ise-server",
                    "optional": True,
                    "help": "ACL (SGACL) ISE Server show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "ise-server",
                        "help": "ISE Server \"description\""
                    }]
                }, {
                    "command": "sync-session",
                    "optional": True,
                    "help": "ACL (SGACL) Sync Session show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "sync-session",
                        "help": "Sync Server \"description\""
                    }]
                }
            ]
        }, {
            "command": "policies",
            "help": "Policy show commands",
            "function": "exec_show_policy",
            "subcommands": [
                {
                    "command": "organization",
                    "optional": True,
                    "help": "Policy Organization show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "organization",
                        "_lookup": {"table": "Organization", "val1": "orgid", "val2": "orgid"},
                        "help": "Meraki \"Organization ID\""
                    }]
                }, {
                    "command": "meraki-account",
                    "optional": True,
                    "help": "Policy Meraki Account show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "meraki-account",
                        "help": "Meraki Account \"description\""
                    }]
                }, {
                    "command": "ise-server",
                    "optional": True,
                    "help": "Policy ISE Server show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "ise-server",
                        "help": "ISE Server \"description\""
                    }]
                }, {
                    "command": "sync-session",
                    "optional": True,
                    "help": "Policy Sync Session show commands",
                    "subcommands": [{
                        "command": "%W",
                        "fx_command": "sync-session",
                        "help": "Sync Server \"description\""
                    }]
                }
            ]
        }],
        "function": "exec_show_parse",
        "help": "show information for a given object"
    }
]

context["config"] = [
    {
        "command": "exit",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "ise-server",
        "special": "supports_no",
        "function": "exec_context_ise",
        "help": "ISE Server configuration commands",
        "subcommands": [{
            "command": "%W",
            "help": "ISE Server \"description\""
        }]
    }, {
        "command": "meraki-account",
        "special": "supports_no",
        "function": "exec_context_meraki",
        "help": "Meraki Account configuration commands",
        "subcommands": [{
            "command": "%W",
            "help": "Meraki Account \"description\""
        }]
    }, {
        "command": "sync-session",
        "special": "supports_no",
        "function": "exec_context_sync",
        "help": "Sync Session configuration commands",
        "subcommands": [{
            "command": "%W",
            "help": "Sync Session \"description\""
        }]
    },
]

context["ise-config"] = [
    {
        "command": "exit",
        "function": "exec_up_context",
        "help": "Exit from ISE Server configuration mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "ip",
        "special": "supports_no",
        "function": "exec_syncsession_ise",
        "help": "Configure ISE Server IP Address or Hostname",
        "subcommands": [{
            "command": "address",
            "help": "ISE Server IP Address or Hostname",
            "fx_command": "ise-ip-address",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "IP Address or Hostname",
                "fx_command": "ise-ip-address"
            }]
        }]
    }, {
        "command": "username",
        "special": "supports_no",
        "function": "exec_syncsession_ise",
        "help": "Configure ISE Server ERS Username",
        "fx_command": "ise-username",
        "subcommands": [{
            "optional_on_no": True,
            "command": "%W",
            "help": "ISE Server Username",
            "fx_command": "ise-username"
        }]
    }, {
        "command": "password",
        "special": "supports_no",
        "function": "exec_syncsession_ise",
        "help": "Configure ISE Server ERS Password",
        "fx_command": "ise-password",
        "subcommands": [{
            "optional_on_no": True,
            "command": "%W",
            "help": "ISE Server Password",
            "fx_command": "ise-password"
        }]
    }, {
        "command": "shutdown",
        "special": "supports_no",
        "function": "exec_syncsession_ise",
        "help": "Shutdown the Meraki Account "
    }, {
        "command": "pxgrid",
        "function": "exec_context_ise_pxgrid",
        "help": "Configure ISE Server pxGrid Settings"
    }, {
        "command": "static-dataset",
        "special": "supports_no",
        "function": "exec_syncsession_ise",
        "help": "Indicates a given ISE Server has been loaded with a static dataset"
    }
]

context["ise-pxgrid-config"] = [
    {
        "command": "exit",
        "function": "exec_up_context",
        "help": "Exit from ISE Server configuration mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "server",
        "special": "supports_no",
        "function": "exec_syncsession_ise_pxgrid",
        "help": "Configure pxGrid Server settings",
        "subcommands": [{
            "command": "ip",
            "help": "Configure pxGrid Node IP Address or Hostname",
            "subcommands": [{
                "command": "address",
                "help": "pxGrid Node IP Address or Hostname",
                "fx_command": "pxgrid-server-ip-address",
                "subcommands": [{
                    "optional_on_no": True,
                    "command": "%W",
                    "help": "IP Address or Hostname",
                    "fx_command": "pxgrid-server-ip-address"
                }]
            }]
        }, {
            "command": "cert",
            "help": "Configure ISE Server pxGrid Node Certificate",
            "fx_command": "pxgrid-server-cert",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "Certificate Filename",
                "fx_command": "pxgrid-server-cert"
            }]
        }]
    }, {
        "command": "client",
        "special": "supports_no",
        "function": "exec_syncsession_ise_pxgrid",
        "help": "Configure pxGrid Client settings",
        "subcommands": [{
            "command": "name",
            "help": "Configure pxGrid Client Name",
            "fx_command": "pxgrid-client-name",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "Client Name",
                "fx_command": "pxgrid-client-name"
            }]
        }, {
            "command": "password",
            "help": "Configure pxGrid Client Password",
            "fx_command": "pxgrid-client-password",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "Client Password",
                "fx_command": "pxgrid-client-password"
            }]
        }, {
            "command": "cert",
            "help": "Configure pxGrid Client Certificate",
            "fx_command": "pxgrid-client-cert",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "Certificate Filename",
                "fx_command": "pxgrid-client-cert"
            }]
        }, {
            "command": "key",
            "help": "Configure pxGrid Client Key",
            "fx_command": "pxgrid-client-key",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "Certificate Filename",
                "fx_command": "pxgrid-client-key"
            }]
        }]
    }, {
        "command": "shutdown",
        "special": "supports_no",
        "function": "exec_syncsession_ise_pxgrid",
        "help": "Shutdown the ISE Server pxGrid Capability"
    }
]

context["meraki-config"] = [
    {
        "command": "exit",
        "function": "exec_up_context",
        "help": "Exit from Meraki Account configuration mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "api",
        "function": "exec_syncsession_meraki",
        "help": "Configure Meraki Account API Settings",
        "subcommands": [{
            "command": "base-url",
            "help": "Configure Meraki Account base API URL",
            "subcommands": [{
                "command": "%W",
                "help": "API URL (default=https://api.meraki.com/api/v1)",
                "fx_command": "api-base-url"
            }]
        }, {
            "command": "key",
            "help": "Configure Meraki Account API key",
            "fx_command": "api-key",
            "subcommands": [{
                "optional_on_no": True,
                "command": "%W",
                "help": "Meraki Account API Token",
                "fx_command": "api-key"
            }]
        }]
    }, {
        "command": "shutdown",
        "special": "supports_no",
        "function": "exec_syncsession_meraki",
        "help": "Shutdown the Meraki Account "
    }, {
        "command": "organization",
        "special": "supports_no",
        "function": "exec_context_meraki_org",
        "help": "Meraki Account Organization configuration commands",
        "subcommands": [{
            "command": "%W",
            "help": "Meraki Organization ID",
            "fx_command": "organization"
        }]
    }
]

context["meraki-org-config"] = [
    {
        "command": "exit",
        "function": "exec_up_context",
        "help": "Exit from Meraki Account configuration mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "static-dataset",
        "special": "supports_no",
        "function": "exec_syncsession_meraki_org",
        "help": "Indicates a given Organization has been loaded with a static dataset"
    }
]

context["sync-config"] = [
    {
        "command": "exit",
        "function": "exec_up_context",
        "help": "Exit from Sync Session configuration mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "source",
        "special": "exec_syncsession_sync",
        "help": "Configure data source for Sync Source",
        "subcommands": [{
            "command": "ise-server",
            "special": "supports_no",
            "function": "exec_syncsession_sync",
            "help": "Configure ISE Server for Sync Session",
            "subcommands": [{
                "command": "%W",
                "help": "ISE Server \"Description\"",
                "fx_command": "ise-server"
            }]
        }, {
            "command": "organization",
            "special": "supports_no",
            "function": "exec_syncsession_sync",
            "help": "Configure Meraki Account for Sync Session",
            "subcommands": [{
                "command": "%W",
                "help": "Dashboard Account \"Description\"",
                "fx_command": "meraki-org"
            }]
        }]
    }, {
        "command": "destinations",
        "function": "exec_context_sync_destination",
        "help": "Configure Destinations for Sync Session"
    }, {
        "command": "shutdown",
        "special": "supports_no",
        "function": "exec_syncsession_sync",
        "help": "Shutdown the Sync Session"
    }, {
        "command": "push-changes",
        "special": "supports_no",
        "function": "exec_syncsession_sync",
        "help": "Apply Changes to Destination"
    }, {
        "command": "reverse-sync",
        "special": "supports_no",
        "function": "exec_syncsession_sync",
        "help": "Sync new objects from destination(s) to source"
    }
]

context["sync-dest-config"] = [
    {
        "command": "exit",
        "function": "exec_up_context",
        "help": "Exit from Meraki Account configuration mode"
    }, {
        "command": "end",
        "function": "exec_root_context",
        "help": "Exit from configure mode"
    }, {
        "command": "no",
        "special": "merge_no_commands",
        "help": "Negate a command or set its defaults"
    }, {
        "command": "ise-server",
        "special": "supports_no",
        "function": "exec_syncsession_sync_dest",
        "help": "Configure ISE Server for Sync Session",
        "subcommands": [{
            "command": "%W",
            "help": "ISE Server \"Description\"",
            "fx_command": "ise-server"
        }]
    }, {
        "command": "organization",
        "special": "supports_no",
        "function": "exec_syncsession_sync_dest",
        "help": "Configure Meraki Organization for Sync Session",
        "subcommands": [{
            "command": "%W",
            "help": "Dashboard Organization id",
            "fx_command": "meraki-org"
        }]
    }
]
