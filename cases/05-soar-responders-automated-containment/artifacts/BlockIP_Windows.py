#!/usr/bin/env python3
# encoding: utf-8
"""
BlockIP_Windows — Cortex responder
Blocks a given IP address at Windows DC firewall via WinRM remote PowerShell.
Author: Jochy Mendez
"""

import sys
import json
import winrm
from datetime import datetime, timezone
from cortexutils.responder import Responder


class BlockIPWindowsResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.dc_host = self.get_param('config.dc_host', '10.10.10.10')
        self.dc_port = self.get_param('config.dc_port', 5985)
        self.svc_username = self.get_param('config.svc_username', None, 'Service username required')
        self.svc_password = self.get_param('config.svc_password', None, 'Service password required')

    def run(self):
        Responder.run(self)

        observable = self.get_param('data.data', None, 'No observable data')
        data_type = self.get_param('data.dataType', None, 'No data type')

        if data_type != 'ip':
            self.error(f"This responder only accepts IP observables, got: {data_type}")
