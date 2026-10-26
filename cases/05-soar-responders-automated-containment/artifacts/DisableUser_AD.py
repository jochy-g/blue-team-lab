
#!/usr/bin/env python3
# encoding: utf-8
"""
DisableUser_AD — Cortex responder
Disables an Active Directory user account via WinRM remote PowerShell.
Includes safety list to prevent disabling privileged accounts.
Author: Jochy Mendez
"""

import sys
import json
import winrm
from datetime import datetime, timezone
from cortexutils.responder import Responder


class DisableUserADResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.dc_host = self.get_param('config.dc_host', '10.10.10.10')
        self.dc_port = self.get_param('config.dc_port', 5985)
        self.svc_username = self.get_param('config.svc_username', None, 'Service username required')
        self.svc_password = self.get_param('config.svc_password', None, 'Service password required')
        protected = self.get_param('config.protected_users', 'Administrator,krbtgt')
        self.protected_users = [u.strip().lower() for u in protected.split(',')]

    def run(self):
        Responder.run(self)

        observable = self.get_param('data.data', None, 'No observable data')
        data_type = self.get_param('data.dataType', None, 'No data type')

        # Normalize username: strip domain prefixes/suffixes
        username = observable.strip()
        if '@' in username:
            username = username.split('@')[0]
        if '\\' in username:
            username = username.split('\\')[-1]

        # SAFETY: block attempts to disable critical users
        if username.lower() in self.protected_users:
            self.error(f"SAFETY BLOCK: User '{username}' is in protected_users list — refusing to disable")

        # Input sanitization: prevent PowerShell injection
        if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
            self.error(f"Invalid username format: {username}")

        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            session = winrm.Session(
                f'http://{self.dc_host}:{self.dc_port}/wsman',
                auth=(self.svc_username, self.svc_password),
                transport='ntlm'
            )

            # Step 1: check user exists + current state
            check_ps = f'''
try {{
    $user = Get-ADUser -Identity "{username}" -Properties Enabled -ErrorAction Stop
    @{{
        Found = $true
        Enabled = $user.Enabled
        SamAccountName = $user.SamAccountName
        DistinguishedName = $user.DistinguishedName
    }} | ConvertTo-Json
}} catch {{
    @{{ Found = $false; Error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
            check_result = session.run_ps(check_ps)

            if check_result.status_code != 0:
                self.error(f"Failed to query user: {check_result.std_err.decode().strip()}")

            try:
                check_data = json.loads(check_result.std_out.decode().strip())
            except json.JSONDecodeError:
                self.error(f"Could not parse user check response: {check_result.std_out.decode()[:300]}")

            if not check_data.get('Found'):
                self.error(f"User '{username}' not found in AD: {check_data.get('Error', 'unknown')}")

            # Idempotent check
            if check_data.get('Enabled') == False:
                self.report({
                    "status": "already_disabled",
                    "message": f"User '{username}' was already disabled",
                    "username": username,
                    "distinguished_name": check_data.get('DistinguishedName'),
                    "dc_host": self.dc_host,
                    "timestamp_utc": timestamp,
                    "undo_command": f'Enable-ADAccount -Identity "{username}"'
                })
                return

            # Step 2: disable the user
            disable_ps = f'''
try {{
    Disable-ADAccount -Identity "{username}" -ErrorAction Stop
    $user = Get-ADUser -Identity "{username}" -Properties Enabled
    @{{
        Success = $true
        NowEnabled = $user.Enabled
        SamAccountName = $user.SamAccountName
    }} | ConvertTo-Json
}} catch {{
    @{{ Success = $false; Error = $_.Exception.Message }} | ConvertTo-Json
}}
'''
            disable_result = session.run_ps(disable_ps)

            if disable_result.status_code != 0:
                self.error(f"Failed to disable user: {disable_result.std_err.decode().strip()}")

            disable_data = json.loads(disable_result.std_out.decode().strip())

            if not disable_data.get('Success'):
                self.error(f"Disable operation failed: {disable_data.get('Error')}")

            self.report({
                "status": "disabled",
                "message": f"User '{username}' successfully disabled at {self.dc_host}",
                "username": username,
                "distinguished_name": check_data.get('DistinguishedName'),
                "previous_state": "enabled",
                "new_state": "disabled",
                "dc_host": self.dc_host,
                "timestamp_utc": timestamp,
                "undo_command": f'Enable-ADAccount -Identity "{username}"',
                "undo_instructions": "To revert: run undo_command in PowerShell on DC01 as account operator"
            })

        except winrm.exceptions.InvalidCredentialsError:
            self.error(f"Invalid credentials for {self.svc_username} on {self.dc_host}")
        except Exception as e:
            self.error(f"Responder error: {type(e).__name__}: {str(e)}")

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag=f'soc:user-disabled-at-{self.dc_host}')]


if __name__ == '__main__':
    DisableUserADResponder().run()
