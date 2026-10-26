# Case 5 - DC01 setup commands
# Run as Domain Admin in PowerShell on DC01

# 1. Enable WinRM
Enable-PSRemoting -Force
winrm quickconfig -q

# Allow unencrypted (lab only - prod requires HTTPS)
Set-Item WSMan:\localhost\Service\Auth\Basic $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted $true

# Firewall rule for WinRM HTTP
New-NetFirewallRule -DisplayName "WinRM-HTTP" `
    -Protocol TCP -LocalPort 5985 -Action Allow

# 2. Create service account
New-ADUser -Name "svc-soc-automation" `
    -SamAccountName "svc-soc-automation" `
    -UserPrincipalName "svc-soc-automation@lab.local" `
    -AccountPassword (ConvertTo-SecureString "LabUser2026!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

# 3. Add to local Administrators on DC01 (for firewall rules)
Add-LocalGroupMember -Group "Administrators" -Member "lab\svc-soc-automation"

# 4. Add to Account Operators (for Disable-ADAccount)
Add-ADGroupMember -Identity "Account Operators" -Members "svc-soc-automation"

# 5. Create test victim user
New-ADUser -Name "test_victim_01" `
    -SamAccountName "test_victim_01" `
    -UserPrincipalName "test_victim_01@lab.local" `
    -AccountPassword (ConvertTo-SecureString "TestPass2026!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

Write-Host "Setup complete. Verify with: Get-ADUser svc-soc-automation"
