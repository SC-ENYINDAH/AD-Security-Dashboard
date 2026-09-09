$dir = if($PSScriptRoot){ Split-Path -Parent $PSScriptRoot }else{Get-Location}
$LogPath = Join-Path $dir "Logs"

$Script:server_db = @()

function PSRemote_ConnectionSetup{
    param([string]$psConfig)

    if(-not $psConfig){$psConfig = Join-Path $LogPath "ldpa_ps_config.json"}

    $DCip = Read-Host 'Enter Server net address'
    $username = Read-Host 'Enter Admin Server username'
    $password = Read-Host 'Enter Server Password' -AsSecureString

    $encryptedPass = ConvertFrom-SecureString $password

    $db = @()
    if (Test-Path $psConfig) {
        $db = Get-Content $psConfig -Raw | ConvertFrom-Json
        if ($db -isnot [System.Collections.IEnumerable]) { $db = @($db) }
    }
    $existing = $db | Where-Object { $_.username -eq $username -or $_.ip -eq $DCip}
    if ($existing) {
        Write-Host "[!] Credentials already exist. Reusing the connection settings without adding a duplicate." -ForegroundColor DarkYellow
    }
    $domainConfig = ([ordered] @{
        "ip" = $DCip
        "username" = $username
        "password" = $encryptedPass
    })
    if (-not $existing) {
        $db += $domainConfig
        $Script:server_db = $db
        $Script:server_db | ConvertTo-Json -Depth 10 | Set-Content $psConfig
    }


    $decrypt = ConvertTo-SecureString $encryptedPass
    $computerName = $DCip
    $PSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $decrypt

    if ($DCip -and $PSCred) { Set-AdConnection -Server $DCip -DomainAddress $computerName -Credential $PSCred} 
    elseif ($DCip) {Set-AdConnection -Server $DCip}
    elseif ($PSCred) { Set-AdConnection -Credential $PSCred} 
    elseif ($computerName) { Set-AdConnection -DomainAddress $computerName}
    else {Set-AdConnection}

    return $true
}
function ps_connect{
    param([string]$DCremote)

    $psConfig = Join-Path $LogPath "ldpa_ps_config.json"

    if (-not (Test-Path $psConfig)) {
        Write-Host "[-] Configuration file not found: $psConfig" "ERROR"
        return $null
    }

    $db = Get-Content $psConfig -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    
    if ($null -eq $db -or $null -eq $db.password) {
        Write-Host "[-] Password decryption failed: Configuration invalid or password not found." "ERROR"
        return $null
    }

    $encrypted = ConvertTo-SecureString $db.password
    $user = $db.username
    $PSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $encrypted


    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    Set-Item  wsman:\\localhost\Client\TrustedHosts -value * -Force

    $DCremote = New-PSSession -ComputerName $($db.ip) -Credential $PSCred
    return $DCremote
}
function Get-PrivilegedGroupChanges {
    $session = ps_connect
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADGroupMember -Identity "Domain Admins" |
            Select-Object SamAccountName
    }
    Remove-PSSession $session
}
function Get-AllUsers {
    $session = ps_connect
    if($null -eq $session -or $session.State -ne 'Opened'){ return }

    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADUser -Filter * -Properties DisplayName, UserPrincipalName, Mail |
            Select-Object SamAccountName, DisplayName, UserPrincipalName, Mail
    }
    Remove-PSSession $session
}
function Get-AdminSDHolderAnomalies {
    $session = ps_connect
    if($null -eq $session -or $session.State -ne 'Opened'){ return }

    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADObject -LDAPFilter '(&(objectClass=*)(adminCount=1))' -Properties adminCount |
            Select-Object Name, ObjectClass, DistinguishedName, adminCount
    }
    Remove-PSSession $session
}
function Get-StaleUsers {
    param([int]$DaysInactive = 90)
    $session = ps_connect
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADUser -Filter * -Properties LastLogonDate |
            Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-$using:DaysInactive) } |
            Select-Object SamAccountName
    }
    Remove-PSSession $session
}
function Get-LockedOutAccounts {
    $session = ps_connect

    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADUser -Filter { LockedOut -eq $true } |
            Select-Object SamAccountName
    }
    Remove-PSSession $session
}
function Get-NonExpiringPasswords {
    $session = ps_connect
    
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADUser -Filter * -Properties PasswordNeverExpires |
            Where-Object { $_.PasswordNeverExpires -eq $true } |
            Select-Object SamAccountName
    }
    Remove-PSSession $session
}
function Get-KerberoastableAccounts {
    $session = ps_connect
    
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName |
            Select-Object SamAccountName, ServicePrincipalName
    }
    Remove-PSSession $session
}
function Get-ASREPExposure {
    $session = ps_connect
     
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } |
            Select-Object SamAccountName
    }
    Remove-PSSession $session
}
function Get-UnconstrainedDelegation {
    $session = ps_connect
    
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module ActiveDirectory
        Get-ADComputer -Filter { TrustedForDelegation -eq $true } |
            Select-Object SamAccountName, DNSHostName
    }
    Remove-PSSession $session
}
function Get-PasswordPolicy {
    $DCremote = ps_connect
   
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Clear-Host
            Write-Host "`n=== Password Policy Summary ===" -ForegroundColor Yellow
            Get-ADDefaultDomainPasswordPolicy
        }  | Format-List
    }
}
function Get-DomainTrusts {
    $DCremote = ps_connect
     
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Clear-Host
            Write-Host "`n=== Domain Trusts ===" -ForegroundColor Yellow
            Get-ADTrust -Filter *
        }  | Format-Table Name, TrustType, Direction -AutoSize
    }
}
function Detect-BruteForce {
    $DCremote = ps_connect
    
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Clear-Host
            Write-Host "`n=== Brute Force Detection ===" -ForegroundColor Yellow
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-15)}
            $grouped = $events | Group-Object {$_.Properties[5].Value}
            foreach ($g in $grouped) {
                if ($g.Count -gt 10) {
                    Write-Host "ALERT: Possible brute-force attack on $($g.Name) with $($g.Count) failures" -ForegroundColor Red
                }
            }  
        } 
    }
}
function Get-BruteForceDetection {
    Detect-BruteForce
}
function Get-ExpiringAccounts {
    $session = ps_connect
    if($null -eq $session -or $session.State -ne 'Opened'){ return }

    $cutoff = (Get-Date).AddDays(7)
    Invoke-Command -Session $session -ScriptBlock {
        param($expirationCutoff)
        Import-Module ActiveDirectory
        Get-ADUser -Filter * -Properties AccountExpirationDate |
            Where-Object { $_.AccountExpirationDate -and $_.AccountExpirationDate -le $expirationCutoff } |
            Select-Object SamAccountName, Name, AccountExpirationDate
    } -ArgumentList $cutoff
    Remove-PSSession $session
}
function Get-MaliciousProcess {
    $DCremote = ps_connect
    
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Clear-Host
            $suspiciousParents = @("WINWORD","EXCEL","OUTLOOK","chrome","firefox","acrord32")
            $childTargets = @("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")

            $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

            foreach ($comp in $computers) {
                try {
                    $procs = Get-CimInstance Win32_Process -ComputerName $comp -ErrorAction SilentlyContinue |
                    Where-Object { $childTargets -contains $_.Name }

                    foreach ($proc in $procs) {
                        $parentProc = Get-CimInstance Win32_Process -ComputerName $comp -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                        if ($parentProc -and ($suspiciousParents -contains $parentProc.Name)) {
                            Write-Host "ALERT: On $comp, $($parentProc.Name) spawned $($proc.Name). Killing process..." -ForegroundColor Red

                            Invoke-Command -ComputerName $comp -ScriptBlock { Stop-Process -Id $using:proc.ProcessId -Force }

                            $logEntry = "$(Get-Date) ALERT on $comp : $($parentProc.Name) ($($parentProc.ExecutablePath)) spawned $($proc.Name) -> killed"
                            Add-Content -Path "C:\Logs\DomainProcessAlerts.txt" -Value $logEntry
                        }
                    }
                } catch {Write-Host "Could not query $comp" -ForegroundColor Yellow}
            }
            
        }
    }  
}
function Invoke-AdFullSecurityAudit {
    [CmdletBinding()] param()
    $session = ps_connect

    $modules = [ordered]@{
        'Privileged Group Membership' = { Invoke-Command -Session $session -ScriptBlock { Get-AdPrivilegedGroupAudit } }
        'Stale User Accounts'         = { Invoke-Command -Session $session -ScriptBlock { Get-AdStaleUserAccounts } }
        'Stale Computer Accounts'     = { Invoke-Command -Session $session -ScriptBlock { Get-AdStaleComputerAccounts } }
        'Non-Expiring Passwords'      = { Invoke-Command -Session $session -ScriptBlock { Get-AdNonExpiringPasswordAccounts } }
        'Locked Out Accounts'         = { Invoke-Command -Session $session -ScriptBlock { Get-AdLockedOutAccounts } }
        'Kerberoasting Exposure'      = { Invoke-Command -Session $session -ScriptBlock { Get-AdKerberoastableAccounts } }
        'AS-REP Roasting Exposure'    = { Invoke-Command -Session $session -ScriptBlock { Get-AdAsRepRoastableAccounts } }
        'Unconstrained Delegation'    = { Invoke-Command -Session $session -ScriptBlock { Get-AdUnconstrainedDelegation } }
        'AdminSDHolder Anomalies'     = { Invoke-Command -Session $session -ScriptBlock { Get-AdAdminCountAnomalies } }
        'Password Policy'             = { Invoke-Command -Session $session -ScriptBlock { Get-AdPasswordPolicySummary } }
        'Domain Trusts'               = { Invoke-Command -Session $session -ScriptBlock { Get-AdDomainTrusts } }
        'Recently Created Accounts'   = { Invoke-Command -Session $session -ScriptBlock { Get-AdRecentlyCreatedAccounts } }
        'Expiring Accounts'           = { Invoke-Command -Session $session -ScriptBlock { Get-AdExpiringAccounts } }
    }

    $allFindings = @()
    $total = $modules.Count
    $i = 0

    foreach ($name in $modules.Keys) {
        $i++
        Write-Progress -Activity 'Running AD Security Audit (PS-Remote)' -Status $name -PercentComplete (($i / $total) * 100)
        try {
            $allFindings += & $modules[$name]
        } catch {
            $allFindings += New-Finding -Category $name -Severity 'Low' -Object 'Module Error' -Detail $_.Exception.Message
        }
    }

    Write-Progress -Activity 'Running AD Security Audit (PS-Remote)' -Completed

    # Clean up session
    Remove-PSSession $session

    return $allFindings
}
# --- Admin Functions ---
function Reset-LockedOutAccount {
    param([string]$UserSamAccountName)
    $DCremote = ps_connect
    
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Unlock-ADAccount -Identity $UserSamAccountName
            Write-Host "Account $UserSamAccountName unlocked." -ForegroundColor Green
        }
    }
}
function Disable-User {
    param([string]$UserSamAccountName)
    $DCremote = ps_connect
    
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Disable-ADAccount -Identity $UserSamAccountName
            Write-Host "Account $UserSamAccountName disabled." -ForegroundColor Green
        }
    }
}
function Enable-User {
    param([string]$UserSamAccountName)
    $DCremote = ps_connect
   
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Enable-ADAccount -Identity $UserSamAccountName
            Write-Host "Account $UserSamAccountName enabled." -ForegroundColor Green
        }
    }
}
function Reset-UserPassword {
    param([string]$UserSamAccountName, [string]$NewPassword)
    $DCremote = ps_connect
    
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Set-ADAccountPassword -Identity $UserSamAccountName -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
            Write-Host "Password reset for $UserSamAccountName." -ForegroundColor Green
        }
    }
}
function Add-UserToGroup {
    param([string]$User, [string]$Group)
    $DCremote = ps_connect
     
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Add-ADGroupMember -Identity $Group -Members $User
            Write-Host "User $User added to $Group." -ForegroundColor Green
        }
    }
}
function Remove-UserFromGroup {
    param([string]$User, [string]$Group)
    $DCremote = ps_connect
    
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Remove-ADGroupMember -Identity $Group -Members $User -Confirm:$false
            Write-Host "User $User removed from $Group." -ForegroundColor Green
        }
    }
}
function Remove-User {
    param([string]$UserSamAccountName)
    $DCremote = ps_connect
   
    if($DCremote.State -eq "Opened"){
        Invoke-Command -Session $DCremote -ScriptBlock{
            Remove-ADUser -Identity $UserSamAccountName -Confirm:$false
            Write-Host "User $UserSamAccountName deleted." -ForegroundColor Green
        }
    }
}
function Reset-ComputerAccount {
    param([string]$ComputerName)
    $DCremote = ps_connect
    if($null -eq $DCremote -or $DCremote.State -ne 'Opened'){ return }

    Invoke-Command -Session $DCremote -ScriptBlock {
        param($name)
        Import-Module ActiveDirectory
        Reset-ComputerMachinePassword -Server $name
        Write-Host "Computer account $name reset." -ForegroundColor Green
    } -ArgumentList $ComputerName
    Remove-PSSession $DCremote
}
function Move-Computer {
    param([string]$ComputerName, [string]$NewOU)
    $DCremote = ps_connect
    if($null -eq $DCremote -or $DCremote.State -ne 'Opened'){ return }

    Invoke-Command -Session $DCremote -ScriptBlock {
        param($name, $destination)
        Import-Module ActiveDirectory
        $computer = Get-ADComputer -Identity $name
        Move-ADObject -Identity $computer.DistinguishedName -TargetPath $destination
        Write-Host "Computer $name moved to $destination." -ForegroundColor Green
    } -ArgumentList $ComputerName, $NewOU
    Remove-PSSession $DCremote
}
Export-ModuleMember -Function *