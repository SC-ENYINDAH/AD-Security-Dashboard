$dir = if($PSScriptRoot){ Split-Path -Parent $PSScriptRoot }else{Get-Location}
$LogPath = Join-Path $dir "Logs"

$Script:server_db = @()

function ldap_connection{
    param([string]$Server, [string]$DCip, [string]$Path, [string]$LDAPDomainConfig)

    if(-not $LDAPDomainConfig){$LDAPDomainConfig = Join-Path $LogPath "ldpa_ps_config.json"}

    try {
        $Server = Read-Host 'Enter your domain (e.g. xyz.com)'
        $DCip = Read-Host 'Enter Server net address'
        $username = Read-Host 'Enter Admin Server username'
        $password = Read-Host 'Enter Server Password' -AsSecureString
        $Path = "LDAP://"

        $DCsplit = $Server.Split(".")
        $DC = ($DCsplit | ForEach-Object {"DC=$_"})
        $DN = $DC -join ","

        $ldapBindPath = "$($Path)$($DCip)/$($DN)"

        Write-Host ""
        Write-Host "[*] Validating LDAP connectivity..." -ForegroundColor Cyan

        $encryptedPass = ConvertFrom-SecureString $password

        $db = @()
        if (Test-Path $LDAPDomainConfig) {
            $db = Get-Content $LDAPDomainConfig -Raw | ConvertFrom-Json
            if ($db -isnot [System.Collections.IEnumerable]) { $db = @($db) }
        }
        $existing = $db | Where-Object { $_.Username -eq $username -or $_.IP -eq $DCip}
        if ($existing) {
            Write-Host "[!] Credentials already exist. Validating the connection without adding a duplicate." -ForegroundColor DarkYellow
        }

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)

        try {

            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

            $entry = New-Object System.DirectoryServices.DirectoryEntry( $ldapBindPath,$username,$plainPassword)
            # Force LDAP bind
            $null = $entry.NativeObject
        }
        finally {
            $zero = ":Zero"
            if($bstr -ne $zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)}
        }

        Write-Host ""
        Write-Host "[+] LDAP bind successful" -ForegroundColor Green

        $domainConfig = ([ordered] @{
            Domain = $DN
            Server = $Server
            IP     = $DCip
            Path = $Path
            Username = $username
            Password = $encryptedPass
            LastUsed = (Get-Date)
        })

        if (-not $existing) {
            $db += $domainConfig
            $Script:server_db = $db
            $Script:server_db | ConvertTo-Json -Depth 10 | Set-Content $LDAPDomainConfig
        }

        Set-AdConnection -Server $DCip -DomainAddress $Server

        return @{
            Type = "LDAP"
            Root = $entry
            Path = $ldapBindPath
            Domain = $DN
            Server = $Server
            Username = $username
            Connected = $true
        }
    }
    catch {}
}
function ldpa_searcher{
    param([string]$filter, [string]$LDAPDomainConfig)

    if(-not $LDAPDomainConfig){$LDAPDomainConfig = Join-Path $LogPath "ldpa_ps_config.json"}

    if (-not (Test-Path $LDAPDomainConfig)) {
        Write-Host "[-] LDAP Configuration file not found: $LDAPDomainConfig" "ERROR"
        return $null
    }

    $json = Get-Content $LDAPDomainConfig -Raw
    $db = ConvertFrom-Json -InputObject $json -ErrorAction SilentlyContinue
    $connection = Get-AdConnection
    if($db.Count -gt 1 -and ($connection['Server'] -or $connection['DomainAddress'])) {
        $configured = $db | Where-Object {
            ($connection['Server'] -and $_.IP -eq $connection['Server']) -or
            ($connection['DomainAddress'] -and $_.Server -eq $connection['DomainAddress'])
        } | Select-Object -First 1
        if($configured){ $db = @($configured) }
    }
    $db = $db | Select-Object -First 1
    
    if ($null -eq $db -or $null -eq $db.Password) {
        Write-Log "[-] Password decryption failed: LDAP configuration invalid or password not found." "ERROR"
        return $null
    }

    $LDpassword = ConvertTo-SecureString ([string]$db.Password)

    $LDAPpasswd = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($LDpassword)
    try {
        $LDAPpass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($LDAPpasswd)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($LDAPpasswd)
    }

    Clear-Host
    Write-Host ''

    $ldapBindPath = "$($db.Path)$($db.IP)"
    if (-not (Test-ADConnection -Server $db.IP -Port 389)) {
        Write-Host "[WARN] LDAP port 389 unreachable. Trying LDAPS (636)..." -ForegroundColor Yellow
            if (-not (Test-ADConnection -Server $db.ip -Port 636)) {
                Write-Host "[-] Domain Controller not reachable on LDAP or LDAPS." -ForegroundColor Red
                return
            }
        $ldapBindPath = "$($db.Path)$($db.IP)/$($db.Domain)"
    }
    Write-Host "LDAP Connecting: $($ldapBindPath) with the following credential $($db.username)" -ForegroundColor Yellow

    $LDAPCred = New-Object System.DirectoryServices.DirectoryEntry("$ldapBindPath",$($db.username),$LDAPpass)
    $LDAPConnect = New-Object System.DirectoryServices.DirectorySearcher($LDAPCred)
    $LDAPConnect.Filter = $filter
    $LDAPConnect.PageSize = 1000
    return $LDAPConnect
}
function Get-PasswordPolicy {
    param([string]$LDAPDomainConfig)

    if(-not $LDAPDomainConfig){$LDAPDomainConfig = Join-Path $LogPath "ldpa_ps_config.json"}

    $json = Get-Content $LDAPDomainConfig -Raw
    $db = ConvertFrom-Json -InputObject $json -ErrorAction SilentlyContinue
    $connection = Get-AdConnection
    if($db.Count -gt 1 -and ($connection['Server'] -or $connection['DomainAddress'])) {
        $configured = $db | Where-Object {
            ($connection['Server'] -and $_.IP -eq $connection['Server']) -or
            ($connection['DomainAddress'] -and $_.Server -eq $connection['DomainAddress'])
        } | Select-Object -First 1
        if($configured){ $db = @($configured) }
    }
    $db = $db | Select-Object -First 1
    if($null -eq $db -or $null -eq $db.Domain){
        Write-Host "[-] LDAP domain configuration is missing." -ForegroundColor Red
        return
    }

    $searcher = ldpa_searcher -filter "(&(objectClass=domainDNS)(distinguishedName=$($db.Domain)))" -LDAPDomainConfig $LDAPDomainConfig
    if($null -eq $searcher){ return }

    foreach($property in @('minPwdLength','pwdHistoryLength','maxPwdAge','minPwdAge','lockoutDuration','lockoutThreshold','lockoutObservationWindow','pwdProperties')) {
        $searcher.PropertiesToLoad.Add($property) | Out-Null
    }

    $result = $searcher.FindOne()
    if($null -eq $result){
        Write-Host "[-] Domain password policy could not be found." -ForegroundColor Red
        return
    }

    $properties = $result.Properties
    $toDuration = {
        param($value)
        if($null -eq $value -or $value.Count -eq 0){ return 'Not configured' }
        $interval = [int64]$value[0]
        if($interval -eq 0){ return 'None' }
        return ([TimeSpan]::FromTicks([math]::Abs($interval))).ToString()
    }

    Write-Host "`n=== LDAP Password Policy Summary ===" -ForegroundColor Yellow
    [pscustomobject]@{
        MinimumPasswordLength = if($properties['minPwdLength']) { $properties['minPwdLength'][0] } else { 0 }
        PasswordHistoryLength = if($properties['pwdHistoryLength']) { $properties['pwdHistoryLength'][0] } else { 0 }
        MaximumPasswordAge = & $toDuration $properties['maxPwdAge']
        MinimumPasswordAge = & $toDuration $properties['minPwdAge']
        LockoutDuration = & $toDuration $properties['lockoutDuration']
        LockoutThreshold = if($properties['lockoutThreshold']) { $properties['lockoutThreshold'][0] } else { 0 }
        LockoutObservationWindow = & $toDuration $properties['lockoutObservationWindow']
        PasswordProperties = if($properties['pwdProperties']) { $properties['pwdProperties'][0] } else { 0 }
    } | Format-List

}
function Get-DomainTrusts {
    param([string]$LDAPDomainConfig)

    if(-not $LDAPDomainConfig){$LDAPDomainConfig = Join-Path $LogPath "ldpa_ps_config.json"}

    $searcher = ldpa_searcher -filter '(objectClass=trustedDomain)' -LDAPDomainConfig $LDAPDomainConfig
    if($null -eq $searcher){ return }

    foreach($property in @('name','trustDirection','trustType','flatName')) {
        $searcher.PropertiesToLoad.Add($property) | Out-Null
    }

    $results = $searcher.FindAll()
    Write-Host "`n=== Domain Trusts ===" -ForegroundColor Yellow
    foreach($result in $results) {
        [pscustomobject]@{
            Name = if($result.Properties['name']) { $result.Properties['name'][0] } else { '' }
            FlatName = if($result.Properties['flatName']) { $result.Properties['flatName'][0] } else { '' }
            TrustDirection = if($result.Properties['trustDirection']) { $result.Properties['trustDirection'][0] } else { '' }
            TrustType = if($result.Properties['trustType']) { $result.Properties['trustType'][0] } else { '' }
        }
    }
}
function Get-PrivilegedGroupChanges {
    param([string]$LDAPDomainConfig)
    if(-not $LDAPDomainConfig){$LDAPDomainConfig = Join-Path $LogPath "ldpa_ps_config.json"}
    $db = Get-Content $LDAPDomainConfig -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

    $searcher = ldpa_searcher -filter "(memberOf=CN=Domain Admins,CN=Users,$($db.domain))"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Domain Admins Membership ===" -ForegroundColor Yellow
    foreach ($res in $results) { 
        $res.Properties["samAccountName"] 
        Write-Host ""
        Write-Host "$($res.Properties["samAccountName"])" -ForegroundColor Green
    }
}
function Get-AllUsers {
    $searcher = ldpa_searcher -filter '(&(objectCategory=person)(objectClass=user))'
    if($null -eq $searcher){ return }

    foreach($property in @('samAccountName','displayName','userPrincipalName','mail')) {
        $searcher.PropertiesToLoad.Add($property) | Out-Null
    }

    Write-Host "`n=== All Active Directory Users ===" -ForegroundColor Yellow
    foreach($result in $searcher.FindAll()) {
        [pscustomobject]@{
            SamAccountName = if($result.Properties['samAccountName']) { $result.Properties['samAccountName'][0] } else { '' }
            DisplayName = if($result.Properties['displayName']) { $result.Properties['displayName'][0] } else { '' }
            UserPrincipalName = if($result.Properties['userPrincipalName']) { $result.Properties['userPrincipalName'][0] } else { '' }
            Email = if($result.Properties['mail']) { $result.Properties['mail'][0] } else { '' }
        }
    }
}
function Get-AdminSDHolderAnomalies {
    $searcher = ldpa_searcher -filter '(&(objectClass=*)(adminCount=1))'
    if($null -eq $searcher){ return }

    foreach($property in @('samAccountName','objectClass','distinguishedName')) {
        $searcher.PropertiesToLoad.Add($property) | Out-Null
    }

    Write-Host "`n=== AdminSDHolder / adminCount Objects ===" -ForegroundColor Yellow
    foreach($result in $searcher.FindAll()) {
        [pscustomobject]@{
            SamAccountName = if($result.Properties['samAccountName']) { $result.Properties['samAccountName'][0] } else { '' }
            ObjectClass = if($result.Properties['objectClass']) { $result.Properties['objectClass'][-1] } else { '' }
            DistinguishedName = if($result.Properties['distinguishedName']) { $result.Properties['distinguishedName'][0] } else { '' }
        }
    }
}
function Get-StaleUsers {
    $daysInactive = 90
    $searcher = ldpa_searcher -filter "(objectClass=user)"
    $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Stale Users (>90 days) ===" -ForegroundColor Yellow
    foreach ($res in $results) {
        if ($res.Properties["lastLogonTimestamp"]) {
            $lastLogon = [DateTime]::FromFileTime($res.Properties["lastLogonTimestamp"][0])
            if ($lastLogon -lt (Get-Date).AddDays(-$daysInactive)) {
                $res.Properties["samAccountName"]
            }
        }
    }
}
function Get-StaleComputers {
    $daysInactive = 90
    $searcher = ldpa_searcher -filter "(objectClass=computer)"
    $searcher.PropertiesToLoad.Add("lastLogonTimestamp") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Stale Computers (>90 days) ===" -ForegroundColor Yellow
    foreach ($res in $results) {
        if ($res.Properties["lastLogonTimestamp"]) {
            $lastLogon = [DateTime]::FromFileTime($res.Properties["lastLogonTimestamp"][0])
            if ($lastLogon -lt (Get-Date).AddDays(-$daysInactive)) {
                $res.Properties["samAccountName"]
            }
        }
    }
}
function Get-NonExpiringPasswords {
    $searcher = ldpa_searcher -filter "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Accounts with Non-Expiring Passwords ===" -ForegroundColor Yellow
    foreach ($res in $results) { $res.Properties["samAccountName"] }
}
function Get-LockedOutAccounts {
    $searcher = ldpa_searcher -filter "(lockoutTime>=1)"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Locked Out Accounts ===" -ForegroundColor Yellow
    foreach ($res in $results) { $res.Properties["samAccountName"] }
}
function Get-KerberoastableAccounts {
    $searcher = ldpa_searcher -filter "(servicePrincipalName=*)"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Kerberoastable Accounts (SPNs) ===" -ForegroundColor Yellow
    foreach ($res in $results) { $res.Properties["samAccountName"] }
}
function Get-ASREPExposure {
    $searcher = ldpa_searcher -filter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== AS-REP Exposure Accounts ===" -ForegroundColor Yellow
    foreach ($res in $results) { $res.Properties["samAccountName"] }
}
function Get-UnconstrainedDelegation {
    $searcher = ldpa_searcher -filter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Unconstrained Delegation Computers ===" -ForegroundColor Yellow
    foreach ($res in $results) { $res.Properties["samAccountName"] }
}
function Get-RecentAccounts {
    $searcher = ldpa_searcher -filter "(objectClass=user)"
    $searcher.PropertiesToLoad.Add("whenCreated") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Recently Created Accounts (7 days) ===" -ForegroundColor Yellow
    foreach ($res in $results) {
        $created = [DateTime]$res.Properties["whenCreated"][0]
        if ($created -gt (Get-Date).AddDays(-7)) {
            $res.Properties["samAccountName"]
        }
    }
}
function Get-ExpiringAccounts {
    $searcher = ldpa_searcher -filter "(accountExpires>=1)"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    $searcher.PropertiesToLoad.Add("accountExpires") | Out-Null
    $results = $searcher.FindAll()
    Write-Host "`n=== Accounts Expiring Soon (7 days) ===" -ForegroundColor Yellow
    foreach ($res in $results) {
        $exp = [DateTime]::FromFileTime($res.Properties["accountExpires"][0])
        if ($exp -lt (Get-Date).AddDays(7)) {
            "$($res.Properties['samAccountName']) expires $exp"
        }
    }
}
function Get-BruteForceDetection {
    param([string]$LDAPDomainConfig)

    if(-not $LDAPDomainConfig){$LDAPDomainConfig = Join-Path $LogPath "ldpa_ps_config.json"}
    $db = Get-Content $LDAPDomainConfig -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

    $filter = "(objectClass=user)"
    $searcher = ldpa_searcher -filter $filter

    $users = $searcher.FindAll() | ForEach-Object {
        $_.Properties["samAccountName"]
    }
    $events = Get-WinEvent -ComputerName $db.ip -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-15)}

    $grouped = $events | Group-Object {$_.Properties[5].Value}
    foreach ($g in $grouped) {
        if ($g.Count -gt 10 -and $users -contains $g.Name) {
            Write-Host "ALERT: Possible brute-force attack on $($g.Name) with $($g.Count) failures" -ForegroundColor Red
        }
    } 
}
function Get-MaliciousProcess {
    param([string]$LDAPDomainConfig)

    $filter = "(objectClass=computer)"
    $searcher = ldpa_searcher -filter $filter

    $computers = $searcher.FindAll() | ForEach-Object { $_.Properties["dNSHostName"]}

    $suspiciousParents = @("WINWORD","EXCEL","OUTLOOK","chrome","firefox","acrord32")
    $childTargets = @("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")

    foreach ($comp in $computers) {
        try {
            $procs = Get-CimInstance Win32_Process -ComputerName $comp -ErrorAction SilentlyContinue |
                    Where-Object { $childTargets -contains $_.Name }

                foreach ($proc in $procs) {
                    $parentProc = Get-CimInstance Win32_Process -ComputerName $comp -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                        if ($parentProc -and ($suspiciousParents -contains $parentProc.Name)) {
                            Write-Host "ALERT: On $comp : $($parentProc.Name) spawned $($proc.Name). Killing process..." -ForegroundColor Red
                            Invoke-Command -ComputerName $comp -ScriptBlock { Stop-Process -Id $using:proc.ProcessId -Force }
                        }
                }   
        } catch { Write-Host "Could not query $comp" -ForegroundColor Yellow }
    }
}
# --- Admin Functions ---
function Reset-LockedOutAccount {
    param([string]$UserSamAccountName, [string]$LDAPDomainConfig)

    $filter = "(samAccountName=$UserSamAccountName)"
    $searcher = ldpa_searcher -filter $filter
    $result = $searcher.FindOne()

    if ($result) {
        $userDN = $result.Properties["distinguishedName"][0]
        $user = [ADSI]"LDAP://$userDN"
        $user.psbase.Invoke("UnlockAccount")
        Write-Host "Account $UserSamAccountName unlocked." -ForegroundColor Green
    }
}
function Disable-User {
    param([string]$UserSamAccountName, [string]$LDAPDomainConfig)

    $filter = "(samAccountName=$UserSamAccountName)"
    $searcher = ldpa_searcher -filter $filter 
    $result = $searcher.FindOne()

    if ($result) {
        $userDN = $result.Properties["distinguishedName"][0]
        $user = [ADSI]"LDAP://$userDN"
        $user.psbase.InvokeSet("AccountDisabled", $true)
        $user.SetInfo()
        Write-Host "Account $UserSamAccountName disabled." -ForegroundColor Green
    }
}
function Enable-User {
    param([string]$UserSamAccountName, [string]$LDAPDomainConfig)

    $filter = "(samAccountName=$UserSamAccountName)"
    $searcher = ldpa_searcher -filter $filter 
    $result = $searcher.FindOne()

    if ($result) {
        $userDN = $result.Properties["distinguishedName"][0]
        $user = [ADSI]"LDAP://$userDN"
        $user.psbase.InvokeSet("AccountDisabled", $false)
        $user.SetInfo()
        Write-Host "Account $UserSamAccountName enabled." -ForegroundColor Green
    }
}
function Reset-UserPassword {
    param([string]$UserSamAccountName, [string]$NewPassword, [string]$LDAPDomainConfig)

    $filter = "(samAccountName=$UserSamAccountName)"
    $searcher = ldpa_searcher -filter $filter
    $result = $searcher.FindOne()

    if ($result) {
        $userDN = $result.Properties["distinguishedName"][0]
        $user = [ADSI]"LDAP://$userDN"
        $user.psbase.Invoke("SetPassword", $NewPassword)
        $user.SetInfo()
        Write-Host "Password reset for $UserSamAccountName." -ForegroundColor Green
    }
}
function Add-UserToGroup {
    param([string]$UserSamAccountName, [string]$GroupCN, [string]$LDAPDomainConfig)

    $userFilter = "(samAccountName=$UserSamAccountName)"
    $groupFilter = "(cn=$GroupCN)"

    $userSearcher = ldpa_searcher -filter $userFilter
    $groupSearcher = ldpa_searcher -filter $groupFilter

    $userResult = $userSearcher.FindOne()
    $groupResult = $groupSearcher.FindOne()

    if ($userResult -and $groupResult) {
        $userDN = $userResult.Properties["distinguishedName"][0]
        $groupDN = $groupResult.Properties["distinguishedName"][0]
        $group = [ADSI]"LDAP://$groupDN"
        $group.Add("LDAP://$userDN")
        Write-Host "User $UserSamAccountName added to $GroupCN." -ForegroundColor Green
    }
}
function Remove-UserFromGroup {
    param([string]$UserSamAccountName, [string]$GroupCN, [string]$LDAPDomainConfig)

    $userFilter = "(samAccountName=$UserSamAccountName)"
    $groupFilter = "(cn=$GroupCN)"

    $userSearcher = ldpa_searcher -filter $userFilter
    $groupSearcher = ldpa_searcher -filter $groupFilter

    $userResult = $userSearcher.FindOne()
    $groupResult = $groupSearcher.FindOne()

    if ($userResult -and $groupResult) {
        $userDN = $userResult.Properties["distinguishedName"][0]
        $groupDN = $groupResult.Properties["distinguishedName"][0]
        $group = [ADSI]"LDAP://$groupDN"
        $group.Remove("LDAP://$userDN")
        Write-Host "User $UserSamAccountName removed from $GroupCN." -ForegroundColor Green
    }
}
function Remove-User {
    param([string]$UserSamAccountName)

    $filter = "(samAccountName=$UserSamAccountName)"
    $searcher = ldpa_searcher -filter $filter 
    $result = $searcher.FindOne()

    if ($result) {
        $userDN = $result.Properties["distinguishedName"][0]
        $user = [ADSI]"LDAP://$userDN"
        $user.DeleteTree()
        Write-Host "User $UserSamAccountName deleted." -ForegroundColor Green
    }
}
function Reset-ComputerAccount {
    param([string]$ComputerName)

    $filter = "(samAccountName=$ComputerName$)"
    $searcher = ldpa_searcher -filter $filter 
    $result = $searcher.FindOne()

    if ($result) {
        $compDN = $result.Properties["distinguishedName"][0]
        $comp = [ADSI]"LDAP://$compDN"
        $comp.psbase.Invoke("ResetPassword","")
        $comp.SetInfo()
        Write-Host "Computer account $ComputerName reset." -ForegroundColor Green
    }
}
function Move-Computer {
    param([string]$ComputerName, [string]$NewOU)

    $filter = "(samAccountName=$ComputerName$)"
    $searcher = ldpa_searcher -filter $filter 
    $result = $searcher.FindOne()

    if ($result) {
        $compDN = $result.Properties["distinguishedName"][0]
        $comp = [ADSI]"LDAP://$compDN"
        $comp.MoveTo([ADSI]"LDAP://$NewOU")
        Write-Host "Computer $ComputerName moved to $NewOU." -ForegroundColor Green
    }
}
Export-ModuleMember -Function *
<#Get-ASREPExposure`
Get-MaliciousProcess`
Get-ExpiringAccounts`
Get-RecentAccounts`
Get-UnconstrainedDelegation`
Get-LockedOutAccounts`
Get-NonExpiringPasswords`
Get-StaleComputers`
Get-StaleUsers`
Get-PrivilegedGroupChanges`
ldap_BruteForce_Detection`
Reset-LockedOutAccount`
Disable-User`
Enable-User`
Reset-UserPassword`
Add-UserToGroup`
Remove-UserFromGroup`
Remove-User`
Reset-ComputerAccount`
Move-Computer
#>