param(
    [string]$smtpServer = "smtp-relay.gmail.com"
)

Set-StrictMode -Version Latest

$dir = if($PSScriptRoot){$PSScriptRoot}else{Get-Location}

$LogPath = Join-Path $dir "\Logs"
$modulePath = Join-Path $dir "Modules" 
$emailAlert = Join-Path $LogPath "AD_Alerts.txt"

if(-not (Test-Path -Path $LogPath)){New-Item -Path $LogPath -ItemType Directory }

$Modules = Get-ChildItem -Path $modulePath -Filter '*.psm1' -Recurse -File

$allSuccess = $true

foreach ($module in $Modules) {
    try {
        Import-Module $module.FullName -Force -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to import module: $($module.FullName). Error: $_"
        $allSuccess = $false
    }
}
if ($allSuccess) { Write-Host "[OK] Modules imported successfully" -ForegroundColor Green; Start-Sleep -Seconds 2 }
else {Write-Warning "One or more modules failed to import."}

Write-Host ""

$script:LastResults = @()

$banner = @'
+===================================================================================================================+
|                                                                                                                   |
|   ###  ####       #### #####  #### #   # ####  ##### ##### #   #    ####   ###   #   #   ####   ###  #     #####  |
|  #   # #   #     #     #     #     #   # #   #   #     #    # #    #      #   #  ##  #  #      #   # #     #      |
|  ##### #   #      ###  ###   #     #   # ####    #     #     #     #      #   #  # # #    ###  #   # #     #####  |
|  #   # #   #         # #     #     #   # #  #    #     #     #     #      #   #  #   #       # #   # #     #      |
|  #   # ####      ####  #####  ####  ###  #   # #####   #     #      ####   ###   #   #  ####    ###  ##### #####  |
|                                                                                                                   |
|                             Active Directory Security and Audit Dashboard                                         |
|                                                                                                                   |
|                                                                                                                   |
+===================================================================================================================+
'@

$Global:AppState = @{
    CurrentUser = $null
    
    ADConnection = @{
        Type = $null
        Suffix = $null
        Session = $null
        Connected = $false
    }
    Session = @{
        StartTime = $null
        LastActivity = $null
        TimeoutSeconds = 300
        IsAuthenticated = $false
    }
LastResults = @()
}
$Global:RolePermissions = @{
    "ADMIN" = @(
        "1","2","3","4","5","6","7","8","9","10","11","12",
        "13","14","15","16","17","18","19","20","21","22",
        "23","24","A","R","C","Q","L","U"
    )
    "DEVELOPER" = @(
        "1","2","3","4",
        "R","Q","L","U"
    )
    "EMPLOYEE" = @(
        "1","2","3","4","U"
    )
    "SYSTEM ADMIN" = @(
        "2","3","4","5","12","13","16","17","18","19",
        "20","21","22","23","24","A","R","C","Q","L","U"
    )
    "SOC ANALYST" = @(
        "2","3","6","7","8","9"
        "14","15","R","Q","L","U"
    )
}
$Global:Menu = @{
    "1" = "Get-PrivilegedGroupChanges"
    "2" = "Get-StaleUsers"
    "3" = "Get-StaleComputers"
    "4" = "Get-NonExpiringPasswords"
    "5" = "Get-LockedOutAccounts"
    "6" = "Get-KerberoastableAccounts"
    "7" = "Get-ASREPExposure"
    "8" = "Get-UnconstrainedDelegation"
    "9" = "Get-AdminSDHolderAnomalies"
    "10" = "Get-PasswordPolicy"
    "11" = "Get-DomainTrusts"
    "12" = "Get-RecentAccounts"
    "13" = "Get-ExpiringAccounts"
    "14" = "Get-BruteForceDetection"
    "15" = "Get-MaliciousProcess"
    "16" = "Reset-LockedOutAccount"
    "17" = "Disable-User"
    "18" = "Enable-User"
    "19" = "Reset-UserPassword"
    "20" = "Add-UserToGroup"
    "21" = "Remove-UserFromGroup"
    "22" = "Remove-User"
    "23" = "Reset-ComputerAccount"
    "24" = "Move-Computer"
    "U" = "Get-AllUsers"
}
function Register-User {
    param([string]$dBLogFile)
    if (-not $dBLogFile) {$dBLogFile = Join-Path $LogPath "dB_Config.json"}

    Clear-Host
    Write-Host ''
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "     USER REGISTRATION         " -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ''

    $f_name = Read-Host "Enter first name"
    $m_name = Read-Host "Enter middle name"
    $l_name = Read-Host "Enter last name"
    $email = Read-Host "Enter Email address"
    $uname = Read-Host "Enter username"
    $pass  = Read-Host "Enter password" -AsSecureString
    $role  = Read-Host "Enter role"

    if($pass.Length -lt 8){

        Write-Log "Password must be at least 8 characters." "ERROR"

        return
    }

    $encryptedPass = ConvertFrom-SecureString $pass

    if($email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$'){
        Write-Log "Invalid email format." "ERROR"
        return
    }

    $allowedRoles = @(
        "ADMIN",
        "SYSTEM ADMIN",
        "DEVELOPER",
        "SOC ANALYST",
        "EMPLOYEE"
    )
    if($role.ToUpper() -notin $allowedRoles){
        Write-Log "Invalid role." "ERROR"
        return
    }

    $db = @()
    if (Test-Path $dBLogFile) {
        $db = Get-Content $dBLogFile -Raw | ConvertFrom-Json
        if ($db -isnot [System.Collections.IEnumerable]) { $db = @($db) }
    }

    $existing = $db | Where-Object { $_.Username -eq $uname -or $_.Email -eq $email}
    if ($existing) {
        Write-Log "[-] Username and Email already exists for this user. Choose another." "WARN"
        return
    }

    $newUser = ([ordered] @{
        "FirstName" = "$f_name"
        "MiddleName" = "$m_name"
        "LastName"  = "$l_name"
        "Email"     = "$email"
        "Username"  = "$uname"
        "Password"  = "$encryptedPass"
        "Role"      = "$role"
        "Created"   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    })

    $db += $newUser

    $db | ConvertTo-Json -Depth 10 | Set-Content $dBLogFile

    Write-Log "[+] Registration successful. Please login to continue." "SUCCESS"
    Write-Host "Please register first [Press Enter to continue]" -ForegroundColor Yellow
    Read-Host 
    Write-Log "Please Wait..." "PROGRESS"
    Start-Sleep 2
    Login -dBLogFile $dBLogFile
}
function Compare-SecureString {
    param(
        [System.Security.SecureString]$s1,
        [System.Security.SecureString]$s2
    )

    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1)
    $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2)
    try {
        $t1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
        $t2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
        return $t1 -eq $t2
    }
    finally {
        if ($b1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1) }
        if ($b2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
    }
}
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $LogFile = join-path $LogPath "audit.log"
    if(-not (Test-Path $LogFile)){
        New-Item -Path $LogPath -Name audit.log -ItemType File 
    }
    if (-not $LogFile) {$LogFile = Join-Path $LogPath "audit.log"}

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "$timestamp [$Level] $Message"

    Add-Content -Path $LogFile -Value $entry

    $script:color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'ERROR'   { 'Red' }
        'PROGRESS' {'Magenta'}
        'WARN'    { 'Yellow' }
        default   { 'White' }
    }

    Write-Host $entry -ForegroundColor $color
}
function Raise-Alert {
    param(
        [string]$Category,
        [string]$Message,
        [string]$Severity = "Medium",
        [string]$NotifyEmail = ""
    )

    if (-not (Test-Path -Path $emailAlert)){New-Item -Path $LogPath -Name AD_Alerts.json -ItemType File}

    if (-not $emailAlert) {$emailAlert = Join-Path $dir "AD_Alerts.json"}

    $alert = "[ALERT][$Severity][$Category] $Message"
    $alertColor = switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'Yellow' }
        'Medium'   { 'Cyan' }
        'Low'      { 'Gray' }
        default    { 'White' }
    }
    Write-Host $alert -ForegroundColor $alertColor

    Add-Content -Path $emailAlert -Value $alert

    if ($NotifyEmail -and ($Severity -eq "Critical" -or $Severity -eq "High")) {
        Send-MailMessage -To $NotifyEmail -From "samchi.seclab@gmail.com" `
            -Subject "AD Security Alert - $Category ($Severity)" `
            -Body $alert -SmtpServer $smtpServer
    }
}
function Show-Banner {
    param([object]$User)

    #Clear-Host
    Write-Host $banner -ForegroundColor Cyan -BackgroundColor Black

    $conn = Get-AdConnection
    $target = if ($conn -and $conn.ContainsKey('Server') -and $conn['Server']) {
        $conn['Server']
    }
    elseif ($conn -and $conn.ContainsKey('DomainAddress') -and $conn['DomainAddress']) {
        $conn['DomainAddress']
    }
    else {
        'auto (DNS-located DC)'
    }
    $asUser = "$($User.FirstName) $($User.LastName)"
    $asRole = $User.Role

    Write-Host ("  Management Host : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
    Write-Host ("  Querying        : {0}" -f $target) -ForegroundColor White
    Write-Host ("  As              : {0}" -f $asUser) -ForegroundColor White
    Write-Host ("  Role            : {0}" -f $asRole) -ForegroundColor White
    Write-Host ("  Time            : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
    Write-Host ''
}
function Set-ADBackend {
    param([ValidateSet("LDAP", "PSREMOTE")] [string]$Type, [Object]$Session)
    switch ($Type) {
        "LDAP" { 
            $Global:AppState.ADConnection = @{
                Type = "LDAP"
                Suffix = "ldap"
                Session = $Session
                Connected = $true
            }
        }

        "PSREMOTE" { 
            $Global:AppState.ADConnection = @{
                Type = "PSREMOTE"
                Suffix = "ps"
                Session = $Session
                Connected = $true
            }
        }
    }
}
function Get-ADBackend {
    return $Global:AppState.ADConnection.Type 
}
function Show-BackendStatus{
    Write-Host ""
    Write-Host "====== Backend Connection Status ======" -ForegroundColor DarkCyan
    Write-Host "Connection Type : $($Global:AppState.ADConnection.Type)"
    Write-Host "Connection Suffix: $($Global:AppState.ADConnection.Suffix)"
    Write-Host "Connected       : $($Global:AppState.ADConnection.Connected)"
    Write-Host ""
}
function Show-ConnectionSetup {
    param([object]$User)

    while($true) {

        Clear-Host

        Write-Host "============================================================"
        Write-Host "                AD CONNECTION SETUP                         "
        Write-Host "============================================================"
        Write-Host ""
        Write-Host "[1] LDAP" -ForegroundColor DarkCyan
        Write-Host "[2] PSREMOTE" -ForegroundColor DarkCyan
        Write-Host "[Q] Quit" -ForegroundColor DarkCyan
        Write-Host ""

        $choice = Read-Host "Select Connection Type (1/2/Q)"
        Write-Host ""

        switch($choice.ToUpper()) {
            "1" {
                $ldapSession = ldap_connection
                if($ldapSession){
                    $null = Set-ADBackend -Type LDAP -Session $ldapSession
                    Show-BackendStatus
                    return [bool]$true
                }
                else {
                    Write-Log "[-] LDAP connection failed. Please check your settings." "ERROR"
                    Write-Host ""
                }
                break
            }
            "2" {
                $psSession = PSRemote_ConnectionSetup
                if($psSession){
                    $null = Set-ADBackend -Type PSREMOTE -Session $psSession
                    Show-BackendStatus
                    return [bool]$true
                }
                else {
                    Write-Log "[-] PSRemote connection failed. Please check your settings." "ERROR"
                }
                break
            }
            "Q" {
                return
            }
            default{
                Write-Log "Invalid Selection" "ERROR"
                Start-Sleep -Seconds 2
            }
        }
    }
}
function Start-UserSession{
    param([object]$User)

    $Global:AppState.CurrentUser = $User
    $Global:AppState.Session.StartTime = Get-Date
    $Global:AppState.Session.LastActivity = Get-Date
    $Global:AppState.Session.IsAuthenticated = $true
}
function Update-LastActivity{
    $Global:AppState.Session.LastActivity = Get-Date
}
function Stop-UserSession{
    $Global:AppState.ADConnection = @{
        Type = $null
        Suffix = $null
        Session = $null
        Connected = $false
    }
    $Global:AppState.Session = @{
        StartTime = $null
        LastActivity = $null
        TimeoutSeconds = 300
        IsAuthenticated = $false
    }
    Write-Log "[*] Session Terminated." "INFO"
}
function Test-SessionTimeout{
    param([string]$dBLogFile)

    if (-not $dBLogFile){$dBLogFile = Join-Path $LogPath "dB_Config.json"}

    if(-not $Global:AppState.Session.IsAuthenticated){
        Write-Log "[-] No active session. Please login." "WARN"
        return $false
    }
    $inactiveSeconds = (New-TimeSpan -Start $Global:AppState.Session.LastActivity -End (Get-Date)).TotalSeconds
 
    $timeoutSeconds = $Global:AppState.Session.TimeoutSeconds

    if ($inactiveSeconds -gt $timeoutSeconds) {
        Write-Log "[!] Session timed out due to inactivity." "WARN"
        Stop-UserSession
        Write-Host "Session has timed out. Please login again." -ForegroundColor Yellow
        Login -dBLogFile $dBLogFile
        return $true
    }
    return $false
}
function Show-LDAPMenu {
    param([object]$User)

    Write-Host " ======================== LDAP MODE ====================== " -ForegroundColor DarkCyan

    switch ($User.Role.ToUpper()) {
        "ADMIN" {
            Write-Host '   1) Privileged group membership audit'
            Write-Host '   2) Stale user accounts'
            Write-Host '   3) Stale computer accounts'
            Write-Host '   4) Accounts with non-expiring passwords'
            Write-Host '   5) Locked out accounts'
            Write-Host '   6) Kerberoasting exposure (SPN accounts)'
            Write-Host '   7) AS-REP roasting exposure'
            Write-Host '   8) Unconstrained delegation'
            Write-Host '   9) AdminSDHolder / adminCount anomalies'
            Write-Host '  10) Password policy summary'
            Write-Host '  11) Domain trusts'
            Write-Host '  12) Recently created accounts (last 7 days)'
            Write-Host '  13) Accounts expiring soon'
            Write-Host '  14) Brute force detection'
            Write-Host '  15) Malicious processes'
            Write-Host '   U) View all users'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
            Write-Host '  A) Run FULL audit (all checks)'
        }
        "SYSTEM ADMIN" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Accounts with non-expiring passwords'
            Write-Host '   3) Locked out accounts'
            Write-Host '   4) Reset Locked out account'
            Write-Host '   5) Add user to a group'
            Write-Host '   6) Remove user from a group'
            Write-Host '   7) Delete a user'
            Write-Host '   8) Recently created accounts (last 7 days)'
            Write-Host '   9) Accounts expiring soon'
            Write-Host '   U) View all users'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
            Write-Host '  A) Run FULL audit (all checks)'
        }
        "DEVELOPER" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Stale computer accounts'
            Write-Host '   3) Kerberoasting exposure (SPN accounts)'
            Write-Host '   4) AS-REP roasting exposure'
            Write-Host '   U) View all users'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
        }
        "SOC ANALYST" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Stale computer accounts'
            Write-Host '   3) Kerberoasting exposure (SPN accounts)'
            Write-Host '   4) AS-REP roasting exposure'
            Write-Host '   U) View all users'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
        }
        "EMPLOYEE" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Locked out accounts'
            Write-Host '   3) Password policy summary'
            Write-Host '   4) Accounts expiring soon'
            Write-Host '   U) View all users'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
        }
        default {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Locked out accounts'
        }
    }

    Write-Host '  R) Export last results to HTML report'
    Write-Host '  C) Reconfigure AD connection'
    Write-Host '  Q) Quit'
    Write-Host '  L) Logout and return to login screen'
    Write-Host '  ======================================================== ' -ForegroundColor DarkCyan
    Write-Host ''
}

function Show-PSRemoteMenu {
    param([object]$User)

    Write-Host " ======================== PSREMOTE MODE ====================== " -ForegroundColor DarkCyan

    switch ($User.Role.ToUpper()) {
        "ADMIN" {
            Write-Host '   1) Privileged group membership audit'
            Write-Host '   2) Stale user accounts'
            Write-Host '   3) Stale computer accounts'
            Write-Host '   4) Accounts with non-expiring passwords'
            Write-Host '   5) Locked out accounts'
            Write-Host '   6) Kerberoasting exposure (SPN accounts)'
            Write-Host '   7) AS-REP roasting exposure'
            Write-Host '   8) Unconstrained delegation'
            Write-Host '   9) AdminSDHolder / adminCount anomalies'
            Write-Host '  10) Password policy summary'
            Write-Host '  11) Domain trusts'
            Write-Host '  12) Recently created accounts (last 7 days)'
            Write-Host '  13) Accounts expiring soon'
            Write-Host '  14) Brute force detection'
            Write-Host '  15) Malicious processes'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
            Write-Host '  A) Run FULL audit (all checks)'
        }
        "SYSTEM ADMIN" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Accounts with non-expiring passwords'
            Write-Host '   3) Locked out accounts'
            Write-Host '   4) Reset Locked out account'
            Write-Host '   5) Add user to a group'
            Write-Host '   6) Remove user from a group'
            Write-Host '   7) Delete a user'
            Write-Host '   8) Recently created accounts (last 7 days)'
            Write-Host '   9) Accounts expiring soon'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
            Write-Host '  A) Run FULL audit (all checks)'
        }
        "DEVELOPER" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Stale computer accounts'
            Write-Host '   3) Kerberoasting exposure (SPN accounts)'
            Write-Host '   4) AS-REP roasting exposure'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
        }
        "SOC ANALYST" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Stale computer accounts'
            Write-Host '   3) Kerberoasting exposure (SPN accounts)'
            Write-Host '   4) AS-REP roasting exposure'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
        }
        "EMPLOYEE" {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Locked out accounts'
            Write-Host '   3) Password policy summary'
            Write-Host '   4) Accounts expiring soon'
            Write-Host '  --------------------------------------------------------' -ForegroundColor Cyan
        }
        default {
            Write-Host '   1) Stale user accounts'
            Write-Host '   2) Locked out accounts'
        }
    }

    Write-Host '  R) Export last results to HTML report'
    Write-Host '  C) Reconfigure AD connection'
    Write-Host '  Q) Quit'
    Write-Host '  L) Logout and return to login screen'
    Write-Host '  ======================================================== ' -ForegroundColor DarkCyan
    Write-Host ''
}

function Read-MenuChoice {
    param(
        [string]$Prompt = 'Select an option',
        [int]$TimeoutSeconds = 300
    )

    Write-Host "$Prompt : " -NoNewline
    $inputBuffer = [System.Text.StringBuilder]::new()
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            switch ($key.Key) {
                'Enter' {
                    Write-Host ''
                    return $inputBuffer.ToString()
                }
                'Backspace' {
                    if ($inputBuffer.Length -gt 0) {
                        $inputBuffer.Length--
                        Write-Host "`b `b" -NoNewline
                    }
                }
                default {
                    if ($key.KeyChar -and -not [char]::IsControl($key.KeyChar)) {
                        [void]$inputBuffer.Append($key.KeyChar)
                        Write-Host $key.KeyChar -NoNewline
                    }
                }
            }
        }
        else {
            Start-Sleep -Milliseconds 100
        }
    }

    Write-Host ''
    return $null
}

function Show-Menu {
    param([object]$User)

    while($true){
        if(Test-SessionTimeout){return}
        Show-Banner -User $User
        Write-Host ""
        Write-Host "Connection Type : $($Global:AppState.ADConnection.Type)"
        Write-Host ""

        switch($Global:AppState.ADConnection.Type){
            "LDAP" {Show-LDAPMenu -User $User}
            "PSREMOTE" {Show-PSRemoteMenu -User $User}
            default {
                Write-Host " No active connection found" -ForegroundColor Red
                return
            }
        }
        $choice = Read-MenuChoice -TimeoutSeconds $Global:AppState.Session.TimeoutSeconds
        if($null -eq $choice -and (Test-SessionTimeout)){return}
        Invoke-MenuChoice -Choice $choice -User $User
    }
}
function Get-UserNameInput{
    Read-Host "Enter username"
}
function Get-GroupNameInput{
    Read-Host "Enter group name"
}
function Get-NewPasswordInput{
    Read-Host "Enter new password" -AsSecureString
}
function Invoke-BackendFunction{
    param(
        [string]$BaseFunctionName,
        [hashtable]$Parameters
    )

    $backendType = Get-ADBackend

    if (-not $backendType) {
        Write-Log "[-] No active AD connection. Please set up a connection first." "ERROR"
        return
    }
    if(-not $Global:AppState.ADConnection.Connected){
        Write-Log "No active AD connection" "ERROR"
        return
    }
    $moduleName = if ($backendType -eq 'LDAP') { 'ldap_connect' } else { 'ps_remote_connect' }
    $name = "$moduleName\$BaseFunctionName"

    $command = Get-Command $name -ErrorAction SilentlyContinue

    if (-not $command) {
        throw "[-] Function $($name) does not exist."
    }

    try {
        $results = @(& $name @Parameters)
        if ($results.Count -gt 0) {
            $script:LastResults = $results
            $results | Format-Table -AutoSize | Out-Host
        }
        else {
            Write-Host "No results returned by $name." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log "[!] Error executing function '$name': $_" "ERROR"
    }

    Write-Host "Press Enter to continue..." -ForegroundColor Cyan
    Read-Host
}
function Invoke-MenuChoice {
    param([string]$Choice, [object]$User, [string]$dBLogFile)

    if (-not $dBLogFile) {$dBLogFile = Join-Path $LogPath "dB_Config.json"}

    Update-LastActivity

    $Choice = $Choice.ToUpper()

    if( -not (Test-Authorization -User $User -Choice $Choice)) {
        Write-Host "[-] You do not have permission to perform this action." -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }

    switch ($Choice) {
        "16" {
            $u = Get-UserNameInput
            Invoke-BackendFunction -BaseFunctionName "Reset-LockedOutAccount" -Parameters @{UserSamAccountName = $u}
            return
        }
        "17" {
            $u = Get-UserNameInput
            Invoke-BackendFunction -BaseFunctionName "Disable-User" -Parameters @{UserSamAccountName = $u}
            return
        }
        "18" {
            $u = Get-UserNameInput
            Invoke-BackendFunction -BaseFunctionName "Enable-User" -Parameters @{UserSamAccountName = $u}
            return
        }
        "19" {
            $u = Get-UserNameInput
            $p = Get-NewPasswordInput
            Invoke-BackendFunction -BaseFunctionName "Reset-UserPassword" -Parameters @{UserSamAccountName = $u; NewPassword = $p}
            return
        }
        "20" {
            $u = Get-UserNameInput
            $g = Get-GroupNameInput
            Invoke-BackendFunction -BaseFunctionName "Add-UserToGroup" -Parameters @{User = $u; Group = $g}
            return
        }
        "21" {
            $u = Get-UserNameInput
            $g = Get-GroupNameInput
            Invoke-BackendFunction -BaseFunctionName "Remove-UserFromGroup" -Parameters @{User = $u; Group = $g}
            return
        }
        "23" {
            $computer = Read-Host "Enter computer name"
            Invoke-BackendFunction -BaseFunctionName "Reset-ComputerAccount" -Parameters @{ComputerName = $computer}
            return
        }
        "24" {
            $computer = Read-Host "Enter computer name"
            $newOU = Read-Host "Enter target OU distinguished name"
            Invoke-BackendFunction -BaseFunctionName "Move-Computer" -Parameters @{ComputerName = $computer; NewOU = $newOU}
            return
        }
        "A" {
            Invoke-BackendFunction -BaseFunctionName "Invoke-AdFullSecurityAudit"
            return
        } 
        "R" {
            if ($script:LastResults.Count -eq 0) {
                Write-Host '  No results to export yet - run a check first.' -ForegroundColor Yellow
            } else {
                $path = Export-AdSecurityReport -Findings $script:LastResults
                Write-Host "  Report exported to: $path" -ForegroundColor Green
            }
            Read-Host '  Press Enter to continue'
            return
        }
        "C" {
            Show-ConnectionSetup -User $User
            return
        }
        "Q" {
            Write-Host "Exiting the application..." -ForegroundColor Cyan
            exit
        }
        "L" {
            Stop-UserSession
            Login -dBLogFile $dBLogFile
            return
        }
    }   

    $baseFunction = $Global:Menu[$Choice]
        if(-not $baseFunction) {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            return
        }
    Invoke-BackendFunction -BaseFunctionName $baseFunction -Parameters @{}
}
function Show_Reg_Login_Menu{
        Clear-Host
        Write-Host "=========================================" -ForegroundColor Cyan
        Write-Host " WELCOME REGISTER/LOGIN TO CONTINUE      " -ForegroundColor Cyan
        Write-Host "=========================================" -ForegroundColor Cyan
        Write-Host ''

        Write-Host "[1] Register (new user?)"
        Write-Host "[2] Login"
        Write-Host "[!] Quit? [Press Enter to exit!]"
}
function Test-Authorization {
    param([object]$User, [string]$Choice)

    $role = $User.Role.ToUpper()
    if (-not $Global:RolePermissions.ContainsKey($role)) {
        return $false
    }
    return ($Choice.ToUpper() -in $Global:RolePermissions[$role])
}
function Login {
    param([string]$dBLogFile)

    if (-not $dBLogFile) {$dBLogFile = Join-Path $LogPath "dB_Config.json"}

    if (-not (Test-Path $dBLogFile)) {
        Write-Log "[-] No credentials file found. Please register first to continue." "ERROR"
        return 
    }

    $db = Get-Content $dBLogFile -Raw | ConvertFrom-Json
    if ($db -isnot [System.Collections.IEnumerable]) { $db = @($db) }

    $attempts = 0
    $maxAttempts = 3
    $lockoutSeconds = 30

    do {
        Clear-Host
        Write-Host ''
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "            LOGIN              " -ForegroundColor Cyan
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host ''

        $uname = Read-Host "Enter username or email"
        $pass  = Read-Host "Enter password" -AsSecureString

        $user = $db | Where-Object { $_.Username -eq $uname -or $_.Email -eq $uname }
        if (-not $user) {
            Write-Log "[-] Username or email not found: $uname" "ERROR"
            $attempts++
        } else {
            
                $storedPass = ConvertTo-SecureString $user.Password -ErrorAction Stop
                if (Compare-SecureString $pass $storedPass) {
                    $Global:AppState.CurrentUser = $user
                    Write-Log "[+] Login successful for $($user.FirstName) $($user.LastName) (Role: $($user.Role))" "SUCCESS"
                    Start-Sleep -Seconds 2

                    $quit = $false

                    do {
                        Clear-Host
                        Start-UserSession -User $user
                        $connectionConfigured = Show-ConnectionSetup -User $user
                        if ($connectionConfigured -eq $true) {
                            Show-Banner -User $user
                            Show-Menu -User $user
                        }
                    
                    } while ($true)
                    if ($quit) { return }
                
                } else {
                    Write-Log "[-] Invalid login credentials for $uname" "ERROR"
                    $attempts++
                }
        }

        if ($attempts -ge $maxAttempts) {
            Write-Log "[-] Maximum login attempts reached. Locking out for $lockoutSeconds seconds..." "ERROR"
            Start-Sleep -Seconds $lockoutSeconds
            $attempts = 0 
        } else {
            $retry = Read-Host "Try again? (Y/n)"
            if ($retry.ToLower() -eq 'n') { return }
        }

    } while ($true)
}
do {

    Show_Reg_Login_Menu
    $get_input = Read-Host 'Select an option'
    if($get_input -eq '1'){ Register-User }  
    elseif($get_input -eq '2'){Login}
    elseif($get_input -eq ''){exit}
    else {
        Write-Host "Invalid selection. Please choose 1 or 2." -ForegroundColor Red
        Start-Sleep 1
        continue
    }  

} while ($true)

Write-Host ''
Write-Host '  AD Security Console closed.' -ForegroundColor Cyan