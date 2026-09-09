$script:AdSplat = @{}
function Set-AdConnection {
    [CmdletBinding()]
    param(
        [string]$Server,
        [pscredential]$Credential,
        [string]$DomainAddress
    )
    $splat = @{}
    if ($Server)     { $splat['Server']     = $Server }
    if ($Credential) { $splat['Credential'] = $Credential }
    if ($DomainAddress) { $splat['DomainAddress'] = $DomainAddress }
    $script:AdSplat = $splat
}
function Get-AdConnection {
    [CmdletBinding()] param()
    
    return $script:AdSplat
}
function Test-ADConnection {
    param([string]$ServerIP, [string]$Server, [int]$Port)

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $target = if($ServerIP) { $ServerIP } else { $Server }
        if(-not $target){ throw "No server address was provided." }
        $tcpClient.Connect([string]$target, $Port)
        $tcpClient.Close()
        Write-Host "[+] Connection successful to $target : $Port" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[-] Connection failed to $target : $Port" -ForegroundColor Red
        return $false
    }
}
function Show-FindingsTable {
    [CmdletBinding()] param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings
    )
    begin { $buffer = @() }
    process { $buffer += $Findings }
    end {
        if ($buffer.Count -eq 0) {
            Write-Host '  No findings in this category.' -ForegroundColor Green
            return
        }
        $order  = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
        $sorted = $buffer | Sort-Object { $order[$_.Severity] }

        foreach ($f in $sorted) {
            $color = Get-SeverityColor -Severity $f.Severity
            Write-Host ('  [{0,-8}] {1,-22} {2}' -f $f.Severity, $f.Object, $f.Detail) -ForegroundColor $color
        }
    }
}
function Show-AuditSummary {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object[]]$Findings
    )
    $bySeverity = $Findings | Group-Object Severity
    Write-Host ''
    Write-Host '  --- RISK SUMMARY ---' -ForegroundColor White
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $match = $bySeverity | Where-Object Name -eq $sev
        $count = if ($match) { $match.Count } else { 0 }
        $color = Get-SeverityColor -Severity $sev
        Write-Host ('  {0,-8}: {1}' -f $sev, $count) -ForegroundColor $color
    }
    Write-Host ''
}
function Export-AdSecurityReport {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object[]]$Findings,
        [string]$Path = (Join-Path -Path (Get-Location) -ChildPath "AD-Security-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html")
    )

    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $sortedFindings = $Findings | Sort-Object { $order[$_.Severity] }, Category

    $rowsHtml = ($sortedFindings | ForEach-Object {
        $cssClass = 'sev-' + $_.Severity.ToLower()
        "<tr class='$cssClass'><td>$($_.Severity)</td><td>$($_.Category)</td><td>$($_.Object)</td><td>$($_.Detail)</td><td>$($_.Recommendation)</td></tr>"
    }) -join "`n"

    $summaryHtml = ($Findings | Group-Object Severity | ForEach-Object {
        "<span class='badge sev-$($_.Name.ToLower())'>$($_.Name): $($_.Count)</span>"
    }) -join ' '

    $connection = if ($script:AdSplat.ContainsKey('Server')) { $script:AdSplat['Server'] } else { 'default (current user / DNS-located DC)' }
    $hostName  = [System.Net.Dns]::GetHostName()
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>AD Security Console Report</title>
<style>
  body { font-family: Consolas, 'Courier New', monospace; background:#0d1117; color:#c9d1d9; margin:0; padding:30px; }
  h1 { color:#58a6ff; }
  .meta { color:#8b949e; margin-bottom:20px; }
  table { width:100%; border-collapse: collapse; margin-top:20px; }
  th, td { padding:8px 12px; border-bottom:1px solid #30363d; text-align:left; vertical-align:top; }
  th { background:#161b22; color:#58a6ff; }
  tr.sev-critical { background: rgba(248,81,73,0.12); }
  tr.sev-high     { background: rgba(219,109,255,0.10); }
  tr.sev-medium   { background: rgba(210,153,34,0.10); }
  tr.sev-low      { background: rgba(56,189,248,0.08); }
  tr.sev-info     { background: rgba(63,185,80,0.06); }
  .badge { display:inline-block; padding:4px 10px; border-radius:4px; margin-right:8px; font-weight:bold; }
  .badge.sev-critical { background:#f85149; color:#0d1117; }
  .badge.sev-high     { background:#db6dff; color:#0d1117; }
  .badge.sev-medium   { background:#d29922; color:#0d1117; }
  .badge.sev-low      { background:#38bdf8; color:#0d1117; }
  .badge.sev-info     { background:#3fb950; color:#0d1117; }
</style>
</head>
<body>
  <h1>AD SECURITY CONSOLE &mdash; Audit Report</h1>
  <div class='meta'>Generated $generated on $hostName (management host) &middot; queried via: $connection</div>
  <div>$summaryHtml</div>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Object</th><th>Detail</th><th>Recommendation</th></tr>
    $rowsHtml
  </table>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding utf8
    return $Path
}
Export-ModuleMember -Function *