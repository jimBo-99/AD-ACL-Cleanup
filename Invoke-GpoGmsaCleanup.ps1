#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][ValidatePattern('^[^\\]+\\[^\\]+\$$')][string]$GmsaAccount,
    [string]$OutputRoot="$env:ProgramData\AD-ACL-Cleanup",
    [ValidateRange(1,3650)][int]$MinimumDeletedDays=30,
    [string[]]$AdditionalValidationDomain=@(),
    [switch]$AuditOnly,
    [ValidateRange(5,1440)][int]$TimeoutMinutes=120
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Windows PowerShell 5.1 erforderlich.' }
if ($WhatIfPreference) { Write-Host 'WhatIf: Es wird kein Task angelegt. Fuer einen gMSA-Lesescan -AuditOnly verwenden.'; return }
if ($OutputRoot.StartsWith('\\') -or ![IO.Path]::IsPathRooted($OutputRoot)) {
    throw 'Der Task-Arbeitsordner muss ein absoluter lokaler Pfad auf diesem Host sein.'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Task-Registrierung braucht eine erhoehte PowerShell auf dem gMSA-Host.' }
Import-Module (Join-Path $PSScriptRoot 'AclCleanup.psm1') -Force
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module ScheduledTasks -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
$sid=(New-Object Security.Principal.NTAccount($GmsaAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
$parts=$GmsaAccount.Split('\')
$service=Get-ADServiceAccount -Identity $sid -Server $parts[0] -Properties ObjectClass
if ($service.ObjectClass -ne 'msDS-GroupManagedServiceAccount') { throw 'Das Konto ist kein gMSA.' }
if (!(Test-ADServiceAccount -Identity $service.SamAccountName)) {
    throw 'gMSA auf diesem Host nicht nutzbar. Kennwortabrufberechtigung/Installation mit eurem AD-Verfahren vorbereiten.'
}
$null=New-Item -ItemType Directory -Path $OutputRoot -Force
$job=Join-Path $OutputRoot ('Gmsa-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
New-SecureDirectory $job -ReadSid $sid
$code=Join-Path $job 'Code'; New-SecureDirectory $code -ReadSid $sid
$scan=Join-Path $job 'Scan'; New-SecureDirectory $scan -ModifySid $sid
$apply=Join-Path $job 'Apply'; New-SecureDirectory $apply -ModifySid $sid
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'AclCleanup.psm1'),(Join-Path $PSScriptRoot 'GpoCleanupWorker.ps1') -Destination $code
$taskName='GPO-'+[guid]::NewGuid().ToString('N')
$taskPath='\AD-ACL-Cleanup\'
$scheduler=New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
try { $null=$scheduler.GetFolder($taskPath) }
catch { $null=$scheduler.GetFolder('\').CreateFolder('AD-ACL-Cleanup') }
$taskCreated=$false
function Invoke-OneTask {
    param([string]$Mode,[string]$OutDir,[string]$PlanPath='',[string]$PlanHash='')
    $request=[pscustomobject]@{Mode=$Mode;Server=$Server;GmsaSid=$sid;OutputDirectory=$OutDir;
        MinimumDeletedDays=$MinimumDeletedDays;AdditionalValidationDomain=@($AdditionalValidationDomain);
        PlanPath=$PlanPath;PlanSha256=$PlanHash;ExpiresUtc=[datetime]::UtcNow.AddHours(4).ToString('o')}
    $requestFile=Join-Path $code ($Mode+'-request.json')
    Write-JsonFile $request $requestFile
    $hash=(Get-FileHash -LiteralPath $requestFile -Algorithm SHA256).Hash
    $worker=Join-Path $code 'GpoCleanupWorker.ps1'
    if ($worker -match '"' -or $requestFile -match '"') { throw 'Ungueltige Pfadzeichen.' }
    $arguments='-NoLogo -NoProfile -NonInteractive -File "{0}" -RequestPath "{1}" -RequestSha256 "{2}"' -f $worker,$requestFile,$hash
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments -WorkingDirectory $code
    $taskPrincipal=New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeoutMinutes) -MultipleInstances IgnoreNew
    $task=New-ScheduledTask -Action $action -Principal $taskPrincipal -Settings $settings -Description "Einmaliger GPO-ACL-$Mode; $job"
    $null=Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -InputObject $task -Force
    $script:taskCreated=$true
    $startedAfter=(Get-Date).AddSeconds(-1)
    Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    Write-Host "gMSA-$Mode laeuft. Protokoll: $(Join-Path $OutDir 'worker.log')" -ForegroundColor Cyan
    $deadline=(Get-Date).AddMinutes($TimeoutMinutes)
    $resultPath=Join-Path $OutDir 'result.json'
    do {
        Start-Sleep -Seconds 2
        $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
        $status=Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
        Write-Progress -Activity "gMSA $Mode" -Status "Task: $($status.State); Ergebnis: $($info.LastTaskResult)"
        if ((Get-Date) -gt $deadline) { throw "Task-Zeitlimit. Status und Backups unter $job pruefen." }
    } while ($status.State -eq 'Running' -or $status.State -eq 'Queued' -or $info.LastRunTime -lt $startedAfter -or
        $info.LastTaskResult -eq 267009 -or $info.LastTaskResult -eq 267011)
    Write-Progress -Activity "gMSA $Mode" -Completed
    if (!(Test-Path -LiteralPath $resultPath)) { throw "Kein Worker-Ergebnis. Task-Code $($info.LastTaskResult); Batch-Logon, gMSA, Execution Policy und Task-History pruefen." }
    $result=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if (!$result.Success -or $info.LastTaskResult -ne 0) { $result | Format-List | Out-Host; throw "gMSA-$Mode nicht erfolgreich. Details: $job" }
    $result
}
try {
    if (!$PSCmdlet.ShouldProcess($GmsaAccount,"Lokalen Einmal-Task anlegen und GPO-ACLs lesen; Ausgabe $job")) { return }
    $scanResult=Invoke-OneTask 'Scan' $scan
    $plan=Get-Content -LiteralPath (Join-Path $scan 'plan.json') -Raw | ConvertFrom-Json
    Show-CleanupPlan $plan
    foreach ($issue in @($scanResult.ValidationIssues)) { Write-Warning $issue }
    Write-Host "Alle Befunde: $(Join-Path $scan 'before.csv')"
    if ($AuditOnly -or @($plan.Targets).Count -eq 0) { Write-Host 'gMSA-Scan beendet; keine Aenderung angefordert.'; return }
    if (@($plan.Errors).Count -gt 0 -or @($scanResult.ValidationIssues).Count -gt 0) { throw 'GPO-Schritt wegen unvollstaendiger Pruefung gesperrt.' }
    Write-Host 'Ziele ausschliesslich AD System/Policies und SYSVOL/Policies. Das AGPM-Archiv wird nicht geaendert.'
    Write-Host 'Keine parallele GPO-Bearbeitung/Bereitstellung. Der Task sichert GPOs und jede betroffene DACL.'
    if ((Read-Host 'Vorschau geprueft, Wartungsfenster aktiv? Exakt BEREINIGEN eingeben') -cne 'BEREINIGEN') { return }
    $approved=Join-Path $code 'approved-plan.json'
    Copy-Item -LiteralPath (Join-Path $scan 'plan.json') -Destination $approved
    $approvedHash=(Get-FileHash -LiteralPath $approved -Algorithm SHA256).Hash
    $result=Invoke-OneTask 'Apply' $apply $approved $approvedHash
    $result.Summary | Format-List | Out-Host
    Import-Csv -LiteralPath (Join-Path $apply 'changes.csv') | Format-Table Before,After,Status,Path -Wrap | Out-Host
    $null=Read-Host 'Vorher/Nachher-Vergleich abgeschlossen; ENTER zum Fortsetzen'
} finally {
    if ($script:taskCreated) {
        $current=Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
        if ($current -and $current.State -eq 'Running') {
            Write-Warning "Task laeuft noch: $taskPath$taskName. Nicht blind erneut starten; Status/Protokoll pruefen."
        } else { Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Continue }
    }
    Write-Host "gMSA-Berichte und Sicherungen: $job"
}
