#requires -Version 5.1
<#
.SYNOPSIS
Gefuehrter DACL-Assistent fuer die beschreibbaren Partitionen eines DCs und dessen GPOs.
.EXAMPLE
.\Start-ADACLCleanup.ps1 -Server dc01.contoso.local
.EXAMPLE
.\Start-ADACLCleanup.ps1 -ResumeDirectory C:\ProgramData\AD-ACL-Cleanup\Run-20260930-150000
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$Server,
    [string]$ResumeDirectory,
    [string]$OutputRoot = "$env:ProgramData\AD-ACL-Cleanup",
    [ValidateRange(1,3650)][int]$MinimumDeletedDays=30,
    [string[]]$AdditionalValidationDomain=@(),
    [switch]$AuditOnly,
    [string]$GmsaAccount
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Bitte in Windows PowerShell 5.1 (64 Bit) ausfuehren; RSAT ActiveDirectory erforderlich.'
}
Import-Module (Join-Path $PSScriptRoot 'AclCleanup.psm1') -Force
if ($WhatIfPreference) {
    Write-Host 'WhatIf: Kein Scan, keine Aenderung. Fuer eine echte Vorschau mit Berichten -AuditOnly verwenden.'
    return
}
$transcript=$false
try {
    if ($ResumeDirectory) {
        $run=(Resolve-Path -LiteralPath $ResumeDirectory).Path
        $state=Get-Content -LiteralPath (Join-Path $run 'state.json') -Raw | ConvertFrom-Json
        if ($Server -and $Server -ne $state.Server) { throw 'Bei Wiederaufnahme darf der DC nicht gewechselt werden.' }
        $Server=$state.Server; $MinimumDeletedDays=$state.MinimumDeletedDays
        $AdditionalValidationDomain=@($state.AdditionalValidationDomain)
    } else {
        $null=New-Item -ItemType Directory -Path $OutputRoot -Force
        $run=Join-Path $OutputRoot ('Run-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6))
        New-SecureDirectory $run
        $state=$null
    }
    Start-Transcript -LiteralPath (Join-Path $run ('terminal-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.log')) | Out-Null
    $transcript=$true
    Write-Host 'AD / GPO ACL-Cleanup - gefuehrter Modus' -ForegroundColor Cyan
    Write-Host "Arbeitsverzeichnis: $run"
    $envInfo=Get-CleanupEnvironment -Server $Server -AdditionalValidationDomain $AdditionalValidationDomain
    if (!$state) {
        $state=[pscustomobject]@{Server=$envInfo.Server;MinimumDeletedDays=$MinimumDeletedDays;
            AdditionalValidationDomain=@($AdditionalValidationDomain);Completed=@();Version=1}
        Write-JsonFile $state (Join-Path $run 'state.json')
    }
    Write-JsonFile $envInfo (Join-Path $run 'environment.json')
    Write-Host "Benutzer: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Host "DC: $($envInfo.Server) | Domaene: $($envInfo.Domain) | Forest: $($envInfo.Forest)"
    $envInfo.Steps | Select-Object Kind,DN,Hint | Format-Table -Wrap | Out-Host
    if (@($envInfo.UnhostedNCs).Count -gt 0) {
        Write-Warning 'Diese Forest-Partitionen liegen nicht als beschreibbare Kopie auf diesem DC und werden hier NICHT bereinigt:'
        $envInfo.UnhostedNCs | Out-Host
        Write-Host 'Fuer andere Domaenen/Anwendungspartitionen auf einem passenden DC einen eigenen Lauf starten.'
    }
    foreach ($issue in $envInfo.ValidationIssues) { Write-Warning $issue }
    Write-Host 'Gruppenhinweise sind keine Rechtegarantie. Benoetigt: Lesen + WRITE_DAC / Berechtigungen aendern.'
    Write-Host 'Neue Gruppenmitgliedschaft? Abmelden/anmelden, erhoehte PowerShell neu starten und -ResumeDirectory verwenden.'
    Write-Host 'Nur explizite DACL-ACEs mit positivem Loeschnachweis werden angeboten. SACL und Owner bleiben unveraendert.'
    Write-Host 'Aenderungen nur im Wartungsfenster ohne parallele ACL-, Wiederherstellungs- oder Migrationsarbeiten.'
    $allowChanges=$false
    if (!$AuditOnly) {
        $allowChanges=((Read-Host 'Modus: [A] Nur pruefen (Standard) / [B] Gefuehrt bereinigen') -ieq 'B')
    }
    $stop=$false
    foreach ($step in $envInfo.Steps) {
        if ($stop) { break }
        if (@($state.Completed) -contains $step.Id -and $allowChanges) {
            Write-Host "Bereits abgeschlossen: $($step.Kind). Fuer erneute Vollpruefung einen neuen Lauf starten."
            continue
        }
        Write-Host "`nNaechster Schritt: $($step.Kind) -- $($step.Hint)" -ForegroundColor Cyan
        $answer=Read-Host 'ENTER = scannen / U = ueberspringen / P = pausieren'
        if ($answer -ieq 'P') { break }
        if ($answer -ieq 'U') { continue }
        if ($step.Kind -eq 'GPO') {
            Write-Host "GPO-Ziele: $($envInfo.PoliciesDN) und $($envInfo.Sysvol)"
            Write-Host 'Das AGPM-Archiv wird nicht geaendert. Waehrend der Bereinigung keine GPO-Bearbeitung/Bereitstellung.'
            $choice=Read-Host 'Ausfuehrung: ENTER = aktueller Benutzer / T = lokaler gMSA-Task (auf berechtigtem Host)'
            if ($choice -ieq 'T') {
                if (!$GmsaAccount) { $GmsaAccount=Read-Host 'gMSA als DOMAENE\Kontoname$' }
                & (Join-Path $PSScriptRoot 'Invoke-GpoGmsaCleanup.ps1') -Server $envInfo.Server -GmsaAccount $GmsaAccount `
                    -OutputRoot $run -MinimumDeletedDays $MinimumDeletedDays -AdditionalValidationDomain $AdditionalValidationDomain `
                    -AuditOnly:(!$allowChanges)
                continue
            }
        }
        $repeat=$true
        while ($repeat) {
            $repeat=$false
            $dir=Join-Path $run ($step.Kind+'-'+$step.Id+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,4))
            $plan=New-CleanupPlan $envInfo $step $MinimumDeletedDays
            Save-CleanupPlan $plan $dir
            Show-CleanupPlan $plan
            Write-Host "Vollstaendige Vorschau: $(Join-Path $dir 'before.csv')"
            $choose=$true
            while ($choose) {
                $menu=if ($allowChanges) {'B = bereinigen / D = alle Details / R = neu scannen / ENTER = weiter / P = pausieren'}
                      else {'D = alle Details / R = neu scannen / ENTER = weiter / P = pausieren (Nur-Pruefen-Modus)'}
                $action=Read-Host $menu
                switch ($action.ToUpperInvariant()) {
                    'D' { @($plan.Rows) | Format-Table Kind,SID,Role,Type,Inherited,Status,Remove,Path -Wrap | Out-Host }
                    'R' { $repeat=$true; $choose=$false }
                    'P' { $stop=$true; $choose=$false }
                    'B' {
                        if (!$allowChanges) { Write-Warning 'Nur-Pruefen-Modus aktiv.'; continue }
                        if (@($plan.Errors).Count -gt 0 -or @($envInfo.ValidationIssues).Count -gt 0) {
                            Write-Warning 'Schritt wegen unvollstaendiger Pruefung gesperrt. Rechte/Konnektivitaet beheben und neu starten.'; continue
                        }
                        if (@($plan.Targets).Count -eq 0) { Write-Host 'Keine automatisch bereinigbaren Eintraege.'; continue }
                        Write-Host "Entfernt werden $(@($plan.Rows | Where-Object Remove).Count) explizite Allow-/Deny-ACEs auf $(@($plan.Targets).Count) Objekten."
                        if ($step.Kind -eq 'GPO') { Write-Host 'GPC und GPT werden nacheinander geaendert. Ein Fehler kann einen Teilstand hinterlassen.' }
                        if ((Read-Host 'Vorschau geprueft, Wartungsfenster aktiv? Zum Ausfuehren exakt BEREINIGEN eingeben') -ceq 'BEREINIGEN') {
                            if ($PSCmdlet.ShouldProcess($step.DN,'Freigegebene explizite DACL-ACEs sichern und entfernen')) {
                                $summary=Invoke-CleanupPlan $plan $envInfo $dir
                                if ($summary.Complete) {
                                    $state.Completed=@($state.Completed)+$step.Id
                                    Write-JsonFile $state (Join-Path $run 'state.json')
                                }
                                $null=Read-Host 'Vorher/Nachher-Vergleich oben; ENTER fuer naechsten Schritt'
                                $choose=$false
                            }
                        }
                    }
                    default { $choose=$false }
                }
            }
        }
    }
    Write-Host "`nLauf beendet. Berichte/Sicherungen: $run" -ForegroundColor Cyan
    Write-Host "Wiederaufnahme: .\Start-ADACLCleanup.ps1 -ResumeDirectory '$run'"
    Write-Host 'Unklare und fremde SIDs bleiben zur Einzelpruefung stehen. Ein sauberer Lauf bedeutet nicht, dass jede SID geklaert ist.'
} finally { if ($transcript) { Stop-Transcript | Out-Null } }
