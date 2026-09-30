#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$BackupDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'AclCleanup.psm1') -Force
$files=@(Get-ChildItem -LiteralPath $BackupDirectory -Filter '*.json' -File)
if ($files.Count -eq 0) { throw 'Keine DACL-Backups im angegebenen Verzeichnis.' }
$records=@($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json })
Write-Host 'Wiederherstellung nur bei identischem Objekt und erwarteter Nachher-DACL. Konflikte bleiben unveraendert.'
Write-Host 'Auch Restore braucht ein Wartungsfenster ohne parallele ACL-/GPO-Aenderungen.'
# Parents first: restore inherited parent ACEs before comparing the original child snapshots.
foreach ($record in @($records | Sort-Object { $_.Target.Path.Length })) {
    try {
        $target=$record.Target
        $current=Get-TargetAcl $target
        $currentSddl=Get-DaclSddl $current.Acl
        if ($current.Identity -ne $target.Identity) { throw 'Objektidentitaet weicht ab.' }
        if ($currentSddl -ceq $record.BeforeSddl) { Write-Host "Bereits im Vorher-Zustand: $($target.Path)"; continue }
        # Never accept an unexpected verification result as a safe restore baseline.
        if ($currentSddl -cne $record.ExpectedAfterSddl) { throw 'Konflikt: aktuelle DACL entspricht nicht dem erwarteten Nachher-Stand.' }
        if ($PSCmdlet.ShouldProcess($target.Path,'Gesicherte DACL wiederherstellen')) {
            Set-TargetDacl $target $record.BeforeSddl $currentSddl $target.Identity
            $verify=Get-TargetAcl $target
            if ((Get-DaclSddl $verify.Acl) -cne $record.BeforeSddl) { throw 'Restore-Nachkontrolle abweichend.' }
            Write-Host "Wiederhergestellt: $($target.Path)" -ForegroundColor Green
        }
    } catch { Write-Warning "$($record.Target.Path): $($_.Exception.Message)" }
}
