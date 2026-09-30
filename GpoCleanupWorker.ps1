#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RequestPath,
    [Parameter(Mandatory)][string]$RequestSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$exitCode=1; $request=$null; $logging=$false
try {
    if ((Get-FileHash -LiteralPath $RequestPath -Algorithm SHA256).Hash -cne $RequestSha256) { throw 'Request-Hash stimmt nicht.' }
    $request=Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    if ([datetime]::UtcNow -gt ([datetime]$request.ExpiresUtc).ToUniversalTime()) { throw 'Task-Freigabe abgelaufen.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $request.GmsaSid) { throw 'Falsches Ausfuehrungskonto.' }
    Import-Module (Join-Path $PSScriptRoot 'AclCleanup.psm1') -Force
    Start-Transcript -LiteralPath (Join-Path $request.OutputDirectory 'worker.log') | Out-Null
    $logging=$true
    $environment=Get-CleanupEnvironment -Server $request.Server -AdditionalValidationDomain @($request.AdditionalValidationDomain)
    $step=@($environment.Steps | Where-Object Kind -eq 'GPO')[0]
    if ($request.Mode -eq 'Scan') {
        $plan=New-CleanupPlan $environment $step $request.MinimumDeletedDays
        Save-CleanupPlan $plan $request.OutputDirectory
        Show-CleanupPlan $plan
        $result=[pscustomobject]@{Success=$true;Mode='Scan';Errors=@($plan.Errors);ValidationIssues=@($environment.ValidationIssues)}
    } elseif ($request.Mode -eq 'Apply') {
        if ((Get-FileHash -LiteralPath $request.PlanPath -Algorithm SHA256).Hash -cne $request.PlanSha256) { throw 'Freigegebener Plan wurde geaendert.' }
        $plan=Get-Content -LiteralPath $request.PlanPath -Raw | ConvertFrom-Json
        if ($plan.Step.Kind -ne 'GPO' -or $plan.Step.DN -ne $environment.PoliciesDN) { throw 'Worker akzeptiert nur den lokalen GPO-Schritt.' }
        $summary=Invoke-CleanupPlan $plan $environment $request.OutputDirectory
        $result=[pscustomobject]@{Success=[bool]$summary.Complete;Mode='Apply';Summary=$summary}
    } else { throw 'Unbekannter Task-Modus.' }
    Write-JsonFile $result (Join-Path $request.OutputDirectory 'result.json')
    if ($result.Success) { $exitCode=0 }
} catch {
    if ($request -and (Test-Path -LiteralPath $request.OutputDirectory)) {
        [pscustomobject]@{Success=$false;Error=$_.Exception.Message} | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $request.OutputDirectory 'result.json') -Encoding UTF8
    }
    Write-Error $_ -ErrorAction Continue
} finally { if ($logging) { Stop-Transcript | Out-Null } }
exit $exitCode
