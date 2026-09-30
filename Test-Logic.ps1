# Offline logic tests. Mocks do not validate Windows/AD/SMB/Task Scheduler integration.
# Run with PowerShell 5.1 or 7: .\Test-Logic.ps1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'AclCleanup.psm1') -Force -DisableNameChecking
$module=Get-Module AclCleanup
& $module {
    $script:testCount=0
    function Assert-True($Value,[string]$Message) {
        if (!$Value) { throw "FAILED: $Message" }
        $script:testCount++; Write-Host "PASS: $Message"
    }
    function Resolve-SidName { param($Sid); if ($script:scenario -eq 'resolved') { 'DEMO\user' } elseif ($script:scenario -eq 'translate-error') { throw 'RPC failed' } }
    function Get-SidLdapValue { param($Sid); '\01\02' }
    function Get-ADObject {
        param($Server,$SearchBase,$SearchScope,$LDAPFilter,$ResultSetSize,$Properties,[switch]$IncludeDeletedObjects)
        $script:queries++
        if ($script:scenario -eq 'query-error') { throw 'LDAP unavailable' }
        if ($IncludeDeletedObjects) {
            if ($script:scenario -eq 'no-tombstone') { return }
            if ($script:scenario -eq 'only-one-dc' -and $Server -eq 'dc2') { return }
            $age=if ($script:scenario -eq 'recent') { 1 } else { 60 }
            [pscustomobject]@{whenChanged=[datetime]::UtcNow.AddDays(-$age)}
        } elseif ($script:scenario -in @('live','sidHistory')) { [pscustomobject]@{DistinguishedName='CN=protected,DC=demo'} }
    }
    $environment=[pscustomobject]@{Server='dc1';Domain='demo';ValidationIssues=@();
        Domains=@([pscustomobject]@{Name='demo';DN='DC=demo';Sid='S-1-5-21-1-2-3';Servers=@('dc1','dc2');OwnForest=$true})}
    $sid='S-1-5-21-1-2-3-1001'
    foreach ($case in @(
        @{Name='deleted';Status='Loeschkandidat';Eligible=$true},
        @{Name='resolved';Status='Aufloesbar';Eligible=$false},
        @{Name='live';Status='AktivOderSIDHistory';Eligible=$false},
        @{Name='sidHistory';Status='AktivOderSIDHistory';Eligible=$false},
        @{Name='no-tombstone';Status='Unklar';Eligible=$false},
        @{Name='only-one-dc';Status='Unklar';Eligible=$false},
        @{Name='recent';Status='Unklar';Eligible=$false},
        @{Name='query-error';Status='Unklar';Eligible=$false},
        @{Name='translate-error';Status='Unklar';Eligible=$false}
    )) {
        $script:scenario=$case.Name; $script:queries=0
        $v=Get-SidVerdict $sid $environment @{} 30
        Assert-True ($v.Status -eq $case.Status -and $v.Eligible -eq $case.Eligible) $case.Name
    }
    $script:scenario='deleted'
    $v=Get-SidVerdict 'S-1-5-21-9-8-7-1001' $environment @{}
    Assert-True (!$v.Eligible -and $v.Status -eq 'FremdeSID') 'Foreign SID protected'
    $v=Get-SidVerdict 'S-1-5-21-1-2-3-512' $environment @{}
    Assert-True (!$v.Eligible -and $v.Status -eq 'Geschuetzt') 'Reserved RID protected'
    $v=Get-SidVerdict 'S-1-5-18' $environment @{}
    Assert-True (!$v.Eligible) 'System SID protected'
    $environment.ValidationIssues=@('Trust unavailable')
    $v=Get-SidVerdict $sid $environment @{}
    Assert-True (!$v.Eligible) 'Incomplete validation scope blocks cleanup'
    $environment.ValidationIssues=@()
    $cache=@{}; $script:queries=0
    $null=Get-SidVerdict $sid $environment $cache
    $previous=$script:queries
    $null=Get-SidVerdict $sid $environment $cache
    Assert-True ($script:queries -eq $previous) 'Scan cache used'
    $script:scenario='live'
    $v=Get-SidVerdict $sid $environment $cache -Fresh
    Assert-True (!$v.Eligible -and $script:queries -gt $previous) 'Fresh validation blocks a restored account'

    # Fake ACL exercises ordering, write guards and backup-before-write without Windows APIs.
    $script:currentSddl='BEFORE'; $script:writes=0; $script:writeScenario='normal'
    function Get-SidVerdict { param($Sid,$Environment,$Cache,$MinimumDeletedDays,[switch]$Fresh); [pscustomobject]@{Eligible=$true} }
    function Get-TargetAcl {
        param($Target)
        $acl=[pscustomobject]@{Sddl=$script:currentSddl}
        $acl | Add-Member ScriptMethod GetSecurityDescriptorSddlForm { param($sections); $this.Sddl }
        $acl | Add-Member ScriptMethod GetAccessRules {
            param($explicit,$inherited,$type)
            if ($this.Sddl -eq 'BEFORE') { [pscustomobject]@{IdentityReference=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'}} }
            [pscustomobject]@{IdentityReference=[pscustomobject]@{Value='S-1-5-18'}}
        }
        $acl | Add-Member ScriptMethod RemoveAccessRuleSpecific { param($rule); $this.Sddl='AFTER' }
        [pscustomobject]@{Acl=$acl;Identity='id1';IsDirectory=$false}
    }
    function Set-TargetDacl {
        param($Target,$Sddl,$ExpectedSddl,$ExpectedIdentity)
        $backups=@(Get-ChildItem (Join-Path $script:testDir 'DaclBackups') -Filter '*.json')
        Assert-True ($backups.Count -eq 1) 'Backup exists before write'
        $script:writes++
        $script:currentSddl=if ($script:writeScenario -eq 'verify-failure') { 'UNEXPECTED' } else { $Sddl }
    }
    function New-CleanupPlan { param($Environment,$Step,$MinimumDeletedDays); [pscustomobject]@{Rows=@();Errors=@()} }
    $plan=[pscustomobject]@{Version=1;CreatedUtc=[datetime]::UtcNow.ToString('o');Server='dc1';Domain='demo';
        Step=[pscustomobject]@{Kind='Domain';DN='DC=demo'};MinimumDeletedDays=30;Errors=@();
        Targets=@([pscustomobject]@{Kind='AD';Server='dc1';Path='CN=test,DC=demo';Identity='id1';BeforeSddl='BEFORE';SIDs=@($sid)});
        Rows=@([pscustomobject]@{Remove=$true;Role='DACL';Inherited=$false;Status='Loeschkandidat'})}
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('AclCleanupTests-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $temp
    try {
        $script:testDir=Join-Path $temp 'normal'
        $result=Invoke-CleanupPlan $plan $environment $script:testDir
        Assert-True ($script:writes -eq 1 -and $result.Complete) 'Verified write completes'
        $script:currentSddl='DRIFT'; $script:writes=0; $script:testDir=Join-Path $temp 'drift'
        $result=Invoke-CleanupPlan $plan $environment $script:testDir
        Assert-True ($script:writes -eq 0 -and !$result.Complete) 'Changed DACL blocks write'
        $script:currentSddl='BEFORE'; $script:writes=0; $script:writeScenario='verify-failure'; $script:testDir=Join-Path $temp 'verify'
        $result=Invoke-CleanupPlan $plan $environment $script:testDir
        Assert-True ($script:writes -eq 1 -and !$result.Complete) 'Verification failure is not success'
        $script:writes=0; $plan.Targets[0].Path='CN=test,DC=other'; $script:testDir=Join-Path $temp 'scope'
        $result=Invoke-CleanupPlan $plan $environment $script:testDir
        Assert-True ($script:writes -eq 0 -and !$result.Complete) 'Out-of-scope target rejected'
        $plan.Targets[0].Path='CN=test,DC=demo'; $plan.CreatedUtc=[datetime]::UtcNow.AddHours(-5).ToString('o')
        $blocked=$false
        try { $null=Invoke-CleanupPlan $plan $environment (Join-Path $temp 'expired') } catch { $blocked=$true }
        Assert-True ($blocked -and $script:writes -eq 0) 'Expired plan rejected'
        $plan.CreatedUtc=[datetime]::UtcNow.ToString('o'); $plan.Errors=@('Read error'); $blocked=$false
        try { $null=Invoke-CleanupPlan $plan $environment (Join-Path $temp 'read-error') } catch { $blocked=$true }
        Assert-True ($blocked -and $script:writes -eq 0) 'Partial scan rejected'
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    Write-Host "RESULT: $script:testCount checks passed (mocked; no AD integration)."
}
# Remove all test doubles with the module instance.
Remove-Module AclCleanup
