#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-JsonFile {
    param($Value, [string]$Path)
    $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Get-TextHash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','') }
    finally { $sha.Dispose() }
}

function New-SecureDirectory {
    param([string]$Path, [string]$ReadSid, [string]$ModifySid)
    if (Test-Path -LiteralPath $Path) { throw "Ziel existiert bereits: $Path" }
    $null = New-Item -ItemType Directory -Path $Path
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    foreach ($entry in @(@{Sid=$ReadSid; Rights='ReadAndExecute'},@{Sid=$ModifySid; Rights='Modify'})) {
        if ($entry.Sid) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                [Security.Principal.SecurityIdentifier]$entry.Sid,$entry.Rights,'ContainerInherit, ObjectInherit','None','Allow')))
        }
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-CleanupEnvironment {
    param([string]$Server, [string[]]$AdditionalValidationDomain = @())
    Import-Module ActiveDirectory -ErrorAction Stop
    if (!$Server) { $Server = [string](Get-ADDomainController -Discover -Writable).HostName }
    $dc = Get-ADDomainController -Identity $Server -Server $Server
    if ($dc.IsReadOnly) { throw 'Ein beschreibbarer DC wird benoetigt.' }
    $Server = [string]$dc.HostName
    $root = Get-ADRootDSE -Server $Server
    $forest = Get-ADForest -Server $Server
    $domain = Get-ADDomain -Server $Server
    $domains = New-Object 'System.Collections.Generic.List[object]'
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $names = @($forest.Domains) + @($AdditionalValidationDomain)
    # Nur Validierung fremder Domaenen; Schreibziele bleiben auf dem gewaehlten DC.
    foreach ($name in @($forest.Domains)) {
        try {
            foreach ($trust in @(Get-ADTrust -Filter * -Server $name)) {
                if ($trust.IntraForest) { continue }
                if ($trust.ForestTransitive) {
                    $names += @((Get-ADForest -Identity $trust.Target -Server $trust.Target).Domains)
                } else { $names += [string]$trust.Target }
            }
        } catch { $issues.Add("Trust-Inventar $name : $($_.Exception.Message)") }
    }
    foreach ($name in @($names | Sort-Object -Unique)) {
        try {
            $d = Get-ADDomain -Identity $name -Server $name
            $controllers = @(Get-ADDomainController -Filter * -Server $name |
                Where-Object { !$_.IsReadOnly } | Sort-Object HostName)
            if ($controllers.Count -lt 2) { throw 'Weniger als zwei beschreibbare DCs fuer die SID-Gegenpruefung.' }
            $servers = @($controllers | Select-Object -First 2 -ExpandProperty HostName)
            foreach ($s in $servers) { $null = Get-ADRootDSE -Server $s }
            $domains.Add([pscustomobject]@{Name=[string]$d.DNSRoot; DN=[string]$d.DistinguishedName;
                Sid=[string]$d.DomainSID; Servers=$servers; OwnForest=(@($forest.Domains) -contains $d.DNSRoot)})
        } catch { $issues.Add("SID-Pruefbereich $name : $($_.Exception.Message)") }
    }
    $ntds=Get-ADObject -Identity $root.dsServiceName -Server $Server -Properties hasMasterNCs,'msDS-hasMasterNCs'
    $masterNCs=@($ntds.hasMasterNCs)+@($ntds.'msDS-hasMasterNCs')
    $ncs = @($root.NamingContexts | ForEach-Object { [string]$_ } | Where-Object { $masterNCs -contains $_ })
    if ($ncs -notcontains [string]$root.DefaultNamingContext) { throw 'Beschreibbare Naming Contexts konnten nicht verlaesslich ermittelt werden.' }
    $steps = New-Object 'System.Collections.Generic.List[object]'
    foreach ($nc in $ncs) {
        if ($nc -eq $root.SchemaNamingContext) { $kind='Schema'; $order=50; $hint='Schema Admins oder delegiertes WRITE_DAC' }
        elseif ($nc -eq $root.ConfigurationNamingContext) { $kind='Configuration'; $order=40; $hint='Enterprise Admins oder delegiertes WRITE_DAC' }
        elseif ($nc -eq $root.DefaultNamingContext) { $kind='Domain'; $order=10; $hint='Domain Admins oder delegiertes WRITE_DAC' }
        elseif ($nc -like 'DC=DomainDnsZones,*') { $kind='DomainDNS'; $order=20; $hint='Domain Admins bzw. delegierte DNS-Partitionsrechte' }
        elseif ($nc -like 'DC=ForestDnsZones,*') { $kind='ForestDNS'; $order=30; $hint='Forest-weite Delegation / Enterprise Admins; effektive ACL entscheidet' }
        else { $kind='Application'; $order=35; $hint='WRITE_DAC gemaess ACL der Anwendungspartition' }
        $steps.Add([pscustomobject]@{Id=(Get-TextHash $nc).Substring(0,12); Kind=$kind; DN=$nc; Order=$order; Hint=$hint})
    }
    $policiesDN = "CN=Policies,CN=System,$($root.DefaultNamingContext)"
    $steps.Add([pscustomobject]@{Id='GPO'; Kind='GPO'; DN=$policiesDN; Order=60;
        Hint='GPO: Berechtigungen aendern auf GPC und GPT; AGPM-gMSA optional'})
    $unhosted = @()
    try {
        $unhosted = @(Get-ADObject -Server $Server -SearchBase "CN=Partitions,$($root.ConfigurationNamingContext)" `
            -LDAPFilter '(&(objectClass=crossRef)(nCName=*))' -Properties nCName |
            Where-Object { $ncs -notcontains [string]$_.nCName } | Select-Object -ExpandProperty nCName)
    } catch { $issues.Add("Partitionsinventar: $($_.Exception.Message)") }
    [pscustomobject]@{Server=$Server; Forest=[string]$forest.Name; Domain=[string]$domain.DNSRoot;
        DomainSid=[string]$domain.DomainSID; RootDomain=[string]$forest.RootDomain;
        DefaultNC=[string]$root.DefaultNamingContext; SchemaNC=[string]$root.SchemaNamingContext;
        PoliciesDN=$policiesDN; Sysvol="\\$Server\SYSVOL\$($domain.DNSRoot)\Policies";
        Domains=@($domains.ToArray()); ValidationIssues=@($issues.ToArray());
        Steps=@($steps.ToArray() | Sort-Object Order,DN); UnhostedNCs=$unhosted;
        AdditionalValidationDomain=@($AdditionalValidationDomain)}
}

function Get-SidLdapValue {
    param([string]$Sid)
    $s = New-Object Security.Principal.SecurityIdentifier($Sid)
    $bytes = New-Object byte[] $s.BinaryLength
    $s.GetBinaryForm($bytes,0)
    (($bytes | ForEach-Object { '\' + $_.ToString('X2') }) -join '')
}

function Resolve-SidName {
    param([string]$Sid)
    try {
        $sidObject=New-Object Security.Principal.SecurityIdentifier($Sid)
        [string]$sidObject.Translate([Security.Principal.NTAccount]).Value
    } catch [Security.Principal.IdentityNotMappedException] { return $null }
}

function Get-SidVerdict {
    param([string]$Sid, $Environment, [hashtable]$Cache, [int]$MinimumDeletedDays=30, [switch]$Fresh)
    if (!$Fresh -and $Cache.ContainsKey($Sid)) { return $Cache[$Sid] }
    $status='Unklar'; $reason=''; $eligible=$false
    if ($Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        $status='SystemSID'; $reason='Keine AD-Domaenen-SID; wird nicht entfernt.'
    } elseif ([long]$Matches[1] -lt 1000) {
        $status='Geschuetzt'; $reason='Reservierter / integrierter RID unter 1000.'
    } else {
        try {
            if (Resolve-SidName $Sid) {
                $v=[pscustomobject]@{SID=$Sid;Status='Aufloesbar';Reason='Windows kann die SID aufloesen; bleibt erhalten.';Eligible=$false}
                $Cache[$Sid]=$v
                return $v
            }
        } catch {
            $v=[pscustomobject]@{SID=$Sid;Status='Unklar';Reason="Namensaufloesung fehlgeschlagen: $($_.Exception.Message)";Eligible=$false}
            $Cache[$Sid]=$v
            return $v
        }
        $prefix = $Sid.Substring(0,$Sid.LastIndexOf('-'))
        $authority = @($Environment.Domains | Where-Object { $_.OwnForest -and $_.Sid -eq $prefix })
        if ($authority.Count -ne 1) {
            $status='FremdeSID'; $reason='Nicht aus einer verifizierten Domaene des eigenen Forests.'
        } elseif (@($Environment.ValidationIssues).Count -gt 0) {
            $reason='SID-Pruefbereich unvollstaendig; keine automatische Freigabe.'
        } else {
            try {
                $hex = Get-SidLdapValue $Sid
                $found = $false
                foreach ($d in $Environment.Domains) {
                    foreach ($s in $d.Servers) {
                        $live = @(Get-ADObject -Server $s -SearchBase $d.DN -SearchScope Subtree `
                            -LDAPFilter "(|(objectSid=$hex)(sIDHistory=$hex))" -ResultSetSize 1)
                        if ($live.Count -gt 0) { $found=$true; break }
                    }
                    if ($found) { break }
                }
                if ($found) { $status='AktivOderSIDHistory'; $reason='Lebendes Objekt, FSP oder SIDHistory gefunden.' }
                else {
                    $oldEnough = $true
                    foreach ($s in $authority[0].Servers) {
                        $deleted = @(Get-ADObject -Server $s -SearchBase $authority[0].DN -IncludeDeletedObjects `
                            -LDAPFilter "(&(isDeleted=TRUE)(objectSid=$hex))" -Properties whenChanged -ResultSetSize 2)
                        if ($deleted.Count -ne 1 -or !$deleted[0].whenChanged -or
                            ([datetime]$deleted[0].whenChanged).ToUniversalTime() -gt [datetime]::UtcNow.AddDays(-$MinimumDeletedDays)) {
                            $oldEnough=$false
                        }
                    }
                    if ($oldEnough) {
                        $status='Loeschkandidat'; $reason="Kein aktiver Bezug im Pruefbereich; Loeschnachweis auf zwei DCs, mindestens $MinimumDeletedDays Tage alt."
                        $eligible=$true
                    } else { $reason='Kein ausreichend alter Loeschnachweis auf beiden DCs (z.B. Garbage Collection / frische Loeschung).' }
                }
            } catch { $reason="SID-Pruefung fehlgeschlagen: $($_.Exception.Message)" }
        }
    }
    $v = [pscustomobject]@{SID=$Sid; Status=$status; Reason=$reason; Eligible=$eligible}
    $Cache[$Sid]=$v
    $v
}

function Open-AdEntry {
    param([string]$Server,[string]$DN)
    $entry = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$($DN.Replace('/','\/'))")
    $entry.AuthenticationType = [DirectoryServices.AuthenticationTypes]'Secure, Signing, Sealing, ServerBind'
    $entry.Options.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl, Owner'
    $entry
}

function Get-DaclSddl {
    param($Acl)
    $Acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
}

function Get-TargetAcl {
    param($Target)
    if ($Target.Kind -eq 'AD') {
        $entry=Open-AdEntry $Target.Server $Target.Path
        try {
            $entry.RefreshCache(@('ntSecurityDescriptor','objectGUID'))
            if ($entry.Properties['ntSecurityDescriptor'].Count -eq 0) {
                throw 'Security Descriptor nicht lesbar; Objekt wird als Lesefehler behandelt.'
            }
            $id=(New-Object guid(,$entry.Properties['objectGUID'][0])).ToString()
            [pscustomobject]@{Acl=$entry.ObjectSecurity; Identity=$id; IsDirectory=$false}
        } finally { $entry.Dispose() }
    } else {
        $item=Get-Item -LiteralPath $Target.Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse Point wird nicht verarbeitet.' }
        [pscustomobject]@{Acl=(Get-Acl -LiteralPath $Target.Path);
            Identity=('{0}|{1}' -f $item.PSIsContainer,$item.CreationTimeUtc.Ticks); IsDirectory=[bool]$item.PSIsContainer}
    }
}

function Set-TargetDacl {
    param($Target,[string]$Sddl,[string]$ExpectedSddl,[string]$ExpectedIdentity)
    # Unmittelbare Konfliktpruefung. Kein atomarer Compare-and-swap fuer LDAP+SMB!
    $current=Get-TargetAcl $Target
    if ($current.Identity -ne $ExpectedIdentity -or (Get-DaclSddl $current.Acl) -cne $ExpectedSddl) {
        throw 'Konflikt: Objekt oder DACL seit der Vorschau geaendert. Neu scannen.'
    }
    if ($Target.Kind -eq 'AD') {
        $entry=Open-AdEntry $Target.Server $Target.Path
        try {
            $entry.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
            $entry.RefreshCache(@('ntSecurityDescriptor'))
            if ((Get-DaclSddl $entry.ObjectSecurity) -cne $ExpectedSddl) { throw 'DACL-Konflikt beim Schreiben.' }
            $acl=New-Object DirectoryServices.ActiveDirectorySecurity
            $acl.SetSecurityDescriptorSddlForm($Sddl,[Security.AccessControl.AccessControlSections]::Access)
            $entry.ObjectSecurity=$acl
            $entry.CommitChanges()
        } finally { $entry.Dispose() }
    } else {
        if ($current.IsDirectory) { $acl=New-Object Security.AccessControl.DirectorySecurity }
        else { $acl=New-Object Security.AccessControl.FileSecurity }
        $acl.SetSecurityDescriptorSddlForm($Sddl,[Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -LiteralPath $Target.Path -AclObject $acl
    }
}

function Get-AdTargets {
    param($Environment,$Step)
    $root=Open-AdEntry $Environment.Server $Step.DN
    $search=New-Object DirectoryServices.DirectorySearcher($root)
    $search.PageSize=500; $search.ReferralChasing=[DirectoryServices.ReferralChasingOption]::None
    $search.SearchScope=[DirectoryServices.SearchScope]::Subtree
    # Tombstoned DNS objects are still live AD objects: deliberately included.
    $search.Filter='(objectClass=*)'
    $null=$search.PropertiesToLoad.Add('distinguishedName')
    $results=$null
    try {
        $results=$search.FindAll()
        foreach ($r in $results) {
            $dn=[string]$r.Properties['distinguishedname'][0]
            if ($Step.Kind -ne 'GPO' -and ($dn -eq $Environment.PoliciesDN -or
                $dn.EndsWith(','+$Environment.PoliciesDN,[StringComparison]::OrdinalIgnoreCase))) { continue }
            # Prevent nested naming contexts, in particular Schema under Configuration, from double handling.
            $nested=$false
            foreach ($other in @($Environment.Steps | Where-Object { $_.Kind -ne 'GPO' -and $_.DN -ne $Step.DN })) {
                if ($other.DN.EndsWith(','+$Step.DN,[StringComparison]::OrdinalIgnoreCase) -and
                    ($dn -eq $other.DN -or $dn.EndsWith(','+$other.DN,[StringComparison]::OrdinalIgnoreCase))) { $nested=$true; break }
            }
            if (!$nested) { [pscustomobject]@{Kind='AD'; Path=$dn; Server=$Environment.Server} }
        }
    } finally { if ($results) { $results.Dispose() }; $search.Dispose(); $root.Dispose() }
}

function Get-SysvolTargets {
    param([string]$Path)
    $queue=New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($Path)
    while ($queue.Count -gt 0) {
        $p=$queue.Dequeue()
        $item=Get-Item -LiteralPath $p -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse Point in SYSVOL: $p" }
        [pscustomobject]@{Kind='File'; Path=$item.FullName; Server=''}
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $p -Force)) { $queue.Enqueue($child.FullName) }
        }
    }
}

function New-CleanupPlan {
    param($Environment,$Step,[int]$MinimumDeletedDays=30)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    $targets=New-Object 'System.Collections.Generic.List[object]'
    $errors=New-Object 'System.Collections.Generic.List[string]'
    $cache=@{}; $count=0
    $visit = {
        param($t)
        try {
            $snapshot=Get-TargetAcl $t
            $acl=$snapshot.Acl; $sids=New-Object 'System.Collections.Generic.HashSet[string]'
            $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            foreach ($ace in $rules) {
                $sid=$ace.IdentityReference.Value
                if ($sid -notlike 'S-1-5-21-*') { continue }
                $v=Get-SidVerdict $sid $Environment $cache $MinimumDeletedDays
                if ($v.Status -in @('AktivOderSIDHistory','Aufloesbar','Geschuetzt','SystemSID')) { continue }
                if ($v.Eligible -and !$ace.IsInherited) { $null=$sids.Add($sid) }
                $rights=if ($t.Kind -eq 'AD') { [string]$ace.ActiveDirectoryRights } else { [string]$ace.FileSystemRights }
                $rows.Add([pscustomobject]@{Kind=$t.Kind; Path=$t.Path; SID=$sid; Role='DACL';
                    Type=[string]$ace.AccessControlType; Rights=$rights; Inherited=[bool]$ace.IsInherited;
                    Status=$v.Status; Remove=([bool]$v.Eligible -and !$ace.IsInherited); Reason=$v.Reason})
            }
            $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier])
            if ($owner -and $owner.Value -like 'S-1-5-21-*') {
                $v=Get-SidVerdict $owner.Value $Environment $cache $MinimumDeletedDays
                if ($v.Status -notin @('AktivOderSIDHistory','Aufloesbar','Geschuetzt')) {
                    $rows.Add([pscustomobject]@{Kind=$t.Kind;Path=$t.Path;SID=$owner.Value;Role='Owner';
                        Type='Owner';Rights='';Inherited=$false;Status=$v.Status;Remove=$false;Reason='Owner wird nur gemeldet. '+$v.Reason})
                }
            }
            if ($sids.Count -gt 0) {
                $targets.Add([pscustomobject]@{Kind=$t.Kind;Path=$t.Path;Server=$t.Server;
                    Identity=$snapshot.Identity;BeforeSddl=(Get-DaclSddl $acl);SIDs=@($sids | Sort-Object)})
            }
        } catch { $errors.Add("$($t.Path) : $($_.Exception.Message)") }
    }
    try {
        Get-AdTargets $Environment $Step | ForEach-Object {
            $count++; if ($count % 100 -eq 0) { Write-Progress -Activity "ACL-Scan $($Step.Kind)" -Status "$count Objekte" }
            & $visit $_
        }
        if ($Step.Kind -eq 'GPO') { Get-SysvolTargets $Environment.Sysvol | ForEach-Object { $count++; & $visit $_ } }
    } catch { $errors.Add("Enumeration unvollstaendig: $($_.Exception.Message)") }
    Write-Progress -Activity "ACL-Scan $($Step.Kind)" -Completed
    [pscustomobject]@{Version=1;CreatedUtc=[datetime]::UtcNow.ToString('o');Server=$Environment.Server;
        Domain=$Environment.Domain;Step=$Step;MinimumDeletedDays=$MinimumDeletedDays;
        AdditionalValidationDomain=@($Environment.AdditionalValidationDomain);Scanned=$count;
        Targets=@($targets.ToArray());Rows=@($rows.ToArray());Errors=@($errors.ToArray())}
}

function Show-CleanupPlan {
    param($Plan)
    Write-Host "`n--- $($Plan.Step.Kind): $($Plan.Step.DN) ---" -ForegroundColor Cyan
    Write-Host "Gelesen: $($Plan.Scanned) | Aenderungsziele: $(@($Plan.Targets).Count) | Lesefehler: $(@($Plan.Errors).Count)"
    @($Plan.Rows) | Group-Object Status,Role,Inherited | Select-Object Count,Name | Format-Table -AutoSize | Out-Host
    @($Plan.Rows | Where-Object Remove) | Select-Object -First 25 Kind,SID,Type,Inherited,Path | Format-Table -Wrap | Out-Host
    if (@($Plan.Rows | Where-Object Remove).Count -gt 25) { Write-Host 'Weitere Kandidaten stehen in before.csv; Menue D zeigt alle.' }
    foreach ($e in @($Plan.Errors | Select-Object -First 10)) { Write-Warning $e }
    Write-Host 'Geerbte ACEs: nur an ihrer expliziten Quelle entfernen. Owner: nur Bericht.'
}

function Save-CleanupPlan {
    param($Plan,[string]$Directory)
    $null=New-Item -ItemType Directory -Path $Directory -Force
    Write-JsonFile $Plan (Join-Path $Directory 'plan.json')
    @($Plan.Rows) | Export-Csv -LiteralPath (Join-Path $Directory 'before.csv') -NoTypeInformation -Encoding UTF8
}

function Invoke-CleanupPlan {
    param($Plan,$Environment,[string]$Directory)
    if ($Plan.Version -ne 1) { throw 'Unbekannte Planversion.' }
    if ($Plan.Server -ne $Environment.Server -or $Plan.Domain -ne $Environment.Domain) { throw 'Plan und Zielumgebung stimmen nicht ueberein.' }
    if ([datetime]::UtcNow -gt ([datetime]$Plan.CreatedUtc).ToUniversalTime().AddHours(4)) { throw 'Plan aelter als vier Stunden. Neu scannen.' }
    if (@($Plan.Errors).Count -gt 0 -or @($Environment.ValidationIssues).Count -gt 0) { throw 'Unvollstaendige Pruefung: Schritt bleibt gesperrt.' }
    $null=New-Item -ItemType Directory -Path $Directory -Force
    $backupDir=Join-Path $Directory 'DaclBackups'
    $null=New-Item -ItemType Directory -Path $backupDir -Force
    if ($Plan.Step.Kind -eq 'GPO' -and @($Plan.Targets).Count -gt 0) {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoBackup=Join-Path $Directory 'GpoBackup'
        $null=New-Item -ItemType Directory -Path $gpoBackup -Force
        $null=Backup-GPO -All -Domain $Environment.Domain -Server $Environment.Server -Path $gpoBackup -ErrorAction Stop
    }
    $outcomes=New-Object 'System.Collections.Generic.List[object]'
    $cache=@{}
    # Children first: changing an inheritable parent ACE can otherwise stale all child previews.
    $ordered=@($Plan.Targets | Sort-Object @{Expression={$_.Path.Length};Descending=$true})
    foreach ($target in $ordered) {
        $backupFile=$null; $beforeCount=$null; $afterCount=$null; $state='Fehler'; $detail=''
        try {
            # A plan is bound to the selected partition / SYSVOL; reject injected targets.
            if ($target.Kind -eq 'AD') {
                if ($target.Server -ne $Environment.Server -or
                    !($target.Path -eq $Plan.Step.DN -or $target.Path.EndsWith(','+$Plan.Step.DN,[StringComparison]::OrdinalIgnoreCase))) {
                    throw 'AD-Ziel liegt ausserhalb des Schritts.'
                }
            } elseif ($target.Kind -eq 'File') {
                if ($Plan.Step.Kind -ne 'GPO' -or !($target.Path -eq $Environment.Sysvol -or
                    $target.Path.StartsWith($Environment.Sysvol+'\',[StringComparison]::OrdinalIgnoreCase)) -or
                    $target.Path -match '\\\.\.?\\') { throw 'Dateiziel liegt ausserhalb SYSVOL Policies.' }
            } else { throw 'Unbekannte Zielart.' }
            foreach ($sid in $target.SIDs) {
                $v=Get-SidVerdict $sid $Environment $cache $Plan.MinimumDeletedDays -Fresh
                if (!$v.Eligible) { throw "SID nicht mehr freigegeben: $sid ($($v.Status))" }
            }
            $current=Get-TargetAcl $target
            if ($current.Identity -ne $target.Identity -or (Get-DaclSddl $current.Acl) -cne $target.BeforeSddl) {
                throw 'Objekt/DACL seit Vorschau geaendert; neuer Scan erforderlich.'
            }
            $acl=$current.Acl
            $rules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) |
                Where-Object { @($target.SIDs) -contains $_.IdentityReference.Value })
            $beforeCount=$rules.Count
            foreach ($rule in $rules) { $acl.RemoveAccessRuleSpecific($rule) }
            if (@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])).Count -eq 0) {
                throw 'Die resultierende DACL waere leer. Automatische Aenderung gesperrt.'
            }
            $afterSddl=Get-DaclSddl $acl
            $record=[pscustomobject]@{Version=1;TimeUtc=[datetime]::UtcNow.ToString('o');Target=$target;
                BeforeSddl=$target.BeforeSddl;ExpectedAfterSddl=$afterSddl;ActualAfterSddl=$null;Status='Prepared'}
            $backupFile=Join-Path $backupDir ((Get-TextHash ($target.Kind+'|'+$target.Path))+'.json')
            if (Test-Path -LiteralPath $backupFile) { throw 'Sicherungsdatei existiert bereits; neuen Durchlauf verwenden.' }
            Write-JsonFile $record $backupFile
            Set-TargetDacl $target $afterSddl $target.BeforeSddl $target.Identity
            $verify=Get-TargetAcl $target
            $actual=Get-DaclSddl $verify.Acl
            $afterCount=@($verify.Acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) |
                Where-Object { @($target.SIDs) -contains $_.IdentityReference.Value }).Count
            $record.ActualAfterSddl=$actual
            if ($afterCount -ne 0 -or $actual -cne $afterSddl) {
                $record.Status='VerificationFailed'; Write-JsonFile $record $backupFile
                throw 'Nachkontrolle abweichend; Sicherung vorhanden. Schritt pruefen.'
            }
            $record.Status='Verified'; Write-JsonFile $record $backupFile
            $state='Verifiziert'; $detail='Explizite ACEs entfernt; DACL erneut gelesen.'
        } catch { $detail=$_.Exception.Message }
        $row=[pscustomobject]@{Kind=$target.Kind;Path=$target.Path;Before=$beforeCount;After=$afterCount;Status=$state;Detail=$detail;Backup=$backupFile}
        $outcomes.Add($row)
        Write-Host ("{0}: {1} -> {2} | {3}" -f $state,$beforeCount,$afterCount,$target.Path) -ForegroundColor $(if ($state -eq 'Verifiziert') {'Green'} else {'Yellow'})
        if ($state -ne 'Verifiziert') { Write-Warning $detail }
        @($outcomes.ToArray()) | Export-Csv -LiteralPath (Join-Path $Directory 'changes.csv') -NoTypeInformation -Encoding UTF8
        # Stop at first failure: GPC and GPT are not a distributed transaction.
        if ($state -ne 'Verifiziert') { break }
    }
    $after=New-CleanupPlan $Environment $Plan.Step $Plan.MinimumDeletedDays
    @($after.Rows) | Export-Csv -LiteralPath (Join-Path $Directory 'after.csv') -NoTypeInformation -Encoding UTF8
    $summary=[pscustomobject]@{BeforeExplicit=@($Plan.Rows | Where-Object Remove).Count;
        AfterExplicit=@($after.Rows | Where-Object Remove).Count;
        BeforeInherited=@($Plan.Rows | Where-Object { $_.Role -eq 'DACL' -and $_.Inherited -and $_.Status -eq 'Loeschkandidat' }).Count;
        AfterInherited=@($after.Rows | Where-Object { $_.Role -eq 'DACL' -and $_.Inherited -and $_.Status -eq 'Loeschkandidat' }).Count;
        Changed=@($outcomes.ToArray() | Where-Object Status -eq 'Verifiziert').Count;
        Errors=@($outcomes.ToArray() | Where-Object Status -ne 'Verifiziert').Count + @($after.Errors).Count;
        Unprocessed=@($Plan.Targets).Count-$outcomes.Count;
        Complete=(@($outcomes.ToArray() | Where-Object Status -ne 'Verifiziert').Count -eq 0 -and
            @($after.Errors).Count -eq 0 -and @($after.Rows | Where-Object Remove).Count -eq 0 -and $outcomes.Count -eq @($Plan.Targets).Count)}
    Write-JsonFile $summary (Join-Path $Directory 'summary.json')
    $summary | Format-List | Out-Host
    Write-Host 'Nachkontrolle gilt fuer diesen DC. AD-/DFSR-Replikation und spaetere SDProp-Laeufe separat pruefen.'
    $summary
}

Export-ModuleMember -Function *
