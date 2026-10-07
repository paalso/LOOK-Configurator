# Помощники: владелец и список дозволов (DACL) файлов. Всё по SID, поэтому не зависит от языка Windows.
# Владелец меняется через takeown/icacls (они сами включают привилегии), DACL через Get-Acl/Set-Acl
# (записывается только раздел Access, поэтому право WRITE_OWNER для этого не нужно).

$Script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

function Get-FileSecuritySnapshot {
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -Path $Path
    @{
        Owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        Dacl  = $acl.GetSecurityDescriptorSddlForm('Access')
    }
}

function Set-FileOwner {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sid)
    if ($Sid -eq 'S-1-5-32-544') { Invoke-Native -File 'takeown.exe' -Arguments @('/F', $Path, '/A') | Out-Null }
    else {
        $who = if ($Sid -eq $Script:TrustedInstallerSid) { 'NT SERVICE\TrustedInstaller' } else { "*$Sid" }
        Invoke-Native -File 'icacls.exe' -Arguments @($Path, '/setowner', $who) | Out-Null
    }
}

function Set-FileDacl {
    # Отключает наследование, удаляет ВСЕ прежние записи и выдаёт перечисленные: @{ SID = 'FullControl' | 'ReadAndExecute' | ... }.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Entries)
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in @($acl.Access | ForEach-Object { $_.IdentityReference } | Select-Object -Unique)) { $acl.PurgeAccessRules($id) }
    foreach ($sid in $Entries.Keys) {
        $id = New-Object System.Security.Principal.SecurityIdentifier $sid
        $rights = [System.Security.AccessControl.FileSystemRights]$Entries[$sid]
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, $rights, 'None', 'None', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Test-FileSecurity {
    # @{ Ok; Actual } : владелец и DACL должны совпадать с ожидаемыми ТОЧНО (без лишних записей, без наследования).
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$OwnerSid, [Parameter(Mandatory)][hashtable]$Expected)
    $acl = Get-Acl -Path $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    $good = @{}; $bad = @(); $dups = $false
    foreach ($r in $acl.Access) {
        $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $want = $null
        if ($Expected.ContainsKey($sid)) { $want = [System.Security.AccessControl.FileSystemRights]$Expected[$sid] }
        $isGood = ($null -ne $want) -and ($r.AccessControlType -eq 'Allow') -and ($r.FileSystemRights -eq $want) -and
                  ($r.InheritanceFlags -eq 'None') -and (-not $r.IsInherited)
        if ($isGood) { if ($good.ContainsKey($sid)) { $dups = $true } else { $good[$sid] = $r.FileSystemRights } }
        else { $bad += "$(Format-SidName $sid): $($r.AccessControlType) $($r.FileSystemRights)$(if ($r.IsInherited) { ' (успадковано)' })" }
    }
    $missing = @($Expected.Keys | Where-Object { -not $good.ContainsKey($_) })
    $ok = ($owner -eq $OwnerSid) -and $acl.AreAccessRulesProtected -and $missing.Count -eq 0 -and $bad.Count -eq 0 -and -not $dups
    $parts = @("власник: $(Format-SidName $owner)")
    $parts += @($good.Keys | ForEach-Object { "$(Format-SidName $_): $($good[$_])" })
    $parts += $bad
    if ($missing.Count -gt 0) { $parts += "відсутні: $((@($missing | ForEach-Object { Format-SidName $_ })) -join ', ')" }
    if (-not $acl.AreAccessRulesProtected) { $parts += 'успадкування увімкнено' }
    @{ Ok = $ok; Actual = ($parts -join '; ') }
}

function Restore-FileSecurity {
    # Возвращает DACL из SDDL, затем владельца (владельца вернуть может не каждая учётка: нужна привилегия SeRestorePrivilege).
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Snapshot)
    $acl = Get-Acl -Path $Path
    $acl.SetSecurityDescriptorSddlForm($Snapshot.Dacl, [System.Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -Path $Path -AclObject $acl
    $now = (Get-Acl -Path $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($now -ne $Snapshot.Owner) {
        try { Set-FileOwner -Path $Path -Sid $Snapshot.Owner }
        catch {
            Write-Ui "Власника '$Path' повернути не вдалося ($($_.Exception.Message.Split("`n")[0])). Для цього потрібна привілея SeRestorePrivilege (у таблиці прав вона лише у SysAdmin) або точка відновлення." Yellow
            Write-Log "Не удалось вернуть владельца '$Path' -> $($Snapshot.Owner)" 'WARN'
        }
    }
}

function Get-EventvwrPlan {
    # Профиль -> @{ Files; OwnerSid; Entries = @{ SID = Rights } }. Проверяет значения и разрешает принципалов (в т.ч. {SecurityAdmin}).
    param($Ctx)
    $p = $Ctx.Params
    foreach ($k in 'Files', 'Entries') { if (-not $p.ContainsKey($k) -or @($p[$k]).Count -eq 0) { throw "В profile.json нет steps -> $($Ctx.Step.UseId) -> $k" } }
    $ownerTok = if ($p.ContainsKey('Owner') -and $p.Owner) { [string]$p.Owner } else { 'Administrators' }
    $entries = @{}
    foreach ($e in @($p.Entries)) {
        $sid = Resolve-PrincipalSid -Token ([string]$e.Principal) -Profile $Ctx.Profile
        $rights = [System.Security.AccessControl.FileSystemRights]0
        if (-not [System.Enum]::TryParse([string]$e.Rights, $true, [ref]$rights) -or [int]$rights -eq 0) { throw "Entries: неизвестное право '$($e.Rights)' (например FullControl, ReadAndExecute)" }
        if ($entries.ContainsKey($sid)) { throw "Entries: принципал '$($e.Principal)' указан дважды" }
        $entries[$sid] = [string]$rights
    }
    if (@($entries.Values | Where-Object { $_ -eq 'FullControl' }).Count -eq 0) { throw 'Entries: нужна хотя бы одна запись с FullControl (иначе файл не сможет изменить никто, кроме владельца).' }
    @{ Files = @($p.Files | ForEach-Object { [string]$_ }); OwnerSid = (Resolve-PrincipalSid -Token $ownerTok -Profile $Ctx.Profile); Entries = $entries }
}
