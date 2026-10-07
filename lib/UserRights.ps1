# Помощники: назначение прав пользователей (User Rights Assignment) через secedit [Privilege Rights].
# Принципалы в профиле: известное имя (Administrators, Users, Local Service...), {Роль} (учётная запись с таким Role
# в steps -> local-accounts -> Accounts), SID (S-1-5-...) или имя локальной учётной записи/группы. Внутри всё по SID.

$Script:WellKnownPrincipals = @{
    'administrators'      = 'S-1-5-32-544'
    'users'               = 'S-1-5-32-545'
    'guests'              = 'S-1-5-32-546'
    'backup operators'    = 'S-1-5-32-551'
    'remote desktop users' = 'S-1-5-32-555'
    'local service'       = 'S-1-5-19'
    'network service'     = 'S-1-5-20'
    'service'             = 'S-1-5-6'
    'system'              = 'S-1-5-18'
    'everyone'            = 'S-1-1-0'
    'anonymous logon'     = 'S-1-5-7'
    'authenticated users' = 'S-1-5-11'
    'trustedinstaller'    = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    'nt service\trustedinstaller' = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    'all application packages' = 'S-1-15-2-1'
    'all restricted application packages' = 'S-1-15-2-2'
}

function Convert-NameToSid {
    param([Parameter(Mandatory)][string]$Name)
    try { (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { $null }
}

function Get-RoleAccountName {
    param($Profile, [Parameter(Mandatory)][string]$Role)
    $accounts = @()
    if ($Profile.steps -and $Profile.steps.ContainsKey('local-accounts')) {
        $accounts = @($Profile.steps['local-accounts'].Accounts | Where-Object { $_.ContainsKey('Role') -and $_.Role -eq $Role })
    }
    if ($accounts.Count -ne 1) {
        throw "Роль '$Role': в steps -> local-accounts -> Accounts нужна ровно одна учётная запись с Role='$Role' (найдено: $($accounts.Count))"
    }
    [string]$accounts[0].Name
}

function Resolve-PrincipalSid {
    param([Parameter(Mandatory)][string]$Token, $Profile)
    $t = $Token.Trim()
    if ($t -match '^\*?(S-1-\d[\d-]*)$') { return $Matches[1] }
    if ($t -match '^\{(.+)\}$') {
        $name = Get-RoleAccountName -Profile $Profile -Role $Matches[1]
        $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if (-not $u) { throw "Учётная запись '$name' (роль $t) не найдена. Сначала выполните шаг local-accounts." }
        return $u.SID.Value
    }
    $k = $t.ToLowerInvariant()
    if ($Script:WellKnownPrincipals.ContainsKey($k)) { return $Script:WellKnownPrincipals[$k] }
    $sid = Convert-NameToSid $t
    if (-not $sid) { throw "Не удалось определить SID для '$Token'" }
    $sid
}

function Get-ResolvedRights {
    # Rights из профиля -> @{ SeXxx = @(SID, ...) } (отсортировано, без повторов). Бросает исключение при ошибке.
    param($Ctx)
    $p = $Ctx.Params
    if (-not $p.ContainsKey('Rights') -or $p.Rights.Count -eq 0) { throw 'В profile.json нет steps -> user-rights -> Rights' }
    $res = @{}
    foreach ($k in $p.Rights.Keys) {
        if ($k -notmatch '^Se[A-Za-z]+(Privilege|Right)$') { throw "Rights: '$k' не похоже на имя права (например SeNetworkLogonRight)" }
        $sids = @()
        foreach ($tok in @($p.Rights[$k])) { if ($tok) { $sids += Resolve-PrincipalSid -Token ([string]$tok) -Profile $Ctx.Profile } }
        $res[$k] = @($sids | Sort-Object -Unique)
    }
    $res
}

function Test-RightsGuard {
    # Защита от самоблокировки: после применения кто-то должен иметь возможность войти локально.
    param([Parameter(Mandatory)][hashtable]$Rights)
    if ($Rights.ContainsKey('SeInteractiveLogonRight') -and @($Rights['SeInteractiveLogonRight']).Count -eq 0) {
        throw 'SeInteractiveLogonRight пуст: после применения никто не сможет войти в систему локально.'
    }
    if ($Rights.ContainsKey('SeDenyInteractiveLogonRight')) {
        $deny = @($Rights['SeDenyInteractiveLogonRight'])
        $critical = @{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-545' = 'Users'; 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users' }
        foreach ($sid in $deny) {
            if ($critical.ContainsKey($sid)) { throw "SeDenyInteractiveLogonRight содержит '$($critical[$sid])': это запретит локальный вход (в т.ч. администраторам)." }
        }
        if ($Rights.ContainsKey('SeInteractiveLogonRight')) {
            $left = @($Rights['SeInteractiveLogonRight'] | Where-Object { $deny -notcontains $_ })
            if ($left.Count -eq 0) { throw 'Все субъекты из SeInteractiveLogonRight перечислены и в SeDenyInteractiveLogonRight: войти будет некому.' }
        }
    }
}

function ConvertTo-RightsValue {
    param([string[]]$Sids)
    (@($Sids | ForEach-Object { "*$_" })) -join ','
}

function ConvertFrom-RightsValue {
    # Значение из экспорта secedit (*SID или имя) -> отсортированный массив SID (имя, если не удалось разрешить).
    param($Raw)
    $out = @()
    foreach ($tok in ([string]$Raw -split ',')) {
        $t = $tok.Trim()
        if (-not $t) { continue }
        if ($t -match '^\*(S-1-.+)$') { $out += $Matches[1] }
        else { $sid = Convert-NameToSid $t; $out += $(if ($sid) { $sid } else { $t }) }
    }
    @($out | Sort-Object -Unique)
}

function Format-PrincipalList {
    param([string[]]$Sids)
    if (-not $Sids -or @($Sids).Count -eq 0) { return 'Ніхто' }
    (@($Sids | ForEach-Object { if ($_ -match '^S-1-') { Format-SidName $_ } else { $_ } })) -join ', '
}
