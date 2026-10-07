# Помощники: Политика ограниченного использования программ (Software Restriction Policies, SRP).
# Хранится в реестре: HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers
#   DefaultLevel (DWORD)        уровень по умолчанию: 0 = Disallowed, 65536 = Basic User, 262144 = Unrestricted
#   TransparentEnabled (DWORD)  «Применять к»: 1 = все файлы кроме библиотек (DLL), 2 = все файлы
#   PolicyScope (DWORD)         «К пользователям»: 0 = все, 1 = все кроме локальных администраторов
#   AuthenticodeEnabled (DWORD) сертификаты: 0 = игнорировать, 1 = применять правила сертификатов
#   ExecutableTypes (MULTI_SZ)  назначенные типы файлов
#   <уровень>\Paths\{GUID}      правила пути: ItemData (путь/маска), SaferFlags, LastModified
# Доверенные издатели: HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Safer, TrustedPublisherFlags (DWORD):
#   биты 0-1 (кто управляет): 0 = конечные пользователи, 1 = локальные администраторы, 2 = администраторы предприятия;
#   0x100 = проверять отзыв сертификата издателя, 0x200 = проверять отзыв сертификата метки времени.

$Script:SrpKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
$Script:SrpTrustedKey = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Safer'
$Script:SrpLevels = @{ 'disallowed' = 0; 'basicuser' = 65536; 'unrestricted' = 262144 }
$Script:SrpLevelNames = @{ 0 = 'Disallowed (Заборонений)'; 4096 = 'Untrusted'; 65536 = 'Basic User'; 131072 = 'Constrained'; 262144 = 'Unrestricted (Необмежений)' }
$Script:SrpDefaultTypes = @('ADE', 'ADP', 'BAS', 'BAT', 'CHM', 'CMD', 'COM', 'CPL', 'CRT', 'EXE', 'HLP', 'HTA', 'INF', 'INS', 'ISP', 'LNK',
    'MDB', 'MDE', 'MSC', 'MSI', 'MSP', 'MST', 'OCX', 'PCD', 'PIF', 'REG', 'SCR', 'SHS', 'URL', 'VB', 'WSC')

function ConvertTo-SrpEnum {
    param([string]$What, [string]$Value, [hashtable]$Map)
    $k = $Value.Trim().ToLowerInvariant()
    if (-not $Map.ContainsKey($k)) { throw "${What}: допустимо $(($Map.Keys | Sort-Object) -join ' | '), указано '$Value'" }
    $Map[$k]
}

function Format-SrpLevel {
    param($Level)
    $n = [int]$Level
    if ($Script:SrpLevelNames.ContainsKey($n)) { $Script:SrpLevelNames[$n] } else { "рівень $n" }
}

function Format-TypeName { param([string]$Name) $Name.Trim().TrimStart('*').TrimStart('.').ToUpperInvariant() }

function Get-SrpExecutableTypes {
    param([string[]]$Base, [string[]]$Remove, [string[]]$Add)
    $rm = @($Remove | ForEach-Object { Format-TypeName $_ })
    $out = New-Object System.Collections.ArrayList
    foreach ($t in (@($Base) + @($Add))) {
        $n = Format-TypeName $t
        if ($n -and ($rm -notcontains $n) -and ($out -notcontains $n)) { [void]$out.Add($n) }
    }
    @($out)
}

function Get-SrpPlan {
    # Профиль -> ожидаемые значения. Бросает исключение при ошибках в профиле.
    param($Ctx)
    $p = $Ctx.Params
    if (-not $p.ContainsKey('Rules') -or @($p.Rules).Count -eq 0) { throw 'В profile.json нет steps -> software-restriction -> Rules' }
    $enf = if ($p.ContainsKey('Enforcement')) { $p.Enforcement } else { @{} }
    $tp = if ($p.ContainsKey('TrustedPublishers')) { $p.TrustedPublishers } else { @{} }
    $dt = if ($p.ContainsKey('DesignatedFileTypes')) { $p.DesignatedFileTypes } else { @{} }

    $rules = @(); $seen = @{}
    foreach ($r in @($p.Rules)) {
        $path = [string]$r.Path
        if ([string]::IsNullOrWhiteSpace($path)) { throw 'Rules: у правила пустой Path' }
        $lvl = ConvertTo-SrpEnum 'Rules.Level' ([string]$r.Level) $Script:SrpLevels
        $key = $path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { throw "Rules: путь '$path' указан дважды" }
        $seen[$key] = $true
        $rules += @{ Path = $path; Level = $lvl }
    }
    $flags = [int](ConvertTo-SrpEnum 'TrustedPublishers.AllowManagement' $(if ($tp.ContainsKey('AllowManagement')) { [string]$tp.AllowManagement } else { 'EndUsers' }) @{ 'endusers' = 0; 'localadministrators' = 1; 'enterpriseadministrators' = 2 })
    if ($tp.ContainsKey('CheckPublisherRevocation') -and [bool]$tp.CheckPublisherRevocation) { $flags += 0x100 }
    if ($tp.ContainsKey('CheckTimestampRevocation') -and [bool]$tp.CheckTimestampRevocation) { $flags += 0x200 }
    @{
        DefaultLevel  = [int](ConvertTo-SrpEnum 'DefaultLevel' $(if ($p.ContainsKey('DefaultLevel')) { [string]$p.DefaultLevel } else { 'Unrestricted' }) $Script:SrpLevels)
        Transparent   = [int](ConvertTo-SrpEnum 'Enforcement.AppliesTo' $(if ($enf.ContainsKey('AppliesTo')) { [string]$enf.AppliesTo } else { 'AllExceptLibraries' }) @{ 'allexceptlibraries' = 1; 'allfiles' = 2 })
        PolicyScope   = [int](ConvertTo-SrpEnum 'Enforcement.Users' $(if ($enf.ContainsKey('Users')) { [string]$enf.Users } else { 'AllExceptAdministrators' }) @{ 'allusers' = 0; 'allexceptadministrators' = 1 })
        Authenticode  = [int](ConvertTo-SrpEnum 'Enforcement.CertificateRules' $(if ($enf.ContainsKey('CertificateRules')) { [string]$enf.CertificateRules } else { 'Ignore' }) @{ 'ignore' = 0; 'enforce' = 1 })
        TypesRemove   = @($dt.Remove | Where-Object { $_ })
        TypesAdd      = @($dt.Add | Where-Object { $_ })
        Rules         = $rules
        TrustedFlags  = $flags
    }
}

function Get-SrpActualRules {
    # Правила пути, фактически лежащие в реестре (по всем уровням).
    foreach ($lvl in @(Get-RegSubKeyNames -Path $Script:SrpKey | Where-Object { $_ -match '^\d+$' })) {
        $pk = "$Script:SrpKey\$lvl\Paths"
        foreach ($g in @(Get-RegSubKeyNames -Path $pk)) {
            $i = Get-RegValueInfo -Path "$pk\$g" -Name 'ItemData'
            if ($i.Exists) { [pscustomobject]@{ Level = [int]$lvl; Path = [string]$i.Value; Id = $g } }
        }
    }
}

function Test-SrpRegistryPathRule {
    # Для правил вида %HKEY_LOCAL_MACHINE\...\Имя%: существует ли значение (иначе правило ни на что не указывает).
    param([string]$Path)
    if ($Path -notmatch '^%(?:HKEY_LOCAL_MACHINE|HKLM)\\(.+)\\([^\\%]+)%') { return $null }
    $info = Get-RegValueInfo -Path "HKLM:\$($Matches[1])" -Name $Matches[2]
    @{ Key = "HKLM\$($Matches[1])"; Name = $Matches[2]; Exists = [bool]$info.Exists }
}
