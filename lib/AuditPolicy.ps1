# Помощники: расширенная политика аудита (Advanced Audit Policy) через auditpol.exe.
# Подкатегории адресуются по GUID (не зависят от языка Windows). Чтение идёт через `auditpol /backup`:
# в этом файле числовой «Setting Value» (0 нет, 1 Success, 2 Failure, 3 оба), в отличие от локализованного текста /get.
# Перечень подкатегорий берётся из самой системы, жёсткого списка GUID в проекте нет.

$Script:LsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$Script:LegacyOverrideName = 'SCENoApplyLegacyAuditPolicy'

function Read-AuditPolicyFile {
    # Возвращает массив @{ Guid; Name; Value } (уникальные подкатегории системной политики).
    param([Parameter(Mandatory)][string]$Path)
    $rows = @(Get-Content -Path $Path | Select-Object -Skip 1 |
        ConvertFrom-Csv -Header 'Machine', 'Target', 'Name', 'Guid', 'Incl', 'Excl', 'Value')
    $seen = @{}
    foreach ($r in $rows) {
        if ($r.Guid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
        $g = $r.Guid.ToUpperInvariant()
        if ($seen.ContainsKey($g)) { continue }      # per-user строки (если есть) идут после системных
        $v = 0
        if (-not [int]::TryParse([string]$r.Value, [ref]$v)) { continue }
        $seen[$g] = $true
        [pscustomobject]@{ Guid = $g; Name = [string]$r.Name; Value = $v }
    }
}

function Get-AuditPolicy {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('audit-{0}.csv' -f [guid]::NewGuid())
    try {
        Invoke-Native -File 'auditpol.exe' -Arguments @('/backup', "/file:$tmp") | Out-Null
        @(Read-AuditPolicyFile -Path $tmp)
    }
    finally { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue }
}

function Save-AuditPolicySnapshot {
    # Полная копия политики в state\backups\<id>-before-<время>.csv; её же использует откат (/restore).
    param([Parameter(Mandatory)][string]$Id)
    $dir = Join-Path $Script:StateDir 'backups'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir ('{0}-before-{1:yyyyMMdd-HHmmss}.csv' -f $Id, (Get-Date))
    Invoke-Native -File 'auditpol.exe' -Arguments @('/backup', "/file:$file") | Out-Null
    Write-Log "Исходная политика аудита сохранена: $file"
    $file
}

function Restore-AuditPolicySnapshot {
    param([Parameter(Mandatory)][string]$File)
    if (-not (Test-Path -LiteralPath $File)) { throw "Файл резервной копии политики аудита не найден: $File" }
    Invoke-Native -File 'auditpol.exe' -Arguments @('/restore', "/file:$File") | Out-Null
}

function Format-AuditValue {
    param($Value)
    switch ([int]$Value) { 0 { 'Без аудиту' } 1 { 'Success' } 2 { 'Failure' } 3 { 'Success, Failure' } default { "$Value" } }
}

function ConvertTo-AuditValue {
    param($Setting)
    [int]([bool]$Setting.Success) + 2 * [int]([bool]$Setting.Failure)
}

function Get-AuditOverrideTable {
    # Overrides из профиля -> @{ '{GUID}' = число }, ключи нормализованы.
    param($Params)
    $t = @{}
    if ($Params.ContainsKey('Overrides') -and $Params.Overrides) {
        foreach ($k in $Params.Overrides.Keys) { $t[([string]$k).Trim().ToUpperInvariant()] = ConvertTo-AuditValue $Params.Overrides[$k] }
    }
    $t
}

function Get-ExpectedAuditValue {
    param($Params, [string]$Guid, [hashtable]$Overrides)
    if ($Overrides.ContainsKey($Guid)) { return $Overrides[$Guid] }
    ConvertTo-AuditValue $Params.Default
}

function Test-AuditConfig {
    param($Params)
    if (-not $Params.ContainsKey('Default')) { throw "В profile.json нет steps -> audit-policy -> Default (Success/Failure)" }
    if ($Params.ContainsKey('Overrides') -and $Params.Overrides) {
        foreach ($k in $Params.Overrides.Keys) {
            if (([string]$k).Trim() -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { throw "Overrides: ключ '$k' не похож на GUID вида {0CCE9215-69AE-11D9-BED3-505054503030}" }
        }
    }
}

function Set-AuditSubcategories {
    # Одна команда на каждое целевое значение (подкатегории перечисляются через запятую).
    param([Parameter(Mandatory)][string[]]$Guids, [Parameter(Mandatory)][int]$Value)
    $s = if ($Value -band 1) { 'enable' } else { 'disable' }
    $f = if ($Value -band 2) { 'enable' } else { 'disable' }
    # Командная строка Windows ограничена по длине: отправляем пачками по 40 GUID.
    for ($i = 0; $i -lt $Guids.Count; $i += 40) {
        $list = ($Guids[$i..([math]::Min($i + 39, $Guids.Count - 1))]) -join ','
        Invoke-Native -File 'auditpol.exe' -Arguments @('/set', "/subcategory:$list", "/success:$s", "/failure:$f") | Out-Null
    }
}

# --- «Audit: Force audit policy subcategory settings to override audit policy category settings» ---

function Get-LegacyAuditOverride {
    (Get-ItemProperty -Path $Script:LsaKey -Name $Script:LegacyOverrideName -ErrorAction SilentlyContinue).($Script:LegacyOverrideName)
}

function Set-LegacyAuditOverride {
    # $null = удалить значение (вернуть «не задано»).
    param($Value)
    if ($null -eq $Value) { Remove-ItemProperty -Path $Script:LsaKey -Name $Script:LegacyOverrideName -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $Script:LsaKey -Name $Script:LegacyOverrideName -Value ([int]$Value) -Type DWord -Force }
}
