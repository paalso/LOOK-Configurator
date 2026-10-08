# Помощники: административные шаблоны компьютера через ЛОКАЛЬНЫЙ объект групповой политики (LGPO).
# Административные шаблоны хранятся в %SystemRoot%\System32\GroupPolicy\Machine\Registry.pol (формат PReg) + gpt.ini.
# Так gpedit.msc показывает «Включено / Отключено», а gpupdate переносит значения в реестр.
#
# Формат Registry.pol: "PReg" + uint32 версия (1), далее записи  [ключ;значение;тип;размер;данные]  (всё в UTF-16LE,
# ключ и значение завершаются нулевым символом, тип и размер - uint32 LE).
#   Включено/Отключено со значением:  запись DWORD (например 1 или 0)
#   Отключено без значения «выкл.»:   запись  **del.<имя>  (Registry CSE удаляет значение из реестра)
#   Не задано:                        записи нет
# gpt.ini: Version = (user << 16) | machine; при каждом изменении увеличиваем машинную часть, чтобы клиент увидел изменение.

$Script:PRegDword = 4
$Script:PRegString = 1
$Script:RegistryCseGuid = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
$Script:RegistryCseToolGuid = '{D02B1F72-3407-48AE-BA88-E8213C6761F1}'

function Get-LocalGpoPaths {
    $root = if ($Script:LocalGpoRoot) { $Script:LocalGpoRoot } else { Join-Path $env:SystemRoot 'System32\GroupPolicy' }
    @{ Root = $root; Machine = (Join-Path $root 'Machine'); Pol = (Join-Path $root 'Machine\Registry.pol'); Ini = (Join-Path $root 'gpt.ini') }
}

# ---------- Registry.pol (PReg) ----------

function Read-PRegString {
    param([byte[]]$Bytes, [hashtable]$Cursor)
    $start = $Cursor.Pos
    $p = $start
    while ($true) {
        if (($p + 1) -ge $Bytes.Length) { throw "Registry.pol пошкоджений: незавершений рядок (зсув $start)" }
        if ($Bytes[$p] -eq 0 -and $Bytes[$p + 1] -eq 0) { break }
        $p += 2
    }
    $Cursor.Pos = $p + 2
    [System.Text.Encoding]::Unicode.GetString($Bytes, $start, $p - $start)
}

function Skip-PRegChar {
    param([byte[]]$Bytes, [hashtable]$Cursor, [char]$Char)
    $p = $Cursor.Pos
    if (($p + 1) -ge $Bytes.Length -or $Bytes[$p] -ne [byte][int]$Char -or $Bytes[$p + 1] -ne 0) {
        throw "Registry.pol пошкоджений: очікувався символ '$Char' (зсув $p)"
    }
    $Cursor.Pos = $p + 2
}

function Read-PRegFile {
    # Список записей @{ Key; Name; Type; Data[byte[]] }. Нет файла - пустой список.
    param([Parameter(Mandatory)][string]$Path)
    $list = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Path)) { return , $list }
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -eq 0) { return , $list }
    if ($b.Length -lt 8 -or [System.Text.Encoding]::ASCII.GetString($b, 0, 4) -ne 'PReg') { throw "Registry.pol: неправильний заголовок ($Path)" }
    if ([BitConverter]::ToUInt32($b, 4) -ne 1) { throw "Registry.pol: непідтримувана версія формату" }
    $c = @{ Pos = 8 }
    while ($c.Pos -lt $b.Length) {
        Skip-PRegChar $b $c '['
        $key = Read-PRegString $b $c
        Skip-PRegChar $b $c ';'
        $name = Read-PRegString $b $c
        Skip-PRegChar $b $c ';'
        $type = [BitConverter]::ToUInt32($b, $c.Pos); $c.Pos += 4
        Skip-PRegChar $b $c ';'
        $size = [BitConverter]::ToUInt32($b, $c.Pos); $c.Pos += 4
        Skip-PRegChar $b $c ';'
        if (($c.Pos + $size) -gt $b.Length) { throw 'Registry.pol пошкоджений: дані виходять за межі файлу' }
        $data = New-Object byte[] $size
        [Array]::Copy($b, $c.Pos, $data, 0, $size)
        $c.Pos += $size
        Skip-PRegChar $b $c ']'
        [void]$list.Add(@{ Key = $key; Name = $name; Type = [int64]$type; Data = $data })
    }
    , $list
}

function ConvertTo-PRegBytes {
    param($Entries)
    $ms = New-Object System.IO.MemoryStream
    $semi = [byte[]](0x3B, 0x00)
    $write = {
        param([byte[]]$x)
        if ($x.Length -gt 0) { $ms.Write($x, 0, $x.Length) }
    }
    & $write ([System.Text.Encoding]::ASCII.GetBytes('PReg'))
    & $write ([BitConverter]::GetBytes([uint32]1))
    foreach ($e in $Entries) {
        & $write ([byte[]](0x5B, 0x00))
        & $write ([System.Text.Encoding]::Unicode.GetBytes([string]$e.Key))
        & $write ([byte[]](0, 0))
        & $write $semi
        & $write ([System.Text.Encoding]::Unicode.GetBytes([string]$e.Name))
        & $write ([byte[]](0, 0))
        & $write $semi
        & $write ([BitConverter]::GetBytes([uint32]$e.Type))
        & $write $semi
        & $write ([BitConverter]::GetBytes([uint32]$e.Data.Length))
        & $write $semi
        & $write ([byte[]]$e.Data)
        & $write ([byte[]](0x5D, 0x00))
    }
    $ms.ToArray()
}

function Write-PRegFile {
    param([Parameter(Mandatory)][string]$Path, $Entries)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllBytes($Path, (ConvertTo-PRegBytes $Entries))
}

function Find-PRegEntry {
    param($Entries, [string]$Key, [string]$Name)
    foreach ($e in $Entries) {
        if ($e.Key -ieq $Key -and $e.Name -ieq $Name) { return $e }
    }
    $null
}

function Remove-PRegEntries {
    # Убирает и значение, и маркер **del. для данного параметра.
    param($Entries, [string]$Key, [string]$Name)
    for ($i = $Entries.Count - 1; $i -ge 0; $i--) {
        $e = $Entries[$i]
        if ($e.Key -ieq $Key -and ($e.Name -ieq $Name -or $e.Name -ieq ('**del.' + $Name))) { $Entries.RemoveAt($i) }
    }
}

function Set-PRegDword {
    param($Entries, [string]$Key, [string]$Name, [int64]$Value)
    Remove-PRegEntries $Entries $Key $Name
    [void]$Entries.Add(@{ Key = $Key; Name = $Name; Type = [int64]$Script:PRegDword; Data = [BitConverter]::GetBytes([uint32]$Value) })
}

function Set-PRegDelete {
    # «Отключено» для политики без значения выключения: **del.<имя>, тип REG_SZ, данные - пробел + NUL.
    param($Entries, [string]$Key, [string]$Name)
    Remove-PRegEntries $Entries $Key $Name
    [void]$Entries.Add(@{ Key = $Key; Name = ('**del.' + $Name); Type = [int64]$Script:PRegString; Data = [byte[]](0x20, 0x00, 0x00, 0x00) })
}

function Get-PRegState {
    # @{ Kind = 'None' | 'Value' | 'Delete'; Value } для параметра.
    param($Entries, [string]$Key, [string]$Name)
    $e = Find-PRegEntry $Entries $Key $Name
    if ($e) {
        if ($e.Type -eq $Script:PRegDword -and $e.Data.Length -eq 4) { return @{ Kind = 'Value'; Value = [int64][BitConverter]::ToUInt32($e.Data, 0) } }
        return @{ Kind = 'Other'; Value = ('тип ' + $e.Type) }
    }
    if (Find-PRegEntry $Entries $Key ('**del.' + $Name)) { return @{ Kind = 'Delete'; Value = $null } }
    @{ Kind = 'None'; Value = $null }
}

# ---------- gpt.ini ----------

function Read-LocalGpoIni {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { , @([System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::Default) -split "\r?\n") } else { , @() }
}

function Get-LocalGpoIniInfo {
    # @{ Exists; Version; MachineVersion; HasRegistryCse }
    param([string]$Path)
    $info = @{ Exists = (Test-Path -LiteralPath $Path); Version = 0L; MachineVersion = 0L; HasRegistryCse = $false }
    if (-not $info.Exists) { return $info }
    foreach ($l in (Read-LocalGpoIni $Path)) {
        if ($l -match '^\s*Version\s*=\s*(\d+)\s*$') { $info.Version = [int64]$Matches[1]; $info.MachineVersion = $info.Version -band 0xFFFF }
        elseif ($l -match '^\s*gPCMachineExtensionNames\s*=(.*)$') { $info.HasRegistryCse = ($Matches[1].ToUpperInvariant().Contains($Script:RegistryCseGuid)) }
    }
    $info
}

function Update-LocalGpoIni {
    # Увеличивает машинную часть Version и гарантирует расширение Registry в gPCMachineExtensionNames.
    param([Parameter(Mandatory)][string]$Path, [switch]$KeepExtension)
    $lines = New-Object System.Collections.ArrayList
    foreach ($l in (Read-LocalGpoIni $Path)) { if ($l -ne '' -or $lines.Count -gt 0) { [void]$lines.Add($l) } }
    while ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
    $gen = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*\[General\]\s*$') { $gen = $i; break } }
    if ($gen -lt 0) { $lines.Insert(0, '[General]'); $gen = 0 }
    $verIdx = -1; $cseIdx = -1
    for ($i = $gen + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*\[') { break }
        if ($lines[$i] -match '^\s*Version\s*=') { $verIdx = $i }
        if ($lines[$i] -match '^\s*gPCMachineExtensionNames\s*=') { $cseIdx = $i }
    }
    $ver = 0L
    if ($verIdx -ge 0 -and $lines[$verIdx] -match '=\s*(\d+)') { $ver = [int64]$Matches[1] }
    $machine = (($ver -band 0xFFFF) + 1) -band 0xFFFF
    if ($machine -eq 0) { $machine = 1 }
    $newVer = ($ver -band 0xFFFF0000) + $machine
    $verLine = "Version=$newVer"
    $pair = '[' + $Script:RegistryCseGuid + $Script:RegistryCseToolGuid + ']'
    if ($verIdx -ge 0) { $lines[$verIdx] = $verLine } else { $lines.Insert($gen + 1, $verLine); if ($cseIdx -ge $gen + 1) { $cseIdx++ } }
    if ($cseIdx -ge 0) {
        if (-not $lines[$cseIdx].ToUpperInvariant().Contains($Script:RegistryCseGuid)) {
            $val = ($lines[$cseIdx] -split '=', 2)[1].Trim()
            $groups = @([regex]::Matches($val, '\[[^\]]*\]') | ForEach-Object { $_.Value }) + $pair
            $lines[$cseIdx] = 'gPCMachineExtensionNames=' + (($groups | Sort-Object { $_.ToUpperInvariant() }) -join '')
        }
    }
    else {
        $pos = if ($verIdx -ge 0) { $verIdx } else { $gen + 1 }
        $lines.Insert($pos, 'gPCMachineExtensionNames=' + $pair)
    }
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, (($lines -join "`r`n") + "`r`n"), [System.Text.Encoding]::Default)
    $newVer
}

function Invoke-GroupPolicyRefresh {
    # Применяет машинную часть политики сразу. Сбой gpupdate не фатален: значения будут перенесены в реестр при следующем обновлении.
    try {
        Invoke-Native -File 'gpupdate.exe' -Arguments @('/target:computer', '/force') | Out-Null
        $true
    }
    catch {
        Write-Log "gpupdate: $($_.Exception.Message)" 'WARN'
        $false
    }
}

# ---------- план шага admin-templates ----------

function Get-AdminTemplatePlan {
    # States из профиля -> список @{ Item; State; Value; Expected } в порядке таблицы. Не перечисленные параметры не затрагиваются.
    # State: Enabled | Disabled | NotConfigured. Для Enabled можно задать значение: { "State": "Enabled", "Value": 255 }.
    param($Ctx)
    if (-not $Ctx.Params.ContainsKey('States') -or $Ctx.Params.States.Count -eq 0) {
        throw 'В profile.json нет steps -> admin-templates -> States'
    }
    $byId = @{}
    foreach ($i in $Ctx.Step.Items) { $byId[$i.Id] = $i }
    $order = @($Ctx.Step.Items | ForEach-Object { $_.Id })
    foreach ($id in $Ctx.Params.States.Keys) {
        if (-not $byId.ContainsKey($id)) { throw "States: невідомий параметр '$id'. Допустимі: $($order -join ', ')" }
    }
    $plan = @()
    foreach ($item in $Ctx.Step.Items) {
        if (-not $Ctx.Params.States.ContainsKey($item.Id)) { continue }
        $raw = $Ctx.Params.States[$item.Id]
        $stateText = $null; $override = $null
        if ($raw -is [hashtable]) {
            $stateText = [string]$raw.State
            if ($raw.ContainsKey('Value')) { $override = $raw.Value }
        }
        else { $stateText = [string]$raw }
        $map = @{ 'enabled' = 'Enabled'; 'disabled' = 'Disabled'; 'notconfigured' = 'NotConfigured' }
        $k = $stateText.Trim().ToLowerInvariant()
        if (-not $map.ContainsKey($k)) { throw "States.$($item.Id): допустимо Enabled | Disabled | NotConfigured, вказано '$stateText'" }
        $state = $map[$k]
        $value = $null
        if ($state -eq 'Enabled') {
            $value = $item.On
            if ($null -ne $override) {
                $n = 0L
                if (-not [int64]::TryParse([string]$override, [ref]$n) -or $n -lt 0 -or $n -gt 4294967295) { throw "States.$($item.Id).Value: очікується невід'ємне ціле, вказано '$override'" }
                $value = $n
            }
        }
        $expected = switch ($state) {
            'Enabled' { @{ Kind = 'Value'; Value = [int64]$value } }
            'Disabled' { if ($null -ne $item.Off) { @{ Kind = 'Value'; Value = [int64]$item.Off } } else { @{ Kind = 'Delete'; Value = $null } } }
            default { @{ Kind = 'None'; Value = $null } }
        }
        $plan += , @{ Item = $item; State = $state; Value = $value; Expected = $expected }
    }
    $plan
}

function Format-PolState {
    param($S)
    switch ($S.Kind) {
        'Value' { "DWORD $($S.Value)" }
        'Delete' { '**del (Вимкнено)' }
        'Other' { "$($S.Value)" }
        default { 'немає запису' }
    }
}

function Format-PolExpected {
    param($S)
    switch ($S.Kind) {
        'Value' { "DWORD $($S.Value)" }
        'Delete' { '**del (Вимкнено)' }
        default { 'немає запису (Не задано)' }
    }
}

function Test-PolStateMatches {
    param($Expected, $Actual)
    if ($Expected.Kind -ne $Actual.Kind) { return $false }
    if ($Expected.Kind -eq 'Value') { return ([int64]$Expected.Value -eq [int64]$Actual.Value) }
    $true
}

function Get-AdminTemplateRegState {
    # Фактическое значение в реестре: тот же вид, что и у Registry.pol (Value / None).
    param($Item)
    $i = Get-RegValueInfo -Path ('HKLM:\' + $Item.Key) -Name $Item.Name
    if ($i.Exists -and $i.Kind -eq 'DWord') { return @{ Kind = 'Value'; Value = [int64]([uint32]([int]$i.Value -band 0xFFFFFFFFL)) } }
    if ($i.Exists) { return @{ Kind = 'Other'; Value = "тип $($i.Kind)" } }
    @{ Kind = 'None'; Value = $null }
}

function Test-RegStateMatchesExpected {
    # В реестре «Отключено без значения» и «Не задано» выглядят одинаково: значения нет.
    param($Expected, $Actual)
    if ($Expected.Kind -eq 'Value') { return ($Actual.Kind -eq 'Value' -and [int64]$Actual.Value -eq [int64]$Expected.Value) }
    $Actual.Kind -eq 'None'
}
