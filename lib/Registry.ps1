# Помощники: реестр с точным контролем типа значения (REG_DWORD / REG_SZ / REG_MULTI_SZ ...).
# Поддерживаются пути HKLM:\... и HKCU:\.... Работают через .NET (Microsoft.Win32.Registry), поэтому
# пустой REG_MULTI_SZ и тип значения обрабатываются точно (Set-ItemProperty здесь ненадёжен).

function ConvertTo-RegistryLocation {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^(HKLM|HKEY_LOCAL_MACHINE):?\\(.+)$') { return @{ Hive = 'LocalMachine'; SubKey = $Matches[2] } }
    if ($Path -match '^(HKCU|HKEY_CURRENT_USER):?\\(.+)$') { return @{ Hive = 'CurrentUser'; SubKey = $Matches[2] } }
    throw "Неподдерживаемый путь реестра: $Path (ожидается HKLM:\... или HKCU:\...)"
}

function Get-RegistryBase {
    param([string]$Hive)
    if ($Hive -eq 'LocalMachine') { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
}

function Get-RegValueInfo {
    # @{ Exists; Kind (DWord|String|MultiString|...); Value } без раскрытия переменных окружения.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $loc = ConvertTo-RegistryLocation $Path
    $key = (Get-RegistryBase $loc.Hive).OpenSubKey($loc.SubKey)
    if (-not $key) { return @{ Exists = $false; Kind = $null; Value = $null } }
    try {
        if (@($key.GetValueNames()) -notcontains $Name) { return @{ Exists = $false; Kind = $null; Value = $null } }
        @{
            Exists = $true
            Kind   = [string]$key.GetValueKind($Name)
            Value  = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    }
    finally { $key.Close() }
}

function Set-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        $Value,
        [Parameter(Mandatory)][ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')][string]$Kind
    )
    $loc = ConvertTo-RegistryLocation $Path
    $key = (Get-RegistryBase $loc.Hive).CreateSubKey($loc.SubKey)
    try {
        # Не через `$v = switch`: присваивание из switch разворачивает массивы (пустой список -> $null, один элемент -> строка).
        if ($Kind -eq 'DWord') { $v = [int]$Value }
        elseif ($Kind -eq 'QWord') { $v = [int64]$Value }
        elseif ($Kind -eq 'Binary') { [byte[]]$v = @($Value | ForEach-Object { [byte]$_ }) }
        elseif ($Kind -eq 'MultiString') { [string[]]$v = @($Value | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }
        else { $v = [string]$Value }
        $key.SetValue($Name, $v, [Microsoft.Win32.RegistryValueKind]$Kind)
    }
    finally { $key.Close() }
}

function Remove-RegValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $loc = ConvertTo-RegistryLocation $Path
    $key = (Get-RegistryBase $loc.Hive).OpenSubKey($loc.SubKey, $true)
    if ($key) { try { $key.DeleteValue($Name, $false) } finally { $key.Close() } }
}

function Get-RegFirstMissingKey {
    # Самый верхний НЕсуществующий ключ цепочки (или $null, если весь путь есть). Нужен, чтобы при откате
    # убрать пустые ключи, созданные при записи значения.
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    $base = Get-RegistryBase $loc.Hive
    $prefix = if ($loc.Hive -eq 'LocalMachine') { 'HKLM:\' } else { 'HKCU:\' }
    $cur = ''
    foreach ($part in ($loc.SubKey -split '\\')) {
        $cur = if ($cur) { "$cur\$part" } else { $part }
        $k = $base.OpenSubKey($cur)
        if (-not $k) { return "$prefix$cur" }
        $k.Close()
    }
    $null
}

function Test-RegKeyTreeEmpty {
    param($Key)
    if ($Key.ValueCount -gt 0) { return $false }
    foreach ($n in $Key.GetSubKeyNames()) {
        $sk = $Key.OpenSubKey($n)
        try { if (-not (Test-RegKeyTreeEmpty $sk)) { return $false } } finally { $sk.Close() }
    }
    $true
}

function Remove-RegKeyIfEmpty {
    # Удаляет ключ вместе с подветвью, только если в ней нет ни одного значения.
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    $base = Get-RegistryBase $loc.Hive
    $key = $base.OpenSubKey($loc.SubKey)
    if (-not $key) { return }
    $empty = $false
    try { $empty = Test-RegKeyTreeEmpty $key } finally { $key.Close() }
    if ($empty) { $base.DeleteSubKeyTree($loc.SubKey, $false) }
}

# ---------- ключи и ветви целиком (для резервных копий и отката) ----------

function Test-RegKey {
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    $k = (Get-RegistryBase $loc.Hive).OpenSubKey($loc.SubKey)
    if ($k) { $k.Close(); $true } else { $false }
}

function New-RegKey {
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    (Get-RegistryBase $loc.Hive).CreateSubKey($loc.SubKey).Close()
}

function Get-RegValueNames {
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    $k = (Get-RegistryBase $loc.Hive).OpenSubKey($loc.SubKey)
    if (-not $k) { return @() }
    try { @($k.GetValueNames() | Where-Object { $_ }) } finally { $k.Close() }
}

function Get-RegSubKeyNames {
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    $k = (Get-RegistryBase $loc.Hive).OpenSubKey($loc.SubKey)
    if (-not $k) { return @() }
    try { @($k.GetSubKeyNames()) } finally { $k.Close() }
}

function Remove-RegKeyTree {
    param([Parameter(Mandatory)][string]$Path)
    $loc = ConvertTo-RegistryLocation $Path
    (Get-RegistryBase $loc.Hive).DeleteSubKeyTree($loc.SubKey, $false)
}

function Export-RegTree {
    # Ветвь -> плоская структура (глубина вложенности не растёт): @{ Exists; KeyList = @(относит. пути); ValueList = @(@{Key;Name;Kind;Value}) }.
    # Имена полей не Keys/Values: они совпали бы со свойствами хэштаблицы.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-RegKey -Path $Path)) { return @{ Exists = $false; KeyList = @(); ValueList = @() } }
    $keys = New-Object System.Collections.ArrayList
    $vals = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push('')
    while ($stack.Count -gt 0) {
        $rel = $stack.Pop()
        $full = if ($rel) { "$Path\$rel" } else { $Path }
        [void]$keys.Add($rel)
        foreach ($n in @(Get-RegValueNames -Path $full)) {
            $i = Get-RegValueInfo -Path $full -Name $n
            [void]$vals.Add(@{ Key = $rel; Name = $n; Kind = $i.Kind; Value = $i.Value })
        }
        foreach ($s in @(Get-RegSubKeyNames -Path $full)) { $stack.Push($(if ($rel) { "$rel\$s" } else { $s })) }
    }
    @{ Exists = $true; KeyList = @($keys); ValueList = @($vals) }
}

function Import-RegTree {
    # Заменяет ветвь содержимым из Export-RegTree (если исходной ветви не было, просто удаляет текущую).
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Tree)
    Remove-RegKeyTree -Path $Path
    if (-not $Tree.Exists) { return }
    foreach ($k in @($Tree.KeyList | Sort-Object { $_.Length })) { New-RegKey -Path $(if ($k) { "$Path\$k" } else { $Path }) }
    foreach ($v in @($Tree.ValueList)) {
        $full = if ($v.Key) { "$Path\$($v.Key)" } else { $Path }
        Set-RegValue -Path $full -Name $v.Name -Value $v.Value -Kind $v.Kind
    }
}
