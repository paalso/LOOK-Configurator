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
        [Parameter(Mandatory)][ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString')][string]$Kind
    )
    $loc = ConvertTo-RegistryLocation $Path
    $key = (Get-RegistryBase $loc.Hive).CreateSubKey($loc.SubKey)
    try {
        # Не через `$v = switch`: присваивание из switch разворачивает массивы (пустой список -> $null, один элемент -> строка).
        if ($Kind -eq 'DWord') { $v = [int]$Value }
        elseif ($Kind -eq 'QWord') { $v = [int64]$Value }
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
