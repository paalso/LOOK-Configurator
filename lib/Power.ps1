# Помощники для схемы электропитания (powercfg). Работают с GUID, а не с текстом,
# поэтому не зависят от языка интерфейса Windows.

function Get-PowerSetting {
    # Возвращает @{ AC = <секунды>; DC = <секунды> } для активной схемы.
    param([Parameter(Mandatory)][string]$Sub, [Parameter(Mandatory)][string]$Setting)
    $out = Invoke-Native -File 'powercfg.exe' -Arguments @('/query', 'SCHEME_CURRENT', $Sub, $Setting)
    $hex = @([regex]::Matches(($out | Out-String), '0x[0-9a-fA-F]{8}') | ForEach-Object { $_.Value })
    # В выводе последними идут «Текущее значение AC», затем «DC».
    if ($hex.Count -lt 2) { return @{ AC = $null; DC = $null } }
    @{
        AC = [Convert]::ToInt64($hex[$hex.Count - 2].Substring(2), 16)
        DC = [Convert]::ToInt64($hex[$hex.Count - 1].Substring(2), 16)
    }
}

function Set-PowerSetting {
    param(
        [Parameter(Mandatory)][string]$Sub,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)][ValidateSet('AC', 'DC')][string]$Source,
        [Parameter(Mandatory)][int]$Seconds
    )
    $verb = if ($Source -eq 'AC') { '/setacvalueindex' } else { '/setdcvalueindex' }
    Invoke-Native -File 'powercfg.exe' -Arguments @($verb, 'SCHEME_CURRENT', $Sub, $Setting, "$Seconds") | Out-Null
}

function Update-ActivePowerScheme {
    Invoke-Native -File 'powercfg.exe' -Arguments @('/setactive', 'SCHEME_CURRENT') | Out-Null
}

function Format-Seconds {
    param($Seconds)
    if ($null -eq $Seconds) { return 'не определено' }
    if ($Seconds -eq 0) { return 'никогда' }
    '{0:0.##} мин' -f ($Seconds / 60)
}
