#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Автономный скрипт: включает защиту системы, задаёт лимит места и создаёт точку восстановления (без GUI).
    Не зависит от LOOK-Configurator, его можно копировать на машину отдельно.
.EXAMPLE
    .\New-RestorePoint.ps1
    .\New-RestorePoint.ps1 -Name 'Base policy'
    .\New-RestorePoint.ps1 -Name 'Add - ESET' -SkipResize
.NOTES
    Запускать в Windows PowerShell 5.1 (powershell.exe) от имени администратора.
    Windows по умолчанию не создаёт точки чаще раза в 24 часа: скрипт временно снимает это ограничение.
#>
[CmdletBinding()]
param(
    [string]$Name = 'Clean system',
    [string]$Drive = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }),
    [string]$MaxSize = '15GB',      # формат vssadmin: 15GB | 20480MB | 10% | UNBOUNDED
    [switch]$SkipResize
)
$ErrorActionPreference = 'Stop'
$Drive = $Drive.TrimEnd('\', '/'); if ($Drive.Length -eq 1) { $Drive += ':' }

function Set-Limit {
    & vssadmin.exe resize shadowstorage "/for=$Drive" "/on=$Drive" "/maxsize=$MaxSize" | Out-Null
    $LASTEXITCODE -eq 0
}

# 1. Включить защиту системы для диска
Enable-ComputerRestore -Drive "$Drive\"

# 2. Лимит места (если связи тома с хранилищем ещё нет, повторим после первой точки)
$limitSet = $SkipResize.IsPresent
if (-not $limitSet) { $limitSet = Set-Limit }

# 3. Создать точку (на время снимаем ограничение «не чаще раза в 24 часа»)
$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
$prop = 'SystemRestorePointCreationFrequency'
$old = (Get-ItemProperty -Path $key -Name $prop -ErrorAction SilentlyContinue).$prop
try {
    Set-ItemProperty -Path $key -Name $prop -Value 0 -Type DWord -Force
    Checkpoint-Computer -Description $Name -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
}
finally {
    if ($null -ne $old) { Set-ItemProperty -Path $key -Name $prop -Value $old -Type DWord -Force }
    else { Remove-ItemProperty -Path $key -Name $prop -ErrorAction SilentlyContinue }
}

if (-not $limitSet -and -not (Set-Limit)) { Write-Warning "Не удалось задать лимит $MaxSize (проверьте: vssadmin list shadowstorage)" }

# 4. Показать результат
Get-ComputerRestorePoint | Sort-Object SequenceNumber -Descending | Select-Object -First 5 SequenceNumber, Description, CreationTime | Format-Table -AutoSize
