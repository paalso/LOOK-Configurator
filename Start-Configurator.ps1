#Requires -Version 5.1
<#
    LOOK-Configurator: пошаговый мастер настройки ЛООК (Windows 11).
    Запуск: Start.cmd (или этот скрипт напрямую). Требуются права администратора.
#>
[CmdletBinding()]
param([switch]$NoElevate)

$ErrorActionPreference = 'Stop'
$Script:Root = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    if ($NoElevate) { throw 'Нужны права администратора.' }
    Write-Host 'Перезапуск с правами администратора...'
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit
}

# Все файлы из lib\ подключаются автоматически (общие помощники для шагов).
Get-ChildItem -Path (Join-Path $Script:Root 'lib') -Filter '*.ps1' | Sort-Object Name |
    ForEach-Object { . $_.FullName }

try {
    Initialize-Environment
    Start-MainMenu
}
catch {
    Write-Host ''
    Write-Host "Критическая ошибка: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    Read-Host 'Нажмите Enter для выхода'
}
