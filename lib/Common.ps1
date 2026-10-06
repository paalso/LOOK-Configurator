# Общие помощники: вывод, логирование, состояние, запуск нативных команд.

function Write-Ui {
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1,-5}] {2}' -f (Get-Date), $Level, $Message
    Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8
}

function Read-Choice {
    # Выбор по цифрам: не зависит от раскладки клавиатуры.
    param([string]$Prompt = 'Выбор', [Parameter(Mandatory)][string[]]$Allowed)
    while ($true) {
        $answer = (Read-Host $Prompt).Trim()
        if ($Allowed -contains $answer) { return $answer }
        Write-Ui 'Неверный выбор, повторите.' Yellow
    }
}

function Confirm-Action {
    param([Parameter(Mandatory)][string]$Question)
    Write-Ui $Question Yellow
    (Read-Choice -Prompt '1 = да, 0 = нет' -Allowed @('1', '0')) -eq '1'
}

function Invoke-Native {
    # Запуск внешней команды с проверкой кода возврата. Возвращает вывод (массив строк).
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments = @())
    $global:LASTEXITCODE = 0
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # иначе stderr нативных команд бросает исключение в PS 5.1
    try { $out = & $File @Arguments 2>&1 } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) {
        throw "Команда '$File $($Arguments -join ' ')' завершилась с кодом $LASTEXITCODE`n$($out | Out-String)"
    }
    $out
}

function New-Check {
    param([string]$Name, [string]$Expected, [string]$Actual, [bool]$Ok)
    [pscustomobject]@{ Name = $Name; Expected = $Expected; Actual = $Actual; Ok = $Ok }
}

function Show-Checks {
    param([object[]]$Checks)
    foreach ($c in $Checks) {
        $mark = if ($c.Ok) { '[ OK ]' } else { '[FAIL]' }
        $color = if ($c.Ok) { 'Green' } else { 'Red' }
        Write-Ui ('  {0} {1}: ожидалось «{2}», фактически «{3}»' -f $mark, $c.Name, $c.Expected, $c.Actual) $color
    }
}

function ConvertTo-Hashtable {
    # JSON -> вложенные хэштаблицы (в PS 5.1 ConvertFrom-Json отдаёт неизменяемые PSCustomObject).
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [pscustomobject]) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hashtable $p.Value }
        return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return , @($InputObject | ForEach-Object { ConvertTo-Hashtable $_ })
    }
    $InputObject
}

# ---------- Состояние мастера (state\state.json, у каждой машины своё) ----------

function Initialize-Environment {
    $Script:StateDir = Join-Path $Script:Root 'state'
    $logDir = Join-Path $Script:StateDir 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $Script:LogPath = Join-Path $logDir ('{0:yyyy-MM-dd}.log' -f (Get-Date))
    $Script:StatePath = Join-Path $Script:StateDir 'state.json'

    $profilePath = Join-Path $Script:Root 'config\profile.json'
    $Script:LookProfile = Get-Content -Path $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json

    $Script:State = @{ steps = @{} }
    if (Test-Path $Script:StatePath) {
        $raw = Get-Content -Path $Script:StatePath -Raw -Encoding UTF8
        if ($raw.Trim()) {
            $Script:State = ConvertTo-Hashtable ($raw | ConvertFrom-Json)
            if (-not $Script:State.ContainsKey('steps')) { $Script:State.steps = @{} }
        }
    }
    Write-Log "Мастер запущен. Пользователь: $env:USERNAME, компьютер: $env:COMPUTERNAME"
}

function Save-State {
    $Script:State | ConvertTo-Json -Depth 10 | Set-Content -Path $Script:StatePath -Encoding UTF8
}

function Get-StepState {
    param([Parameter(Mandatory)][string]$Id)
    if ($Script:State.steps.ContainsKey($Id)) { $Script:State.steps[$Id] } else { $null }
}

function Set-StepState {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Status,   # pending | applied | skipped | rolledback
        $Backup,
        [switch]$ClearBackup
    )
    if (-not $Script:State.steps.ContainsKey($Id)) { $Script:State.steps[$Id] = @{} }
    $entry = $Script:State.steps[$Id]
    $entry.status = $Status
    $entry.time = (Get-Date).ToString('s')
    if ($PSBoundParameters.ContainsKey('Backup')) { $entry.backup = $Backup }
    if ($ClearBackup) { $entry.Remove('backup') }
    Save-State
}
