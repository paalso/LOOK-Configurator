# Помощники: параметры журналов Windows (размер, режим хранения) через EventLogConfiguration (.NET).
# Режим хранения (LogMode): Circular = «перезаписывать старые события по необходимости»,
# AutoBackup = архивировать полный журнал, Retain = НЕ перезаписывать (полный журнал блокирует запись событий).

function Get-EventLogSettings {
    param([Parameter(Mandatory)][string]$LogName)
    $c = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName
    try { @{ MaxSizeKB = [int64]($c.MaximumSizeInBytes / 1KB); Mode = [string]$c.LogMode } }
    finally { $c.Dispose() }
}

function Set-EventLogSettings {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int64]$MaxSizeKB,
        [Parameter(Mandatory)][ValidateSet('Circular', 'AutoBackup', 'Retain')][string]$Mode
    )
    $c = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName
    try {
        $c.MaximumSizeInBytes = $MaxSizeKB * 1KB
        $c.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]$Mode
        try { $c.SaveChanges() }
        catch [System.UnauthorizedAccessException] {
            throw "Немає прав змінити журнал '$LogName'. Для журналу безпеки потрібне право 'Керування аудитом та журналом безпеки' (SeSecurityPrivilege): після кроку user-rights воно лише в Адміністратора безпеки, запустіть майстер від його імені."
        }
    }
    finally { $c.Dispose() }
}

function Format-LogMode {
    param([string]$Mode)
    switch ($Mode) {
        'Circular'   { 'Перезаписувати старі події за необхідності (Circular)' }
        'AutoBackup' { 'Архівувати журнал при заповненні (AutoBackup)' }
        'Retain'     { 'НЕ перезаписувати події (Retain)' }
        default      { $Mode }
    }
}

function Test-EventLogConfig {
    # Размер в КБ: кратен 64 (требование Windows), не менее 1024. Режим: Circular | AutoBackup | Retain.
    param($Params, [object[]]$Items)
    if (-not $Params.ContainsKey('Logs') -or $Params.Logs.Count -eq 0) { throw 'В profile.json нет steps -> event-log-settings -> Logs' }
    $known = @($Items | ForEach-Object { $_.Log })
    foreach ($name in $Params.Logs.Keys) {
        if ($known -notcontains $name) { throw "Logs: неизвестный журнал '$name'. Допустимые: $($known -join ', ')" }
        $l = $Params.Logs[$name]
        $n = 0L
        if (-not $l.ContainsKey('MaxSizeKB') -or -not [int64]::TryParse([string]$l.MaxSizeKB, [ref]$n)) { throw "Logs.$name.MaxSizeKB: ожидается целое число (КБ)" }
        if ($n -lt 1024 -or ($n % 64) -ne 0) { throw "Logs.$name.MaxSizeKB = ${n}: размер должен быть не менее 1024 КБ и кратен 64" }
        if (@('Circular', 'AutoBackup', 'Retain') -notcontains [string]$l.Retention) { throw "Logs.$name.Retention: допустимо Circular | AutoBackup | Retain, указано '$($l.Retention)'" }
    }
}
