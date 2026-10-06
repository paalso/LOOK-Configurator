# Помощники: локальная политика безопасности через secedit (раздел [System Access]:
# политика паролей, блокировка учётных записей и т.п.). Эти параметры хранятся в SAM/LSA, а не в реестре,
# поэтому reg.exe и Registry.pol (LGPO) для них не подходят. Имена параметров не зависят от языка Windows.

function Export-SecurityPolicy {
    param([Parameter(Mandatory)][string]$Path)
    Invoke-Native -File 'secedit.exe' -Arguments @('/export', '/cfg', $Path, '/areas', 'SECURITYPOLICY', '/quiet') | Out-Null
}

function Read-SystemAccessSection {
    # Читает секцию [System Access] из .inf (UTF-16) в хэштаблицу имя -> строковое значение.
    param([Parameter(Mandatory)][string]$Path)
    $values = @{}
    $in = $false
    foreach ($line in (Get-Content -Path $Path -Encoding Unicode)) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $in = ($Matches[1] -eq 'System Access'); continue }
        if ($in -and $line -match '^\s*(\w+)\s*=\s*(.*?)\s*$') { $values[$Matches[1]] = $Matches[2] }
    }
    $values
}

function Get-SystemAccessPolicy {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('secpol-{0}.inf' -f [guid]::NewGuid())
    try { Export-SecurityPolicy -Path $tmp; Read-SystemAccessSection -Path $tmp }
    finally { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue }
}

function Save-SecurityPolicySnapshot {
    # Резервная копия: полный экспорт политики в state\backups\<id>-before-<время>.inf (для аудита)
    # и значения [System Access] (для отката).
    param([Parameter(Mandatory)][string]$Id)
    $dir = Join-Path $Script:StateDir 'backups'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir ('{0}-before-{1:yyyyMMdd-HHmmss}.inf' -f $Id, (Get-Date))
    Export-SecurityPolicy -Path $file
    Write-Log "Исходная политика безопасности сохранена: $file"
    Read-SystemAccessSection -Path $file
}

function Set-SystemAccessPolicy {
    # Применяет только перечисленные параметры (остальные не затрагиваются).
    param([Parameter(Mandatory)][hashtable]$Values)
    $work = Join-Path $Script:StateDir 'work'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $inf = Join-Path $work 'apply.inf'
    $sdb = Join-Path $work 'apply.sdb'
    $log = Join-Path $work 'secedit.log'
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[System Access]')
    foreach ($k in ($Values.Keys | Sort-Object)) { $lines += ('{0} = {1}' -f $k, $Values[$k]) }
    Set-Content -Path $inf -Value $lines -Encoding Unicode
    try {
        Invoke-Native -File 'secedit.exe' -Arguments @('/configure', '/db', $sdb, '/cfg', $inf, '/areas', 'SECURITYPOLICY', '/log', $log, '/quiet') | Out-Null
    }
    catch {
        $tail = if (Test-Path $log) { (Get-Content -Path $log -Tail 15) -join "`n" } else { '' }
        throw "secedit /configure завершился с ошибкой. Журнал: $log`n$tail`n$($_.Exception.Message)"
    }
    Remove-Item -Path "$sdb*", $inf -Force -ErrorAction SilentlyContinue
}

function Format-PolicyValue {
    param([string]$Kind, $Value)
    if ($null -eq $Value -or "$Value" -eq '') { return 'не задано' }
    switch ($Kind) {
        'bool'   { if ([int64]$Value -ne 0) { 'Ввімкнено' } else { 'Вимкнено' } }
        'days'   { if ([int64]$Value -eq -1) { 'необмежено' } else { "$Value днів" } }
        'length' { "$Value символів" }
        'count'  { "$Value" }
        'minutes' { "$Value хв" }
        default  { "$Value" }
    }
}

function Test-PolicyValues {
    # Проверка значений из профиля до применения. $Items: @{Key; Min; Max}.
    param([hashtable]$Params, [object[]]$Items)
    foreach ($i in $Items) {
        if (-not $Params.ContainsKey($i.Key)) { throw "В profile.json нет параметра '$($i.Key)'" }
        $n = 0L
        if (-not [int64]::TryParse([string]$Params[$i.Key], [ref]$n)) { throw "'$($i.Key)': ожидается целое число" }
        if ($n -lt $i.Min -or $n -gt $i.Max) { throw "'$($i.Key)' = $n вне допустимого диапазона $($i.Min)..$($i.Max)" }
    }
}
