# Ядро мастера: загрузка шагов, выполнение Apply/Verify/Rollback, меню.

function Get-Steps {
    $seqPath = Join-Path $Script:Root 'config\sequence.json'
    $sequence = @((Get-Content -Path $seqPath -Raw -Encoding UTF8 | ConvertFrom-Json).sequence)
    $steps = @()
    foreach ($id in $sequence) {
        $path = Join-Path $Script:Root "steps\$id.ps1"
        if (-not (Test-Path $path)) {
            Write-Ui "Шаг '$id' есть в sequence.json, но файл не найден: $path" Red
            continue
        }
        $step = & $path
        $missing = @('Id', 'Title', 'Apply', 'Verify') | Where-Object { -not $step.ContainsKey($_) }
        if ($missing) { Write-Ui "Шаг '$id': нет обязательных полей: $($missing -join ', ')" Red; continue }
        if ($step.Id -ne $id) { Write-Ui "Шаг '$id': Id внутри файла ($($step.Id)) не совпадает с именем файла" Red; continue }
        if (-not $step.ContainsKey('Reversible')) { $step.Reversible = $true }
        $steps += $step
    }
    # Предупредим о файлах шагов, не включённых в последовательность.
    Get-ChildItem -Path (Join-Path $Script:Root 'steps') -Filter '*.ps1' | ForEach-Object {
        if ($sequence -notcontains $_.BaseName) {
            Write-Ui "Внимание: steps\$($_.Name) не указан в config\sequence.json (не будет выполнен)." DarkYellow
        }
    }
    $steps
}

function New-StepContext {
    param($Step)
    $params = @{}
    $stepsCfg = $Script:LookProfile.steps
    if ($stepsCfg -and $stepsCfg.ContainsKey($Step.Id)) { $params = $stepsCfg[$Step.Id] }
    @{ Id = $Step.Id; Step = $Step; Params = $params; Profile = $Script:LookProfile }
}

function Get-StatusLabel {
    param([string]$Id)
    $st = Get-StepState -Id $Id
    if (-not $st) { return @('не выполнялся', 'Gray') }
    switch ($st.status) {
        'applied'    { @('применён', 'Green') }
        'skipped'    { @('пропущен', 'DarkYellow') }
        'rolledback' { @('откачен', 'Yellow') }
        'pending'    { @('не завершён', 'Red') }
        default      { @($st.status, 'Gray') }
    }
}

function Invoke-Guarded {
    # Выполняет действие; при исключении пишет в лог и в консоль, возвращает $false.
    param([scriptblock]$Action)
    try { & $Action }
    catch {
        Write-Ui "Ошибка: $($_.Exception.Message)" Red
        Write-Log "Ошибка: $($_.Exception.Message)" 'ERROR'
        $false
    }
}

function Invoke-StepVerify {
    param($Step)
    $ctx = New-StepContext $Step
    $checks = @(& $Step.Verify $ctx)
    Show-Checks $checks
    $failed = @($checks | Where-Object { -not $_.Ok })
    foreach ($c in $checks) {
        Write-Log ("Проверка [{0}] {1}: ожидалось '{2}', фактически '{3}' -> {4}" -f `
            $Step.Id, $c.Name, $c.Expected, $c.Actual, $(if ($c.Ok) { 'OK' } else { 'FAIL' }))
    }
    $failed.Count -eq 0
}

function Invoke-StepApply {
    param($Step)
    if (-not $Step.Reversible) {
        if (-not (Confirm-Action 'Этот шаг НЕОБРАТИМ (откат невозможен). Продолжить?')) { return $false }
    }
    $ctx = New-StepContext $Step
    $st = Get-StepState -Id $Step.Id

    # Резервная копия берётся один раз, до первого применения (повторный Apply её не затирает).
    if ($Step.ContainsKey('Backup') -and -not ($st -and $st.ContainsKey('backup'))) {
        $backup = & $Step.Backup $ctx
        $status = if ($st) { $st.status } else { 'pending' }
        Set-StepState -Id $Step.Id -Status $status -Backup $backup
        Write-Log "[$($Step.Id)] резервная копия исходных значений сохранена"
    }

    Write-Log "[$($Step.Id)] применение..."
    & $Step.Apply $ctx | Out-Null
    Set-StepState -Id $Step.Id -Status 'applied'
    Write-Log "[$($Step.Id)] применён" 'OK'

    Write-Ui 'Проверка результата:' Cyan
    Invoke-StepVerify $Step
}

function Invoke-StepRollback {
    param($Step)
    if (-not $Step.ContainsKey('Rollback')) {
        Write-Ui 'Для этого шага откат не предусмотрен.' Yellow; return $false
    }
    $st = Get-StepState -Id $Step.Id
    if (-not ($st -and $st.ContainsKey('backup'))) {
        Write-Ui 'Нет сохранённых исходных значений (шаг не применялся или уже откачен).' Yellow; return $false
    }
    $ctx = New-StepContext $Step
    & $Step.Rollback $ctx $st.backup | Out-Null
    Set-StepState -Id $Step.Id -Status 'rolledback' -ClearBackup
    Write-Log "[$($Step.Id)] откачен" 'OK'
    Write-Ui 'Исходные значения восстановлены.' Green
    $true
}

function Show-StepMenu {
    # Возвращает 'next' (идти дальше) или 'quit' (выйти из мастера).
    param($Step, [string]$Position, [switch]$Wizard)
    while ($true) {
        $label = Get-StatusLabel -Id $Step.Id
        Write-Ui ''
        Write-Ui ('-' * 72) DarkGray
        Write-Ui "Шаг $Position`: $($Step.Title)" Cyan
        if ($Step.ContainsKey('Reference')) { Write-Ui "Основание: $($Step.Reference)" DarkGray }
        if ($Step.ContainsKey('Description')) { Write-Ui $Step.Description }
        if (-not $Step.Reversible) { Write-Ui 'ВНИМАНИЕ: шаг необратим.' Yellow }
        Write-Ui "Статус: $($label[0])" $label[1]
        Write-Ui ''
        Write-Ui '  1 - Применить'
        Write-Ui '  2 - Проверить текущее состояние'
        Write-Ui '  3 - Пропустить / далее'
        Write-Ui '  4 - Откатить'
        Write-Ui '  0 - Выйти в меню'

        switch (Read-Choice -Allowed @('1', '2', '3', '4', '0')) {
            '1' {
                $ok = Invoke-Guarded { Invoke-StepApply $Step }
                if ($ok -and $Wizard) { return 'next' }
                if (-not $ok) { Write-Ui 'Шаг не завершён успешно (см. выше).' Red }
            }
            '2' { Invoke-Guarded { Invoke-StepVerify $Step } | Out-Null }
            '3' {
                if (-not (Get-StepState -Id $Step.Id)) {
                    Set-StepState -Id $Step.Id -Status 'skipped'
                    Write-Log "[$($Step.Id)] пропущен пользователем" 'WARN'
                }
                return 'next'
            }
            '4' { Invoke-Guarded { Invoke-StepRollback $Step } | Out-Null }
            '0' { return 'quit' }
        }
    }
}

function Show-StepTable {
    param($Steps)
    $i = 0
    foreach ($s in $Steps) {
        $i++
        $label = Get-StatusLabel -Id $s.Id
        Write-Host ('  {0,2}. ' -f $i) -NoNewline
        Write-Host ('[{0}]' -f $label[0]).PadRight(18) -NoNewline -ForegroundColor $label[1]
        Write-Host $s.Title
    }
}

function Invoke-Wizard {
    param($Steps)
    $n = $Steps.Count
    for ($i = 0; $i -lt $n; $i++) {
        if ((Show-StepMenu -Step $Steps[$i] -Position ('{0}/{1}' -f ($i + 1), $n) -Wizard) -eq 'quit') { return }
    }
    Write-Ui ''
    Write-Ui 'Мастер завершён. Итог:' Cyan
    Show-StepTable $Steps
    Read-Host 'Enter - вернуться в меню' | Out-Null
}

function Invoke-VerifyAll {
    param($Steps)
    $bad = 0
    foreach ($s in $Steps) {
        Write-Ui ''
        Write-Ui $s.Title Cyan
        $ok = Invoke-Guarded { Invoke-StepVerify $s }
        if (-not $ok) { $bad++ }
    }
    Write-Ui ''
    if ($bad -eq 0) { Write-Ui 'Все шаги соответствуют профилю.' Green }
    else { Write-Ui "Шагов с расхождениями: $bad из $($Steps.Count)." Red }
    Read-Host 'Enter - вернуться в меню' | Out-Null
}

function Start-MainMenu {
    while ($true) {
        $steps = @(Get-Steps)
        Clear-Host
        Write-Ui 'LOOK-Configurator: настройка ЛООК (Windows 11)' Cyan
        Write-Ui ('Компьютер: {0}   Пользователь: {1}' -f $env:COMPUTERNAME, $env:USERNAME) DarkGray
        Write-Ui ''
        Show-StepTable $steps
        Write-Ui ''
        Write-Ui '  1 - Пройти мастер по порядку'
        Write-Ui '  2 - Выбрать отдельный шаг'
        Write-Ui '  3 - Проверить все шаги'
        Write-Ui '  0 - Выход'

        switch (Read-Choice -Allowed @('1', '2', '3', '0')) {
            '1' { Invoke-Wizard $steps }
            '2' {
                $allowed = @('0') + @(1..$steps.Count | ForEach-Object { "$_" })
                $n = [int](Read-Choice -Prompt 'Номер шага (0 = назад)' -Allowed $allowed)
                if ($n -gt 0) { Show-StepMenu -Step $steps[$n - 1] -Position ('{0}/{1}' -f $n, $steps.Count) | Out-Null }
            }
            '3' { Invoke-VerifyAll $steps }
            '0' { Write-Log 'Мастер закрыт'; return }
        }
    }
}
