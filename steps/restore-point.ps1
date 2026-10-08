# Шаг: Створення точки відновлення операційної системи (розділ 2.6).
# Параметры: config\profile.json -> steps -> restore-point (Drive, MaxSize, PointName, AskForName, MinRestorePoints).
# Шаг можно вставлять в sequence.json несколько раз (см. README: «экземпляры шага»).
# Отката нет намеренно: точки восстановления не удаляются.

@{
    Id          = 'restore-point'
    Title       = 'Створення точки відновлення операційної системи'
    Reference   = 'розділ 2.6 (кроки 1-7)'
    Description = 'Вмикає захист системи для диска, задає ліміт простору, створює точку відновлення (назву можна змінити при запуску).'

    Apply       = {
        param($ctx)
        Test-RestorePointConfig $ctx.Params
        $p = Get-RestorePointSettings $ctx.Params

        $blocked = Get-RestoreBlockingPolicy
        if ($blocked) { throw "Відновлення системи вимкнено політикою ($blocked). Приберіть політику (Адміністративні шаблони -> Система -> Відновлення системи)." }

        Enable-ComputerRestore -Drive "$($p.Drive)\"
        Write-Log "Защита системы включена для $($p.Drive)"
        $resized = Set-ShadowStorageLimit -Drive $p.Drive -MaxSize $p.MaxSize

        $name = $p.PointName.Trim()
        if ($p.AskForName) {
            $in = Read-Host "Назва точки відновлення [$name]"
            if ($in -and $in.Trim()) { $name = $in.Trim() }
        }
        Write-Ui "Створення точки відновлення '$name'..." Cyan
        New-SystemRestorePoint -Name $name

        # Связь тома с хранилищем появляется при первой точке: если лимит не удалось задать раньше, повторяем.
        if (-not $resized) {
            if (-not (Set-ShadowStorageLimit -Drive $p.Drive -MaxSize $p.MaxSize)) {
                Write-Ui "Не вдалося задати ліміт простору ($($p.MaxSize)): див. лог. Перевірка покаже поточне значення." Yellow
            }
        }

        # Checkpoint-Computer відпрацював без помилки (ErrorAction Stop вище кинув би виняток) - це і є
        # ознака успіху. WMI-клас SystemRestore публікує новий запис із затримкою, тож чекаємо її окремо
        # і при затримці лише попереджаємо в журнал: крок усе одно позначається виконаним, а не "не завершён".
        Set-StepData -Id $ctx.Id -Data @{ PointName = $name; Created = (Get-Date).ToString('s') }
        if (Wait-RestorePoint -Name $name) {
            Write-Log "Создана точка восстановления '$name' ($($p.Drive), лимит $($p.MaxSize))" 'OK'
        }
        else {
            Write-Ui "Точка '$name' создана (Checkpoint-Computer не сообщил об ошибке), но пока не видна в списке - WMI публикует запись с задержкой. Загляните в «2 - Проверить» через полминуты." Yellow
            Write-Log "Точка восстановления '$name' создана, но не найдена в Get-ComputerRestorePoint за 30 с (WMI-задержка или ограничение доступа)" 'WARN'
        }
    }

    Verify      = {
        param($ctx)
        Test-RestorePointConfig $ctx.Params
        $p = Get-RestorePointSettings $ctx.Params

        $blocked = Get-RestoreBlockingPolicy
        New-Check 'Політика вимкнення відновлення системи' 'не задана' $(if ($blocked) { $blocked } else { 'не задана' }) (-not $blocked)

        $info = Get-ShadowStorageInfo -Drive $p.Drive
        if (-not $info -or -not $info.Exists) {
            New-Check "Ліміт простору для $($p.Drive)" $p.MaxSize 'захист не налаштований' $false
        }
        else {
            $exp = if ($p.MaxSize -ieq 'UNBOUNDED') { 'без обмеження' } else { '{0} (~{1})' -f $p.MaxSize, (Format-Bytes (Get-ExpectedMaxBytes $p.MaxSize $info.Capacity)) }
            New-Check "Ліміт простору для $($p.Drive)" $exp (Format-Bytes $info.MaxSpace) (Test-MaxSizeMatch $p.MaxSize $info.Capacity $info.MaxSpace)
        }

        $pts = @(Get-RestorePointList)
        $last = $pts | Sort-Object Time -Descending | Select-Object -First 1
        $lastText = if ($last) { "; остання: '{0}', {1:yyyy-MM-dd HH:mm}" -f $last.Name, $last.Time } else { '' }
        New-Check 'Точки відновлення' "щонайменше $($p.MinRestorePoints)" ("{0}{1}" -f $pts.Count, $lastText) ($pts.Count -ge $p.MinRestorePoints)

        $d = Get-StepData -Id $ctx.Id
        if ($d.ContainsKey('PointName')) {
            $hit = @($pts | Where-Object { $_.Name -eq $d.PointName })
            New-Check "Точка '$($d.PointName)' (створена цим кроком)" 'існує' $(if ($hit) { 'існує' } else { 'не знайдена' }) ([bool]$hit)
        }
    }
}
