# Шаг: Налаштування журналів подій (розмір і метод збереження), розділ 4.1/4.2, таблиця «Параметри журналів».
# Параметры: config\profile.json -> steps -> event-log-settings -> Logs -> <Application|Security|System> { MaxSizeKB, Retention }.
# Применяется к самому журналу (то, что видно в «Журнал подій -> Властивості»).

@{
    Id          = 'event-log-settings'
    Title       = 'Налаштування журналів подій (розмір і метод збереження)'
    Reference   = 'розділ 4.1/4.2; ЦПБ AU-4, AU-5'
    Description = 'Максимальний розмір і метод збереження подій для журналів додатків, безпеки та системи.'
    Reversible  = $true

    # Num* = номера пунктов таблицы (размер / метод хранения).
    Items       = @(
        @{ Log = 'Application'; SizeNum = 1; SizeTitle = 'Maximum application log size';  RetNum = 4; RetTitle = 'Retention method for application log' }
        @{ Log = 'Security';    SizeNum = 2; SizeTitle = 'Maximum security log size';     RetNum = 5; RetTitle = 'Retention method for security log' }
        @{ Log = 'System';      SizeNum = 3; SizeTitle = 'Maximum system log size';       RetNum = 6; RetTitle = 'Retention method for system log' }
    )

    Backup      = {
        param($ctx)
        Test-EventLogConfig -Params $ctx.Params -Items $ctx.Step.Items
        $saved = @{}
        foreach ($name in $ctx.Params.Logs.Keys) { $saved[$name] = Get-EventLogSettings -LogName $name }
        $saved
    }

    Apply       = {
        param($ctx)
        Test-EventLogConfig -Params $ctx.Params -Items $ctx.Step.Items
        foreach ($name in $ctx.Params.Logs.Keys) {
            $l = $ctx.Params.Logs[$name]
            Set-EventLogSettings -LogName $name -MaxSizeKB ([int64]$l.MaxSizeKB) -Mode ([string]$l.Retention)
            Write-Log "Журнал ${name}: размер $($l.MaxSizeKB) КБ, режим $($l.Retention)" 'OK'
        }
    }

    Verify      = {
        param($ctx)
        Test-EventLogConfig -Params $ctx.Params -Items $ctx.Step.Items
        foreach ($i in $ctx.Step.Items) {
            if (-not $ctx.Params.Logs.ContainsKey($i.Log)) { continue }
            $want = $ctx.Params.Logs[$i.Log]
            $cur = Get-EventLogSettings -LogName $i.Log
            New-Check ('{0}. {1}' -f $i.SizeNum, $i.SizeTitle) ("{0:N0} KB" -f [int64]$want.MaxSizeKB) ("{0:N0} KB" -f $cur.MaxSizeKB) ($cur.MaxSizeKB -eq [int64]$want.MaxSizeKB)
            New-Check ('{0}. {1}' -f $i.RetNum, $i.RetTitle) (Format-LogMode ([string]$want.Retention)) (Format-LogMode $cur.Mode) ($cur.Mode -eq [string]$want.Retention)
        }
    }

    Rollback    = {
        param($ctx, $backup)
        foreach ($name in @($backup.Keys)) {
            Set-EventLogSettings -LogName $name -MaxSizeKB ([int64]$backup[$name].MaxSizeKB) -Mode ([string]$backup[$name].Mode)
        }
    }
}
