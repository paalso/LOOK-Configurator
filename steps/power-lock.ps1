# Шаг: Ініціювання блокування пристрою (ПК), вимога ЦПБ AC-11.
# Файл возвращает описание шага (хэштаблицу). Подробности контракта: README.md.

@{
    Id          = 'power-lock'
    Title       = 'Ініціювання блокування пристрою (ПК)'
    Reference   = 'ЦПБ AC-11; розділ 1.4'
    Description = 'План електроживлення: вимкнення дисплея та перехід у сон через N хв (від мережі і від батареї).'
    Reversible  = $true

    # Что настраиваем. Param = ключ в config\profile.json -> steps -> power-lock.
    # GUID: 7516b95f-... = «Дисплей», 3c0bc021-... = «Отключать экран через»,
    #       238c9fa8-... = «Сон»,     29f6c1db-... = «Сон после».
    Items       = @(
        @{ Key = 'display-ac'; Name = 'Вимикати дисплей (від мережі)';     Param = 'DisplayOffAcMinutes'; Source = 'AC'
           Sub = '7516b95f-f776-4464-8c53-06167f40cc99'; Setting = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' }
        @{ Key = 'display-dc'; Name = 'Вимикати дисплей (від батареї)';    Param = 'DisplayOffDcMinutes'; Source = 'DC'
           Sub = '7516b95f-f776-4464-8c53-06167f40cc99'; Setting = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' }
        @{ Key = 'sleep-ac';   Name = 'Перевести у режим сну (від мережі)';  Param = 'SleepAfterAcMinutes'; Source = 'AC'
           Sub = '238c9fa8-0aad-41ed-83f4-97be242c8f20'; Setting = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' }
        @{ Key = 'sleep-dc';   Name = 'Перевести у режим сну (від батареї)'; Param = 'SleepAfterDcMinutes'; Source = 'DC'
           Sub = '238c9fa8-0aad-41ed-83f4-97be242c8f20'; Setting = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' }
    )

    # Запоминаем исходные значения (секунды) для отката.
    Backup      = {
        param($ctx)
        $saved = @{}
        foreach ($i in $ctx.Step.Items) {
            $saved[$i.Key] = (Get-PowerSetting -Sub $i.Sub -Setting $i.Setting)[$i.Source]
        }
        $saved
    }

    Apply       = {
        param($ctx)
        foreach ($i in $ctx.Step.Items) {
            if (-not $ctx.Params.ContainsKey($i.Param)) { throw "В profile.json нет параметра '$($i.Param)'" }
            $minutes = [int]$ctx.Params[$i.Param]
            Set-PowerSetting -Sub $i.Sub -Setting $i.Setting -Source $i.Source -Seconds ($minutes * 60)
        }
        Update-ActivePowerScheme
    }

    Verify      = {
        param($ctx)
        foreach ($i in $ctx.Step.Items) {
            $expected = [int]$ctx.Params[$i.Param] * 60
            $actual = (Get-PowerSetting -Sub $i.Sub -Setting $i.Setting)[$i.Source]
            New-Check -Name $i.Name -Expected (Format-Seconds $expected) -Actual (Format-Seconds $actual) `
                -Ok ($null -ne $actual -and [int64]$actual -eq $expected)
        }
    }

    Rollback    = {
        param($ctx, $backup)
        foreach ($i in $ctx.Step.Items) {
            if ($null -ne $backup[$i.Key]) {
                Set-PowerSetting -Sub $i.Sub -Setting $i.Setting -Source $i.Source -Seconds ([int]$backup[$i.Key])
            }
        }
        Update-ActivePowerScheme
    }
}
