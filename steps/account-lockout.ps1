# Шаг: Блокування облікового запису (Account Lockout Policy), вимога ЦПБ AC-7, розділ 3.1.2, таблиця 4.
# Значения: config\profile.json -> steps -> account-lockout (имена параметров = имена в secedit).
# Применяется через secedit, секция [System Access] - та же, что и password-policy (lib\SecPol.ps1).

@{
    Id          = 'account-lockout'
    Title       = 'Блокування облікового запису (Account Lockout Policy)'
    Reference   = 'ЦПБ AC-7; розділ 3.1.2, табл. 4'
    Description = 'Порогове значення блокування, час блокування, термін скидання лічильника невдалих спроб входу. Застосовується через secedit.'
    Reversible  = $true

    # Key = имя параметра в secedit; Min/Max = допустимые значения (проверка до применения).
    Items       = @(
        @{ Key = 'LockoutBadCount';    Kind = 'count';   Min = 0;  Max = 999;   Name = 'Порогове значення блокування (Account lockout threshold)' }
        @{ Key = 'LockoutDuration';    Kind = 'minutes'; Min = 0;  Max = 99999; Name = 'Час до скидання блокування (Account lockout duration)' }
        @{ Key = 'ResetLockoutCount';  Kind = 'minutes'; Min = 1;  Max = 99999; Name = 'Термін скидання лічильника (Reset account lockout counter after)' }
    )

    Backup      = {
        param($ctx)
        $current = Save-SecurityPolicySnapshot -Id $ctx.Id
        $saved = @{}
        foreach ($i in $ctx.Step.Items) {
            $n = 0L
            if ($current.ContainsKey($i.Key) -and [int64]::TryParse($current[$i.Key], [ref]$n)) { $saved[$i.Key] = $n }
        }
        $saved
    }

    Apply       = {
        param($ctx)
        Test-PolicyValues -Params $ctx.Params -Items $ctx.Step.Items
        $thr = [int64]$ctx.Params.LockoutBadCount
        $dur = [int64]$ctx.Params.LockoutDuration
        $rst = [int64]$ctx.Params.ResetLockoutCount
        if ($dur -ne 0 -and $rst -gt $dur) {
            throw "ResetLockoutCount ($rst) не може перевищувати LockoutDuration ($dur): Windows відхилить таку пару (крім LockoutDuration=0 - 'до розблокування адміністратором')."
        }
        $values = @{ LockoutBadCount = $thr }
        # LockoutBadCount=0 означає "поріг вимкнено": Windows тоді не приймає LockoutDuration/ResetLockoutCount (UI їх ховає).
        if ($thr -gt 0) { $values.LockoutDuration = $dur; $values.ResetLockoutCount = $rst }
        Set-SystemAccessPolicy -Values $values
        Write-Log "Политика блокировки учётных записей применена: $((($values.Keys | Sort-Object) | ForEach-Object { "$_=$($values[$_])" }) -join ', ')" 'OK'
    }

    Verify      = {
        param($ctx)
        Test-PolicyValues -Params $ctx.Params -Items $ctx.Step.Items
        $current = Get-SystemAccessPolicy
        $thr = [int64]$ctx.Params.LockoutBadCount
        foreach ($i in $ctx.Step.Items) {
            if ($i.Key -ne 'LockoutBadCount' -and $thr -eq 0) {
                New-Check $i.Name 'не застосовується (поріг блокування вимкнено)' 'не застосовується' $true
                continue
            }
            $want = [int64]$ctx.Params[$i.Key]
            $have = $null
            $n = 0L
            if ($current.ContainsKey($i.Key) -and [int64]::TryParse($current[$i.Key], [ref]$n)) { $have = $n }
            New-Check $i.Name (Format-PolicyValue $i.Kind $want) (Format-PolicyValue $i.Kind $have) ($null -ne $have -and $have -eq $want)
        }
    }

    Rollback    = {
        param($ctx, $backup)
        $values = @{}
        foreach ($i in $ctx.Step.Items) {
            if ($backup.ContainsKey($i.Key) -and $null -ne $backup[$i.Key]) { $values[$i.Key] = [int64]$backup[$i.Key] }
        }
        if ($values.Count -gt 0) { Set-SystemAccessPolicy -Values $values }
    }
}
