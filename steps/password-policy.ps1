# Шаг: Політика паролів (Password Policy), вимога ЦПБ IA-2, розділ 3.1.1, таблиця 3.
# Значения: config\profile.json -> steps -> password-policy (имена параметров = имена в secedit).
# Применяется через secedit (те же параметры, что в secpol.msc / gpedit).

@{
    Id          = 'password-policy'
    Title       = 'Політика паролів (Password Policy)'
    Reference   = 'ЦПБ IA-2; розділ 3.1.1, табл. 3'
    Description = 'Журнал паролів, мін./макс. термін дії, довжина, складність, зворотне шифрування. Застосовується через secedit; змінюються лише ці 6 параметрів.'
    Reversible  = $true

    # Key = имя параметра в secedit; Min/Max = допустимые значения (проверка до применения).
    Items       = @(
        @{ Key = 'PasswordHistorySize';    Kind = 'count';  Min = 0;  Max = 24;  Name = 'Вести журнал паролів (Enforce password history)' }
        @{ Key = 'MaximumPasswordAge';     Kind = 'days';   Min = -1; Max = 999; Name = 'Максимальний термін дії пароля (Maximum password age)' }
        @{ Key = 'MinimumPasswordAge';     Kind = 'days';   Min = 0;  Max = 998; Name = 'Мінімальний термін дії пароля (Minimum password age)' }
        @{ Key = 'MinimumPasswordLength';  Kind = 'length'; Min = 0;  Max = 128; Name = 'Мінімальна довжина пароля (Minimum password length)' }
        @{ Key = 'PasswordComplexity';     Kind = 'bool';   Min = 0;  Max = 1;   Name = 'Вимоги складності (Password must meet complexity requirements)' }
        @{ Key = 'ClearTextPassword';      Kind = 'bool';   Min = 0;  Max = 1;   Name = 'Зворотне шифрування (Store password using reversible encryption)' }
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
        $max = [int64]$ctx.Params.MaximumPasswordAge
        $min = [int64]$ctx.Params.MinimumPasswordAge
        if ($max -ne -1 -and $min -ge $max) {
            throw "MinimumPasswordAge ($min) должен быть меньше MaximumPasswordAge ($max): Windows отклонит такую пару."
        }
        $values = @{}
        foreach ($i in $ctx.Step.Items) { $values[$i.Key] = [int64]$ctx.Params[$i.Key] }
        Set-SystemAccessPolicy -Values $values
        Write-Log "Политика паролей применена: $((($values.Keys | Sort-Object) | ForEach-Object { "$_=$($values[$_])" }) -join ', ')" 'OK'
    }

    Verify      = {
        param($ctx)
        Test-PolicyValues -Params $ctx.Params -Items $ctx.Step.Items
        $current = Get-SystemAccessPolicy
        foreach ($i in $ctx.Step.Items) {
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
