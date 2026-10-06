# Шаг: Політика аудиту (Audit Policies), вимога ЦПБ AU-2, розділ 3.2.1, таблиця 5.
# Налаштовується РОЗШИРЕНА політика аудиту (Advanced Audit Policy / System Audit Policies, підкатегорії)
# через auditpol: базові 9 категорій з таблиці 5 перекриваються підкатегоріями й самі не зберігаються.
# Значення: config\profile.json -> steps -> audit-policy.

@{
    Id          = 'audit-policy'
    Title       = 'Політика аудиту (Audit Policies)'
    Reference   = 'ЦПБ AU-2; розділ 3.2.1, табл. 5'
    Description = 'Розширена політика аудиту: усі підкатегорії (за замовчуванням Success+Failure, виключення в профілі) + пріоритет підкатегорій над базовими параметрами.'
    Reversible  = $true

    Backup      = {
        param($ctx)
        $file = Save-AuditPolicySnapshot -Id $ctx.Id
        $cur = Get-LegacyAuditOverride
        @{ File = $file; LegacyOverrideExisted = ($null -ne $cur); LegacyOverride = $cur }
    }

    Apply       = {
        param($ctx)
        Test-AuditConfig $ctx.Params
        $overrides = Get-AuditOverrideTable $ctx.Params
        $current = @(Get-AuditPolicy)
        if ($current.Count -eq 0) { throw 'auditpol не повернув жодної підкатегорії.' }

        # Меняем только то, что отличается от нужного (повторный запуск ничего не трогает).
        $byValue = @{}
        foreach ($e in $current) {
            $want = Get-ExpectedAuditValue $ctx.Params $e.Guid $overrides
            if ($e.Value -ne $want) {
                if (-not $byValue.ContainsKey($want)) { $byValue[$want] = @() }
                $byValue[$want] += $e.Guid
            }
        }
        foreach ($v in $byValue.Keys) {
            Set-AuditSubcategories -Guids $byValue[$v] -Value $v
            Write-Log "Аудит: $($byValue[$v].Count) подкатегорий -> $(Format-AuditValue $v)"
        }

        $force = if ($ctx.Params.ContainsKey('ForceSubcategoryOverride')) { [bool]$ctx.Params.ForceSubcategoryOverride } else { $true }
        if ($force) { Set-LegacyAuditOverride 1 }
        Write-Log "Политика аудита применена (изменено подкатегорий: $(@($byValue.Values | ForEach-Object { $_ }).Count))" 'OK'
    }

    Verify      = {
        param($ctx)
        Test-AuditConfig $ctx.Params
        $overrides = Get-AuditOverrideTable $ctx.Params
        $current = @(Get-AuditPolicy)

        $bad = @($current | Where-Object { $_.Value -ne (Get-ExpectedAuditValue $ctx.Params $_.Guid $overrides) })
        $actual = if ($bad.Count -eq 0) { "{0} з {0} відповідають" -f $current.Count }
                  else { '{0} з {1} відхиляються: {2}{3}' -f $bad.Count, $current.Count,
                         (($bad | Select-Object -First 8 | ForEach-Object { "$($_.Name) = $(Format-AuditValue $_.Value)" }) -join '; '),
                         $(if ($bad.Count -gt 8) { '; ...' } else { '' }) }
        $def = Format-AuditValue (ConvertTo-AuditValue $ctx.Params.Default)
        New-Check 'Підкатегорії аудиту' "усі: $def (виключень: $($overrides.Count))" $actual ($current.Count -gt 0 -and $bad.Count -eq 0)

        $known = @($current | ForEach-Object { $_.Guid })
        foreach ($g in $overrides.Keys) {
            if ($known -notcontains $g) { New-Check "Виключення $g" 'підкатегорія існує' 'не знайдена в системі' $false }
        }

        $force = if ($ctx.Params.ContainsKey('ForceSubcategoryOverride')) { [bool]$ctx.Params.ForceSubcategoryOverride } else { $true }
        if ($force) {
            $cur = Get-LegacyAuditOverride
            New-Check 'Пріоритет підкатегорій над базовими (SCENoApplyLegacyAuditPolicy)' '1 (Ввімкнено)' $(if ($null -eq $cur) { 'не задано' } else { "$cur" }) ($cur -eq 1)
        }
    }

    Rollback    = {
        param($ctx, $backup)
        Restore-AuditPolicySnapshot -File $backup.File
        if ($backup.LegacyOverrideExisted) { Set-LegacyAuditOverride $backup.LegacyOverride } else { Set-LegacyAuditOverride $null }
    }
}
