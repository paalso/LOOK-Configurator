# Шаг: Доступ до журналу подій: власник і дозволи eventvwr.exe / eventvwr.msc, розділ 4.1, кроки 1-5.
# Вимоги: ЦПБ AU-9 (журнал доступний лише Адміністратору безпеки), AC-6(1).
# Параметры: config\profile.json -> steps -> eventvwr-access (Files, Owner, Entries).
# Владелец ставится через takeown (/A = группа Administrators), DACL через Set-Acl. Записи по SID, роль {SecurityAdmin} из local-accounts.

@{
    Id          = 'eventvwr-access'
    Title       = 'Доступ до журналу подій: власник і дозволи eventvwr'
    Reference   = 'ЦПБ AU-9, AC-6(1); розділ 4.1'
    Description = 'eventvwr.exe/.msc: власник - Administrators; дозволи лише TrustedInstaller, SYSTEM, пакети програм і Адміністратор безпеки. Група Administrators і Users з дозволів видаляються.'
    Reversible  = $true

    Backup      = {
        param($ctx)
        $plan = Get-EventvwrPlan $ctx
        $saved = @{}
        foreach ($f in $plan.Files) {
            if (-not (Test-Path -LiteralPath $f)) { throw "Файл не знайдено: $f" }
            $saved[$f] = Get-FileSecuritySnapshot -Path $f
        }
        $saved
    }

    Apply       = {
        param($ctx)
        $plan = Get-EventvwrPlan $ctx
        foreach ($f in $plan.Files) {
            Set-FileOwner -Path $f -Sid $plan.OwnerSid      # спочатку власник: тоді можна змінювати DACL
            Set-FileDacl -Path $f -Entries $plan.Entries
            Write-Log "Журнал подій: власник і дозволи '$f' встановлено" 'OK'
        }
    }

    Verify      = {
        param($ctx)
        $plan = Get-EventvwrPlan $ctx
        $expText = (($plan.Entries.Keys | ForEach-Object { "$(Format-SidName $_): $($plan.Entries[$_])" }) -join '; ')
        foreach ($f in $plan.Files) {
            if (-not (Test-Path -LiteralPath $f)) { New-Check "$f" 'існує' 'не знайдено' $false; continue }
            $r = Test-FileSecurity -Path $f -OwnerSid $plan.OwnerSid -Expected $plan.Entries
            New-Check "$f [ЦПБ AU-9, AC-6(1)]" ("власник: $(Format-SidName $plan.OwnerSid); $expText; без успадкування") $r.Actual $r.Ok
        }
    }

    Rollback    = {
        param($ctx, $backup)
        foreach ($f in @($backup.Keys)) {
            if (Test-Path -LiteralPath $f) { Restore-FileSecurity -Path $f -Snapshot $backup[$f] }
        }
    }
}
