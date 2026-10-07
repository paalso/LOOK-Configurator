# Шаг: Призначення прав користувачів (User Rights Assignment), розділ 3.2.2, таблиця 6.
# Значения: config\profile.json -> steps -> user-rights -> Rights (ключ = константа права, значение = список принципалов).
# Применяется через secedit [Privilege Rights]; затрагиваются только права, перечисленные в профиле.
# ВАЖНО: пустой список = «Ніхто» (право снимается со всех). Перед применением нужна точка відновлення.

@{
    Id          = 'user-rights'
    Title       = 'Призначення прав користувачів (User Rights Assignment)'
    Reference   = 'розділ 3.2.2, табл. 6'
    Description = 'Призначення прав за таблицею: групи та облікові записи за ролями ({SecurityAdmin}, {SystemAdmin}). Порожній список = Ніхто.'
    Reversible  = $true

    # Порядок и подписи для отчёта (константы прав; значения берутся из профиля).
    Items       = @(
        @{ Key = 'SeNetworkLogonRight'; Name = 'Access this computer from the network (Доступ до комп''ютеру з мережі)' }
        @{ Key = 'SeIncreaseQuotaPrivilege'; Name = 'Adjust memory quotas for a process (Налаштування квот пам''яті для процесу)' }
        @{ Key = 'SeInteractiveLogonRight'; Name = 'Allow log on locally (Локальний вхід в систему)' }
        @{ Key = 'SeRemoteInteractiveLogonRight'; Name = 'Allow log on through Remote Desktop Services (Вхід через службу віддалених робочих столів)' }
        @{ Key = 'SeBackupPrivilege'; Name = 'Back up files and directories (Архівування файлів і каталогів)' }
        @{ Key = 'SeChangeNotifyPrivilege'; Name = 'Bypass traverse checking (Обхід перехресної перевірки)' }
        @{ Key = 'SeSystemtimePrivilege'; Name = 'Change the system time (Зміна системного часу)' }
        @{ Key = 'SeTimeZonePrivilege'; Name = 'Change the time zone (Зміна часового поясу)' }
        @{ Key = 'SeCreatePagefilePrivilege'; Name = 'Create a pagefile (Створення файлу підкачки)' }
        @{ Key = 'SeCreateGlobalPrivilege'; Name = 'Create global objects (Створення глобальних об''єктів)' }
        @{ Key = 'SeCreateSymbolicLinkPrivilege'; Name = 'Create symbolic links (Створення символічних посилань)' }
        @{ Key = 'SeDebugPrivilege'; Name = 'Debug programs (Відладка програм)' }
        @{ Key = 'SeDenyNetworkLogonRight'; Name = 'Deny access to this computer from the network (Відмова в доступі до комп''ютера з мережі)' }
        @{ Key = 'SeDenyBatchLogonRight'; Name = 'Deny log on as a batch job (Відмова у вході в якості пакетного завдання)' }
        @{ Key = 'SeDenyServiceLogonRight'; Name = 'Deny log on as a service (Відмова у вході в якості служби)' }
        @{ Key = 'SeDenyInteractiveLogonRight'; Name = 'Deny log on locally (Заборонити локальний вхід)' }
        @{ Key = 'SeDenyRemoteInteractiveLogonRight'; Name = 'Deny log on through Remote Desktop Services (Заборонити вхід через службу терміналів)' }
        @{ Key = 'SeRemoteShutdownPrivilege'; Name = 'Force shutdown from a remote system (Примусове віддалене завершення роботи)' }
        @{ Key = 'SeAuditPrivilege'; Name = 'Generate security audits (Ведення аудиту безпеки)' }
        @{ Key = 'SeImpersonatePrivilege'; Name = 'Impersonate a client after authentication (Видавати себе за клієнта після автентифікації)' }
        @{ Key = 'SeIncreaseWorkingSetPrivilege'; Name = 'Increase a process working set (Збільшення робочого набору процесу)' }
        @{ Key = 'SeLoadDriverPrivilege'; Name = 'Load and unload device drivers (Завантаження і вивантаження драйверів пристроїв)' }
        @{ Key = 'SeBatchLogonRight'; Name = 'Log on as a batch job (Вхід в якості пакетного завдання)' }
        @{ Key = 'SeServiceLogonRight'; Name = 'Log on as a service (Вхід в якості служби)' }
        @{ Key = 'SeSecurityPrivilege'; Name = 'Manage auditing and security log (Керування аудитом та журналом безпеки)' }
        @{ Key = 'SeManageVolumePrivilege'; Name = 'Perform volume maintenance tasks (Виконання задач по обслуговуванню томів)' }
        @{ Key = 'SeSystemProfilePrivilege'; Name = 'Profile system performance (Продуктивність системи профілю)' }
        @{ Key = 'SeAssignPrimaryTokenPrivilege'; Name = 'Replace a process level token (Заміна маркера рівня процесу)' }
        @{ Key = 'SeRestorePrivilege'; Name = 'Restore files and directories (Відновлення файлів і каталогів)' }
        @{ Key = 'SeShutdownPrivilege'; Name = 'Shut down the system (Завершення роботи системи)' }
    )

    Backup      = {
        param($ctx)
        $rights = Get-ResolvedRights $ctx            # заодно проверяет профиль и существование учёток-ролей
        $cur = Save-SecurityPolicySnapshot -Id $ctx.Id -Section 'Privilege Rights' -Areas 'USER_RIGHTS'
        $saved = @{}
        # Права, которых нет в экспорте, никому не назначены: в копии это пустая строка.
        foreach ($k in $rights.Keys) { $saved[$k] = $(if ($cur.ContainsKey($k)) { [string]$cur[$k] } else { '' }) }
        $saved
    }

    Apply       = {
        param($ctx)
        $rights = Get-ResolvedRights $ctx
        Test-RightsGuard -Rights $rights
        $values = @{}
        foreach ($k in $rights.Keys) { $values[$k] = ConvertTo-RightsValue $rights[$k] }
        Set-SecurityPolicySection -Values $values -Section 'Privilege Rights' -Areas 'USER_RIGHTS'
        Write-Log "Права пользователей применены: $($values.Count) параметров" 'OK'
    }

    Verify      = {
        param($ctx)
        $rights = Get-ResolvedRights $ctx
        $cur = Get-SecurityPolicySection -Section 'Privilege Rights' -Areas 'USER_RIGHTS'
        $order = @($ctx.Step.Items | ForEach-Object { $_.Key })
        $names = @{}; foreach ($i in $ctx.Step.Items) { $names[$i.Key] = $i.Name }
        $keys = @($order | Where-Object { $rights.ContainsKey($_) }) + @($rights.Keys | Where-Object { $order -notcontains $_ } | Sort-Object)
        foreach ($k in $keys) {
            $want = @($rights[$k])
            $have = ConvertFrom-RightsValue $(if ($cur.ContainsKey($k)) { $cur[$k] } else { '' })
            $label = $(if ($names.ContainsKey($k)) { $names[$k] } else { $k })
            New-Check $label (Format-PrincipalList $want) (Format-PrincipalList $have) ((($want -join '|') -eq ($have -join '|')))
        }
    }

    Rollback    = {
        param($ctx, $backup)
        $values = @{}
        foreach ($k in $backup.Keys) { $values[$k] = [string]$backup[$k] }
        if ($values.Count -gt 0) { Set-SecurityPolicySection -Values $values -Section 'Privilege Rights' -Areas 'USER_RIGHTS' }
    }
}
