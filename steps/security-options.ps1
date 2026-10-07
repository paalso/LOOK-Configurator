# Шаг: Параметри безпеки (Security Options), розділ 3.2.3, таблиця 7 (пункти 12-42).
# Значения: config\profile.json -> steps -> security-options -> Values (ключ = Id параметра из Items ниже).
# Реестровые параметры пишутся напрямую (с точным типом REG_*), проверка читает фактическое значение реестра.
# Параметры из [System Access] (Kind = SystemAccess) идут через secedit.
# Чтобы добавить параметр (например, пункты 1-11 таблицы), допишите строку в Items и значение в Values.

@{
    Id          = 'security-options'
    Title       = 'Параметри безпеки (Security Options)'
    Reference   = 'розділ 3.2.3, табл. 7 (п. 12-42); ЦПБ ІА-6, AC-8'
    Description = 'Параметри безпеки з таблиці 7: підпис/шифрування каналів, інтерактивний вхід, повідомлення, мережеві та UAC-параметри. Застосовуються лише ті, що є в профілі.'
    Reversible  = $true

    # Num = номер пункта в таблице; Id = ключ в Values; Kind = DWord | String | MultiString | SystemAccess.
    Items       = @(
        @{ Num = 12; Id = 'DomainMember_RequireSignOrSeal'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Title = 'Domain member: Digitally encrypt or sign secure channel data (always)' }
        @{ Num = 13; Id = 'DomainMember_SealSecureChannel'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Title = 'Domain member: Digitally encrypt secure channel data (when possible)' }
        @{ Num = 14; Id = 'DomainMember_SignSecureChannel'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Title = 'Domain member: Digitally sign secure channel data (when possible)' }
        @{ Num = 15; Id = 'DomainMember_RequireStrongKey'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Title = 'Domain member: Require strong (Windows 2000 or later) session key' }
        @{ Num = 16; Id = 'DontDisplayLockedUserId'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DontDisplayLockedUserId'; Title = 'Interactive logon: Display user information when the session is locked' }
        @{ Num = 17; Id = 'DisableCAD'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DisableCAD'; Title = 'Interactive logon: Do not require CTRL+ALT+DEL' }
        @{ Num = 18; Id = 'DontDisplayLastUserName'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DontDisplayLastUserName'; Title = 'Interactive logon: Do not display last signed-in' }
        @{ Num = 19; Id = 'InactivityTimeoutSecs'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; Title = 'Interactive logon: Machine inactivity limit' }
        @{ Num = 20; Id = 'LegalNoticeText'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'legalnoticetext'; Title = 'Interactive logon: Message text for users attempting to log on' }
        @{ Num = 21; Id = 'LegalNoticeCaption'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'legalnoticecaption'; Title = 'Interactive logon: Message title for users attempting to log on' }
        @{ Num = 22; Id = 'CachedLogonsCount'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'CachedLogonsCount'; Title = 'Interactive logon: Number of previous logons to cache' }
        @{ Num = 23; Id = 'Client_RequireSecuritySignature'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Title = 'Microsoft network client: Digitally sign communications (always)' }
        @{ Num = 24; Id = 'Client_EnableSecuritySignature'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'EnableSecuritySignature'; Title = 'Microsoft network client: Digitally sign communications (if server agrees)' }
        @{ Num = 25; Id = 'Server_AutoDisconnect'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoDisconnect'; Title = 'Microsoft network server: Amount of idle time required before suspending session' }
        @{ Num = 26; Id = 'Server_RequireSecuritySignature'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RequireSecuritySignature'; Title = 'Microsoft network server: Digitally sign communications (always)' }
        @{ Num = 27; Id = 'Server_EnableForcedLogOff'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'EnableForcedLogOff'; Title = 'Microsoft network server: Disconnect clients when logon hours expire' }
        @{ Num = 28; Id = 'RestrictAnonymous'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Title = 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' }
        @{ Num = 29; Id = 'AllowedExactPaths'; Kind = 'MultiString'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'; Name = 'Machine'; Title = 'Network access: Remotely accessible registry paths' }
        @{ Num = 30; Id = 'AllowedPaths'; Kind = 'MultiString'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'; Name = 'Machine'; Title = 'Network access: Remotely accessible registry paths and sub-paths' }
        @{ Num = 31; Id = 'ForceLogoffWhenHourExpire'; Kind = 'SystemAccess'; Path = $null; Name = 'ForceLogoffWhenHourExpire'; Title = 'Network security: Force logoff when logon hours expire' }
        @{ Num = 32; Id = 'LDAPClientIntegrity'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Title = 'Network security: LDAP client signing requirements' }
        @{ Num = 33; Id = 'ShutdownWithoutLogon'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ShutdownWithoutLogon'; Title = 'Shutdown: Allow system to be shut down without having to log on' }
        @{ Num = 34; Id = 'ClearPageFileAtShutdown'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'ClearPageFileAtShutdown'; Title = 'Shutdown: Clear virtual memory pagefile' }
        @{ Num = 35; Id = 'ForceKeyProtection'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography'; Name = 'ForceKeyProtection'; Title = 'System cryptography: Force strong key protection for user keys stored on the computer' }
        @{ Num = 36; Id = 'PromptOnSecureDesktop'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'PromptOnSecureDesktop'; Title = 'User Account Control: Switch to the secure desktop when prompting for elevation' }
        @{ Num = 37; Id = 'ConsentPromptBehaviorAdmin'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Title = 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' }
        @{ Num = 38; Id = 'ConsentPromptBehaviorUser'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorUser'; Title = 'User Account Control: Behavior of the elevation prompt for standard users' }
        @{ Num = 39; Id = 'EnableSecureUIAPaths'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSecureUIAPaths'; Title = 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' }
        @{ Num = 40; Id = 'ValidateAdminCodeSignatures'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ValidateAdminCodeSignatures'; Title = 'User Account Control: Only elevate executables that are signed and validated' }
        @{ Num = 41; Id = 'EnableUIADesktopToggle'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableUIADesktopToggle'; Title = 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' }
        @{ Num = 42; Id = 'FilterAdministratorToken'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'FilterAdministratorToken'; Title = 'User Account Control: Admin Approval Mode for the Built-in Administrator account' }
    )

    Backup      = {
        param($ctx)
        $plan = Get-SecurityOptionPlan $ctx
        $saved = @{ Reg = @{}; Sys = @{} }
        $sys = @($plan | Where-Object { $_.Item.Kind -eq 'SystemAccess' })
        if ($sys.Count -gt 0) {
            $cur = Save-SecurityPolicySnapshot -Id $ctx.Id
            foreach ($p in $sys) {
                $n = 0L
                if ($cur.ContainsKey($p.Item.Name) -and [int64]::TryParse($cur[$p.Item.Name], [ref]$n)) { $saved.Sys[$p.Item.Name] = $n }
            }
        }
        foreach ($p in @($plan | Where-Object { $_.Item.Kind -ne 'SystemAccess' })) {
            $info = Get-RegValueInfo -Path $p.Item.Path -Name $p.Item.Name
            $saved.Reg[$p.Item.Id] = @{ Exists = [bool]$info.Exists; Kind = $info.Kind; Value = $info.Value }
        }
        $saved
    }

    Apply       = {
        param($ctx)
        $plan = Get-SecurityOptionPlan $ctx
        $sysValues = @{}
        foreach ($p in $plan) {
            if ($p.Item.Kind -eq 'SystemAccess') { $sysValues[$p.Item.Name] = $p.Value }
            else { Set-RegValue -Path $p.Item.Path -Name $p.Item.Name -Value $p.Value -Kind $p.Item.Kind }
        }
        if ($sysValues.Count -gt 0) { Set-SystemAccessPolicy -Values $sysValues }
        Write-Log "Параметры безопасности применены: $($plan.Count) параметров" 'OK'
    }

    Verify      = {
        param($ctx)
        $plan = Get-SecurityOptionPlan $ctx
        $sysCur = $null
        if (@($plan | Where-Object { $_.Item.Kind -eq 'SystemAccess' }).Count -gt 0) { $sysCur = Get-SystemAccessPolicy }
        foreach ($p in $plan) {
            $i = $p.Item
            if ($i.Kind -eq 'SystemAccess') {
                $n = 0L
                $ok = $sysCur.ContainsKey($i.Name) -and [int64]::TryParse($sysCur[$i.Name], [ref]$n)
                $info = @{ Exists = $ok; Kind = 'SystemAccess'; Value = $n }
            }
            else { $info = Get-RegValueInfo -Path $i.Path -Name $i.Name }
            $actual = Format-OptionValue -Kind $i.Kind -Value $info.Value -Exists $info.Exists
            if ($info.Exists -and $i.Kind -ne 'SystemAccess' -and $info.Kind -ne $i.Kind) { $actual = "$actual (тип $($info.Kind))" }
            New-Check ('{0}. {1}' -f $i.Num, $i.Title) (Format-OptionValue -Kind $i.Kind -Value $p.Value -Exists $true) $actual (Test-OptionMatches -Item $i -Want $p.Value -Info $info)
        }
    }

    Rollback    = {
        param($ctx, $backup)
        foreach ($id in @($backup.Reg.Keys)) {
            $item = @($ctx.Step.Items | Where-Object { $_.Id -eq $id })[0]
            if (-not $item) { continue }
            $b = $backup.Reg[$id]
            if ($b.Exists) { Set-RegValue -Path $item.Path -Name $item.Name -Value $b.Value -Kind $b.Kind }
            else { Remove-RegValue -Path $item.Path -Name $item.Name }
        }
        if ($backup.Sys.Count -gt 0) { Set-SystemAccessPolicy -Values $backup.Sys }
    }
}
