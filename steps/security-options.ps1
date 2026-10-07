# Шаг: Параметри безпеки (Security Options), розділ 3.2.3, таблиця 7 (пункти 1-42).
# Значения: config\profile.json -> steps -> security-options -> Values (ключ = Id параметра из Items ниже).
# Реестровые параметры пишутся напрямую (с точным типом REG_*), проверка читает фактическое значение реестра.
# Параметры из [System Access] (Kind = SystemAccess) идут через secedit.
# Req = требование ЦПБ / приложение к Акту (выводится в отчёте проверки).
# Kind = RenameBuiltin: переименование вбудованих Administrator (RID 500) / Guest (RID 501), по SID, а не по имени.
# Scope = DC: пункты только для контроллера домена; на обычной машине пропускаются (ApplyDomainControllerItems = true заставит применить).
# Чтобы добавить параметр (например, пункты 1-11 таблицы), допишите строку в Items и значение в Values.

@{
    Id          = 'security-options'
    Title       = 'Параметри безпеки (Security Options)'
    Reference   = 'розділ 3.2.3, табл. 7 (п. 1-42); ЦПБ ІА-6, AC-8, AU-5'
    Description = 'Параметри безпеки з таблиці 7: підпис/шифрування каналів, інтерактивний вхід, повідомлення, мережеві та UAC-параметри. Застосовуються лише ті, що є в профілі.'
    Reversible  = $true

    # Num = номер пункта в таблице; Id = ключ в Values; Kind = DWord | String | MultiString | SystemAccess | RenameBuiltin.
    Items       = @(
        @{ Num = 1; Id = 'RenameAdministrator'; Kind = 'RenameBuiltin'; Name = 'Administrator'; Title = 'Accounts: Rename administrator account'; Rid = 500; Recommended = $true }
        @{ Num = 2; Id = 'RenameGuest'; Kind = 'RenameBuiltin'; Name = 'Guest'; Title = 'Accounts: Rename guest account'; Rid = 501; Recommended = $true }
        @{ Num = 3; Id = 'ForceAuditSubcategoryOverride'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Title = 'Audit: Force audit policy subcategory settings to override audit policy category settings' }
        @{ Num = 4; Id = 'CrashOnAuditFail'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'CrashOnAuditFail'; Title = 'Audit: Shut down system immediately if unable to log security audits'; Req = 'ЦПБ AU-5; Додаток 12 до Акту' }
        @{ Num = 5; Id = 'AllocateDASD'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'AllocateDASD'; Title = 'Devices: Allowed to format and eject removable media' }
        @{ Num = 6; Id = 'AddPrinterDrivers'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'; Name = 'AddPrinterDrivers'; Title = 'Devices: Prevent users from installing printer drivers' }
        @{ Num = 7; Id = 'AllocateCDRoms'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'AllocateCDRoms'; Title = 'Devices: Restrict CD-ROM access to locally logged-on user only' }
        @{ Num = 8; Id = 'AllocateFloppies'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'AllocateFloppies'; Title = 'Devices: Restrict floppy access to locally logged-on user only' }
        @{ Num = 9; Id = 'DC_SubmitControl'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SubmitControl'; Title = 'Domain controller: Allow server operators to schedule tasks'; Scope = 'DC' }
        @{ Num = 10; Id = 'DC_LDAPServerIntegrity'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LDAPServerIntegrity'; Title = 'Domain controller: LDAP server signing requirements'; Scope = 'DC' }
        @{ Num = 11; Id = 'DC_RefusePasswordChange'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RefusePasswordChange'; Title = 'Domain controller: Refuse machine account password changes'; Scope = 'DC' }
        @{ Num = 12; Id = 'DomainMember_RequireSignOrSeal'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Title = 'Domain member: Digitally encrypt or sign secure channel data (always)' }
        @{ Num = 13; Id = 'DomainMember_SealSecureChannel'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Title = 'Domain member: Digitally encrypt secure channel data (when possible)' }
        @{ Num = 14; Id = 'DomainMember_SignSecureChannel'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Title = 'Domain member: Digitally sign secure channel data (when possible)' }
        @{ Num = 15; Id = 'DomainMember_RequireStrongKey'; Kind = 'DWord'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Title = 'Domain member: Require strong (Windows 2000 or later) session key' }
        @{ Num = 16; Id = 'DontDisplayLockedUserId'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DontDisplayLockedUserId'; Title = 'Interactive logon: Display user information when the session is locked'; Req = 'ЦПБ ІА-6; Додаток 18 до Акту' }
        @{ Num = 17; Id = 'DisableCAD'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DisableCAD'; Title = 'Interactive logon: Do not require CTRL+ALT+DEL' }
        @{ Num = 18; Id = 'DontDisplayLastUserName'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DontDisplayLastUserName'; Title = 'Interactive logon: Do not display last signed-in' }
        @{ Num = 19; Id = 'InactivityTimeoutSecs'; Kind = 'DWord'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; Title = 'Interactive logon: Machine inactivity limit' }
        @{ Num = 20; Id = 'LegalNoticeText'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'legalnoticetext'; Title = 'Interactive logon: Message text for users attempting to log on'; Req = 'ЦПБ AC-8' }
        @{ Num = 21; Id = 'LegalNoticeCaption'; Kind = 'String'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'legalnoticecaption'; Title = 'Interactive logon: Message title for users attempting to log on'; Req = 'ЦПБ AC-8' }
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
        $plan = @(Get-SecurityOptionPlan $ctx | Where-Object { -not $_.Skip })
        $saved = @{ Reg = @{}; Sys = @{}; Names = @{} }
        $sys = @($plan | Where-Object { $_.Item.Kind -eq 'SystemAccess' })
        if ($sys.Count -gt 0) {
            $cur = Save-SecurityPolicySnapshot -Id $ctx.Id
            foreach ($p in $sys) {
                $n = 0L
                if ($cur.ContainsKey($p.Item.Name) -and [int64]::TryParse($cur[$p.Item.Name], [ref]$n)) { $saved.Sys[$p.Item.Name] = $n }
            }
        }
        foreach ($p in $plan) {
            if ($p.Item.Kind -eq 'RenameBuiltin') {
                $acc = Get-BuiltinAccount -Rid $p.Item.Rid
                if ($acc) { $saved.Names[$p.Item.Id] = [string]$acc.Name }
            }
            elseif ($p.Item.Kind -ne 'SystemAccess') {
                $info = Get-RegValueInfo -Path $p.Item.Path -Name $p.Item.Name
                $saved.Reg[$p.Item.Id] = @{ Exists = [bool]$info.Exists; Kind = $info.Kind; Value = $info.Value; FirstMissingKey = (Get-RegFirstMissingKey -Path $p.Item.Path) }
            }
        }
        $saved
    }

    Apply       = {
        param($ctx)
        $plan = @(Get-SecurityOptionPlan $ctx)
        $sysValues = @{}
        $done = 0
        foreach ($p in $plan) {
            if ($p.Skip) { Write-Log "[$($ctx.Id)] п. $($p.Item.Num) пропущен: $($p.SkipReason)"; continue }
            if ($p.Item.Kind -eq 'SystemAccess') { $sysValues[$p.Item.Name] = $p.Value }
            elseif ($p.Item.Kind -eq 'RenameBuiltin') { Rename-BuiltinAccount -Rid $p.Item.Rid -NewName $p.Value }
            else { Set-RegValue -Path $p.Item.Path -Name $p.Item.Name -Value $p.Value -Kind $p.Item.Kind }
            $done++
        }
        if ($sysValues.Count -gt 0) { Set-SystemAccessPolicy -Values $sysValues }
        Write-Log "Параметры безопасности применены: $done параметров" 'OK'
    }

    Verify      = {
        param($ctx)
        $plan = @(Get-SecurityOptionPlan $ctx)
        $sysCur = $null
        if (@($plan | Where-Object { -not $_.Skip -and $_.Item.Kind -eq 'SystemAccess' }).Count -gt 0) { $sysCur = Get-SystemAccessPolicy }
        foreach ($p in $plan) {
            $i = $p.Item
            $label = '{0}. {1}' -f $i.Num, $i.Title
            if ($i.ContainsKey('Req')) { $label += " [$($i.Req)]" }
            if ($p.Skip) { New-Check $label 'не застосовується' $p.SkipReason $true; continue }
            if ($i.Kind -eq 'RenameBuiltin') {
                $acc = Get-BuiltinAccount -Rid $i.Rid
                $now = if ($acc) { [string]$acc.Name } else { 'обліковий запис не знайдено' }
                New-Check $label $p.Value $now ($acc -and $now -eq $p.Value)
                continue
            }
            if ($i.Kind -eq 'SystemAccess') {
                $n = 0L
                $ok = $sysCur.ContainsKey($i.Name) -and [int64]::TryParse($sysCur[$i.Name], [ref]$n)
                $info = @{ Exists = $ok; Kind = 'SystemAccess'; Value = $n }
            }
            else { $info = Get-RegValueInfo -Path $i.Path -Name $i.Name }
            $actual = Format-OptionValue -Kind $i.Kind -Value $info.Value -Exists $info.Exists
            if ($info.Exists -and $i.Kind -ne 'SystemAccess' -and $info.Kind -ne $i.Kind) { $actual = "$actual (тип $($info.Kind))" }
            New-Check $label (Format-OptionValue -Kind $i.Kind -Value $p.Value -Exists $true) $actual (Test-OptionMatches -Item $i -Want $p.Value -Info $info)
        }
        # П. 4: зупинка системи залежить від режиму журналу безпеки (розділ 4.2): довідковий рядок.
        $crash = @($plan | Where-Object { -not $_.Skip -and $_.Item.Id -eq 'CrashOnAuditFail' -and [int64]$_.Value -ne 0 })
        if ($crash.Count -gt 0) {
            New-Check '4 (довідково). Журнал безпеки: режим зберігання і розмір' 'узгоджено з розділом 4.2' (Get-SecurityLogInfo) $true
        }
        # «Рекомендовано» без значення в профілі: інформаційний рядок (не помилка).
        foreach ($i in @($ctx.Step.Items | Where-Object { $_.Kind -eq 'RenameBuiltin' -and -not $ctx.Params.Values.ContainsKey($_.Id) })) {
            $acc = Get-BuiltinAccount -Rid $i.Rid
            New-Check ('{0}. {1}' -f $i.Num, $i.Title) 'рекомендовано (ім''я не задано в профілі)' $(if ($acc) { "поточне ім'я: $($acc.Name)" } else { 'не знайдено' }) $true
        }
    }

    Rollback    = {
        param($ctx, $backup)
        foreach ($id in @($backup.Reg.Keys)) {
            $item = @($ctx.Step.Items | Where-Object { $_.Id -eq $id })[0]
            if (-not $item) { continue }
            $b = $backup.Reg[$id]
            if ($b.Exists) { Set-RegValue -Path $item.Path -Name $item.Name -Value $b.Value -Kind $b.Kind }
            else {
                Remove-RegValue -Path $item.Path -Name $item.Name
                # ключи, созданные при записи значения (например Services\NTDS на обычной машине), убираем, если они пусты
                if ($b.ContainsKey('FirstMissingKey') -and $b.FirstMissingKey) { Remove-RegKeyIfEmpty -Path $b.FirstMissingKey }
            }
        }
        if ($backup.ContainsKey('Names')) {
            foreach ($id in @($backup.Names.Keys)) {
                $item = @($ctx.Step.Items | Where-Object { $_.Id -eq $id })[0]
                if ($item) { Rename-BuiltinAccount -Rid $item.Rid -NewName ([string]$backup.Names[$id]) }
            }
        }
        if ($backup.Sys.Count -gt 0) { Set-SystemAccessPolicy -Values $backup.Sys }
    }
}
