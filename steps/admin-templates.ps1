# Шаг: Адміністративні шаблони комп'ютера (таблиця 13): AutoPlay, Camera, NetMeeting, OneDrive, Online Assistance,
# Windows Mobility Center, Windows Messenger, Windows Installer.
# Параметры: config\profile.json -> steps -> admin-templates -> States (Id = Enabled | Disabled | NotConfigured).
# Значения пишутся в Registry.pol локального GPO (lib\LocalGpo.ps1) и применяются gpupdate: в gpedit.msc видно «Включено/Відключено».

@{
    Id          = 'admin-templates'
    Title       = "Адміністративні шаблони комп'ютера (таблиця 13)"
    Reference   = 'Розділ 5, таблиця 13'
    Description = "Локальний GPO (Конфігурація комп'ютера - Адміністративні шаблони): AutoPlay, Camera, NetMeeting, OneDrive, Online Assistance, Mobility Center, Windows Messenger, Windows Installer."
    Reversible  = $true

    # Id, номер (пункт таблиці 13), назва політики, шлях у gpedit, ключ/ім'я реєстру, значення для «Увімкнено» (On) і «Вимкнено» (Off; $null = запис **del.).
    Items       = @(
        @{ Id = 'autoplay-off'; Num = '1.1'; Title = 'Turn off Autoplay (Enabled: All drives)'; Path = 'Windows Components\AutoPlay Policies'
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; On = 255; Off = $null }
        @{ Id = 'autorun-default'; Num = '1.2'; Title = 'Set the default behavior for AutoRun (Enabled: Do not execute any autorun commands)'; Path = 'Windows Components\AutoPlay Policies'
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; On = 1; Off = $null }
        @{ Id = 'camera-allow'; Num = '2'; Title = 'Allow Use of Camera'; Path = 'Windows Components\Camera'
            Key = 'SOFTWARE\Policies\Microsoft\Camera'; Name = 'AllowCamera'; On = 1; Off = 0 }
        @{ Id = 'netmeeting-rds'; Num = '3'; Title = 'Disable remote Desktop Sharing'; Path = 'Windows Components\NetMeeting'
            Key = 'SOFTWARE\Policies\Microsoft\Conferencing'; Name = 'NoRDS'; On = 1; Off = $null }
        @{ Id = 'onedrive-block'; Num = '4'; Title = 'Prevent the usage of OneDrive for file storage'; Path = 'Windows Components\OneDrive'
            Key = 'SOFTWARE\Policies\Microsoft\Windows\OneDrive'; Name = 'DisableFileSyncNGSC'; On = 1; Off = $null }
        @{ Id = 'online-assistance'; Num = '5'; Title = 'Turn off Active Help'; Path = 'Windows Components\Online Assistance'
            Key = 'SOFTWARE\Policies\Microsoft\Assistance\Client\1.0'; Name = 'NoActiveHelp'; On = 1; Off = $null }
        @{ Id = 'mobility-center'; Num = '6'; Title = 'Turn off Windows Mobility Center'; Path = 'Windows Components\Windows Mobility Center'
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter'; Name = 'NoMobilityCenter'; On = 1; Off = $null }
        @{ Id = 'messenger-noautostart'; Num = '7.1'; Title = 'Do not automatically start Windows Messenger initially'; Path = 'Windows Components\Windows Messenger'
            Key = 'SOFTWARE\Policies\Microsoft\Messenger\Client'; Name = 'PreventAutoRun'; On = 1; Off = $null }
        @{ Id = 'messenger-norun'; Num = '7.2'; Title = 'Do not allow Windows Messenger to be run'; Path = 'Windows Components\Windows Messenger'
            Key = 'SOFTWARE\Policies\Microsoft\Messenger\Client'; Name = 'PreventRun'; On = 1; Off = $null }
        @{ Id = 'installer-rollback'; Num = '8.1'; Title = 'Prohibit rollback'; Path = 'Windows Components\Windows Installer'
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'DisableRollback'; On = 1; Off = 0 }
        @{ Id = 'installer-restorepoint'; Num = '8.2'; Title = 'Turn off creation of System Restore checkpoints'; Path = 'Windows Components\Windows Installer'
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'LimitSystemRestoreCheckpointing'; On = 1; Off = 0 }
    )

    Backup      = {
        param($ctx)
        $gp = Get-LocalGpoPaths
        $b = @{ PolExists = (Test-Path -LiteralPath $gp.Pol); IniExists = (Test-Path -LiteralPath $gp.Ini); Registry = @{} }
        if ($b.PolExists) { $b.Pol = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($gp.Pol)) }
        if ($b.IniExists) { $b.Ini = [System.IO.File]::ReadAllText($gp.Ini, [System.Text.Encoding]::Default) }
        foreach ($it in $ctx.Step.Items) {
            $i = Get-RegValueInfo -Path ('HKLM:\' + $it.Key) -Name $it.Name
            $b.Registry[$it.Id] = @{ Exists = $i.Exists; Kind = $i.Kind; Value = $i.Value; KeyMissing = (Get-RegFirstMissingKey ('HKLM:\' + $it.Key)) }
        }
        $b
    }

    Apply       = {
        param($ctx)
        $plan = Get-AdminTemplatePlan $ctx
        $gp = Get-LocalGpoPaths
        $entries = Read-PRegFile -Path $gp.Pol
        foreach ($p in $plan) {
            $it = $p.Item
            switch ($p.Expected.Kind) {
                'Value' { Set-PRegDword $entries $it.Key $it.Name $p.Expected.Value }
                'Delete' { Set-PRegDelete $entries $it.Key $it.Name }
                default { Remove-PRegEntries $entries $it.Key $it.Name }
            }
        }
        Write-PRegFile -Path $gp.Pol -Entries $entries
        $ver = Update-LocalGpoIni -Path $gp.Ini
        Write-Log "Локальний GPO: Registry.pol записано ($($entries.Count) записів), gpt.ini Version=$ver" 'OK'

        $null = Invoke-GroupPolicyRefresh

        # Если gpupdate недоступен или не перенёс значение, приводим реестр в соответствие напрямую (политика всё равно останется в LGPO).
        foreach ($p in $plan) {
            $it = $p.Item
            $act = Get-AdminTemplateRegState $it
            if (Test-RegStateMatchesExpected $p.Expected $act) { continue }
            $path = 'HKLM:\' + $it.Key
            if ($p.Expected.Kind -eq 'Value') { Set-RegValue -Path $path -Name $it.Name -Value $p.Expected.Value -Kind DWord }
            else { Remove-RegValue -Path $path -Name $it.Name }
            Write-Log "$($it.Num) '$($it.Title)': gpupdate не змінив реєстр, значення записано напряму" 'WARN'
        }
    }

    Verify      = {
        param($ctx)
        $plan = Get-AdminTemplatePlan $ctx
        $gp = Get-LocalGpoPaths
        $entries = Read-PRegFile -Path $gp.Pol
        foreach ($p in $plan) {
            $it = $p.Item
            $pol = Get-PRegState $entries $it.Key $it.Name
            $reg = Get-AdminTemplateRegState $it
            $ok = (Test-PolStateMatches $p.Expected $pol) -and (Test-RegStateMatchesExpected $p.Expected $reg)
            $exp = "$($p.State): Registry.pol $(Format-PolExpected $p.Expected); реєстр " + $(if ($p.Expected.Kind -eq 'Value') { "$($p.Expected.Value)" } else { 'значення немає' })
            $act = "Registry.pol $(Format-PolState $pol); реєстр " + $(if ($reg.Kind -eq 'None') { 'значення немає' } else { "$($reg.Value)" })
            New-Check "П.$($it.Num) $($it.Title) [$($it.Path)]" $exp $act $ok
        }
        $ini = Get-LocalGpoIniInfo -Path $gp.Ini
        $iniOk = $ini.Exists -and $ini.MachineVersion -ge 1 -and $ini.HasRegistryCse
        New-Check 'gpt.ini локального GPO (видно в gpedit.msc)' 'є, Version > 0, розширення Registry підключене' ("Exists=$($ini.Exists); Version=$($ini.Version); Registry CSE=$($ini.HasRegistryCse)") $iniOk
    }

    Rollback    = {
        param($ctx, $backup)
        $gp = Get-LocalGpoPaths
        if ($backup.PolExists) {
            [System.IO.File]::WriteAllBytes($gp.Pol, [Convert]::FromBase64String([string]$backup.Pol))
        }
        elseif (Test-Path -LiteralPath $gp.Pol) { Remove-Item -LiteralPath $gp.Pol -Force }

        if ($backup.IniExists) {
            [System.IO.File]::WriteAllText($gp.Ini, [string]$backup.Ini, [System.Text.Encoding]::Default)
            $null = Update-LocalGpoIni -Path $gp.Ini      # версия растёт, чтобы клиент заметил откат
        }
        elseif (Test-Path -LiteralPath $gp.Ini) { Remove-Item -LiteralPath $gp.Ini -Force }

        $null = Invoke-GroupPolicyRefresh

        # Реестр возвращаем к исходному состоянию независимо от результата gpupdate.
        foreach ($it in $ctx.Step.Items) {
            $o = $backup.Registry[$it.Id]
            if (-not $o) { continue }
            $path = 'HKLM:\' + $it.Key
            if ($o.Exists) { Set-RegValue -Path $path -Name $it.Name -Value $o.Value -Kind ([string]$o.Kind) }
            else {
                Remove-RegValue -Path $path -Name $it.Name
                if ($o.KeyMissing) { Remove-RegKeyIfEmpty $o.KeyMissing }
            }
        }
    }
}
