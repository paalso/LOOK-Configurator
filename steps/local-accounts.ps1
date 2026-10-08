# Шаг: окремі облікові записи адміністраторів та користувачів + особисті папки (ЦПБ AC-5).
# Данные (список учёток, корень папок, политика для существующих) берутся из
# config\profile.json -> steps -> local-accounts.

@{
    Id          = 'local-accounts'
    Title       = 'Облікові записи адміністраторів і користувачів, особисті папки'
    Reference   = 'ЦПБ AC-5; розділи 2.1-2.2, табл. 2'
    Description = 'Створення облікових записів із профілю, членство в групах, каталог профілів на тому ж диску (RelocateProfiles; D:\Users\<ім''я> створює сама Windows при першому вході). Без RelocateProfiles - окрема особиста папка з правами за табл. 2. Існуючі облікові записи обробляються за політикою ExistingAccount.'
    Reversible  = $true

    Backup      = {
        param($ctx)
        Test-AccountConfig $ctx.Params
        $root = Get-UsersRoot $ctx.Params
        $saved = @{ Users = @{}; Folders = @{}; RootExisted = [bool](Test-Path -LiteralPath $root) }
        if (Test-ProfileRelocation $ctx.Params) { $saved.Profiles = Get-ProfilesDirectoryBackup $root }
        foreach ($a in @($ctx.Params.Accounts)) {
            $u = Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue
            if ($u) {
                $inGroups = @()
                foreach ($g in @($a.Groups)) {
                    $grp = Get-ConfiguredGroup $g
                    if (Test-LocalGroupMember -Group $grp -UserName $a.Name -UserSid $u.SID.Value) { $inGroups += $grp.SID.Value }
                }
                $saved.Users[$a.Name] = @{
                    Existed              = $true
                    PasswordNeverExpires = (Get-AccountPasswordNeverExpires $a.Name)
                    Enabled              = [bool]$u.Enabled
                    Groups               = @($inGroups)
                }
            }
            else { $saved.Users[$a.Name] = @{ Existed = $false } }

            $path = Get-AccountFolderPath $root $a
            $exists = [bool](Test-Path -LiteralPath $path)
            $sddl = $null
            if ($exists) { try { $sddl = (Get-Acl -Path $path).GetSecurityDescriptorSddlForm('Access') } catch { $sddl = $null } }
            $saved.Folders[$a.Name] = @{ Existed = $exists; Sddl = $sddl }
        }
        $saved
    }

    Apply       = {
        param($ctx)
        Test-AccountConfig $ctx.Params
        $root = Get-UsersRoot $ctx.Params
        $drive = [System.IO.Path]::GetPathRoot($root)
        if (-not (Test-Path -LiteralPath $drive)) {
            throw "Диск '$drive' не знайдено. Спочатку розподіліть дисковий простір (розділ 1.6)."
        }
        if (-not (Test-Path -LiteralPath $root)) {
            New-Item -ItemType Directory -Path $root | Out-Null
            Write-Log "Создана корневая папка '$root'"
        }
        if (Test-ProfileRelocation $ctx.Params) { Set-ProfilesRoot -Root $root }
        foreach ($a in @($ctx.Params.Accounts)) {
            $decision = Resolve-AccountDecision -Ctx $ctx -Account $a -Root $root
            if ($decision -eq 'skip') {
                Write-Ui "'$($a.Name)': существовала до мастера, пропущена (учётка и папка не изменяются)." Yellow
                Write-Log "'$($a.Name)': пропущена (существовала до мастера)" 'WARN'
                continue
            }
            Initialize-LocalAccount -Account $a
            if (Test-AccountWantsFolder $a) {
                if (Test-ProfileRelocation $ctx.Params) {
                    # Профіль (саму папку D:\Users\<ім'я> і права на неї) створює Windows при першому вході.
                    # Мастер тут нічого не створює і не чіпає: саме спроба підготувати цю папку заздалегідь
                    # ламала вхід (тимчасовий профіль TEMP). Verify лише повідомляє про стан.
                }
                else {
                    $path = Get-AccountFolderPath $root $a
                    $sid = (Get-LocalUser -Name $a.Name).SID.Value
                    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
                    Set-PersonalFolderAcl -Path $path -FullControlSids (Get-PersonalFolderSids $a $sid)
                    Write-Log "Папка '$path': права установлены"
                }
            }
        }
    }

    Verify      = {
        param($ctx)
        Test-AccountConfig $ctx.Params
        $root = Get-UsersRoot $ctx.Params
        if (Test-ProfileRelocation $ctx.Params) {
            $pd = Get-RegValueInfo -Path $Script:ProfileListKey -Name 'ProfilesDirectory'
            New-Check 'Каталог профілів (ProfileList\ProfilesDirectory)' $root $(if ($pd.Exists) { [string]$pd.Value } else { 'не задано' }) ($pd.Exists -and (Test-SamePath ([string]$pd.Value) $root))
            $df = Get-RegValueInfo -Path $Script:ProfileListKey -Name 'Default'
            $dfPath = Join-Path $root 'Default'
            $dfOk = $df.Exists -and (Test-SamePath ([string]$df.Value) $dfPath) -and (Test-Path -LiteralPath (Join-Path $dfPath 'NTUSER.DAT') -PathType Leaf)
            New-Check 'Шаблон нового профілю (ProfileList\Default)' "$dfPath (з NTUSER.DAT)" $(if ($df.Exists) { [string]$df.Value } else { 'не задано' }) $dfOk
        }
        foreach ($a in @($ctx.Params.Accounts)) {
            $n = $a.Name
            if ((Get-AccountDecision $ctx $a) -eq 'skip') {
                New-Check "$n`: обліковий запис" 'існувала до мастера' 'пропущена за політикою (не перевіряється)' $true
                continue
            }
            $user = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
            if (-not $user) {
                New-Check "$n`: обліковий запис" 'існує, увімкнений' 'не знайдено' $false
                continue
            }
            New-Check "$n`: обліковий запис" 'існує, увімкнений' $(if ($user.Enabled) { 'існує, увімкнений' } else { 'вимкнений' }) ([bool]$user.Enabled)

            $want = [bool]$a.PasswordNeverExpires
            $have = Get-AccountPasswordNeverExpires $n
            $fmt = { param($v) if ($null -eq $v) { 'невідомо' } elseif ($v) { 'не закінчується' } else { 'обмежений' } }
            New-Check "$n`: термін дії пароля" (& $fmt $want) (& $fmt $have) ($have -eq $want)

            $names = @(); $okGroups = $true
            foreach ($g in @($a.Groups)) {
                $grp = Get-ConfiguredGroup $g
                if (Test-LocalGroupMember -Group $grp -UserName $n -UserSid $user.SID.Value) { $names += $g } else { $okGroups = $false }
            }
            New-Check "$n`: групи" (@($a.Groups) -join ', ') $(if ($names) { $names -join ', ' } else { 'немає' }) $okGroups

            if (Test-AccountWantsFolder $a) {
                $path = Get-AccountFolderPath $root $a
                if (Test-ProfileRelocation $ctx.Params) {
                    # Мастер папку не створює - вона з'явиться після першого входу користувача. Поки входу не було,
                    # це не помилка (довідково); якщо профіль вже зареєстрований, звіряємо лише шлях (чи справді на D:).
                    $reg = Get-RegisteredProfilePath $user.SID.Value
                    if (-not $reg) {
                        New-Check "$n`: профіль користувача (довідково)" $path 'ще не виконано вхід: Windows створить профіль автоматично' $true
                    }
                    else {
                        New-Check "$n`: профіль користувача" $path $reg (Test-SamePath $reg $path)
                    }
                }
                elseif (-not (Test-Path -LiteralPath $path)) {
                    New-Check "$n`: папка $path" 'існує' 'не знайдено' $false
                }
                else {
                    $expected = @(Get-PersonalFolderSids $a $user.SID.Value)
                    $r = Test-PersonalFolderAcl -Path $path -ExpectedSids $expected
                    $expText = (($expected | ForEach-Object { Format-SidName $_ }) | ForEach-Object { "$_ : Full" }) -join '; '
                    New-Check "$n`: права на $path" "$expText (без успадкування)" $r.Actual $r.Ok
                }
            }
        }
    }

    Rollback    = {
        param($ctx, $backup)
        $root = Get-UsersRoot $ctx.Params
        foreach ($a in @($ctx.Params.Accounts)) {
            if ((Get-AccountDecision $ctx $a) -eq 'skip') { continue }   # эту учётку мастер не трогал
            $b = $backup.Users[$a.Name]
            if (-not $b) { continue }
            $user = Get-LocalUser -Name $a.Name -ErrorAction SilentlyContinue
            if ($user) {
                if (-not $b.Existed) {
                    if ($backup.Profiles) {
                        $regPath = Get-RegisteredProfilePath $user.SID.Value
                        if ($regPath -and (Confirm-Action "Видалити профіль '$regPath' облікового запису '$($a.Name)' разом з даними?")) {
                            if (Remove-UserProfile -Sid $user.SID.Value) { Write-Log "Відкат: профіль '$regPath' видалено" 'WARN' }
                            else { Write-Ui "Профіль '$regPath' видалити не вдалося: залишено." Yellow }
                        }
                    }
                    Remove-LocalUser -Name $a.Name
                    Write-Log "Откат: удалена учётная запись '$($a.Name)'" 'WARN'
                }
                else {
                    if ($null -ne $b.PasswordNeverExpires) { Set-LocalUser -Name $a.Name -PasswordNeverExpires ([bool]$b.PasswordNeverExpires) }
                    if ($b.Enabled -eq $false -and $user.Enabled) { Disable-LocalUser -Name $a.Name }
                    foreach ($g in @($a.Groups)) {
                        $grp = Get-ConfiguredGroup $g
                        $was = @($b.Groups) -contains $grp.SID.Value
                        if (-not $was -and (Test-LocalGroupMember -Group $grp -UserName $a.Name -UserSid $user.SID.Value)) {
                            Remove-LocalGroupMember -Group $grp.Name -Member $a.Name
                        }
                    }
                }
            }

            # Папка. Старый формат резервной копии хранил просто bool.
            $f = $backup.Folders[$a.Name]
            $existed = if ($f -is [hashtable]) { [bool]$f.Existed } else { [bool]$f }
            $path = Get-AccountFolderPath $root $a
            if (-not (Test-Path -LiteralPath $path)) { continue }
            if ($existed) {
                if ($f -is [hashtable] -and $f.Sddl) {
                    Restore-FolderAcl -Path $path -Sddl $f.Sddl
                    Write-Log "Откат: права папки '$path' восстановлены из резервной копии" 'WARN'
                }
                else { Write-Ui "Папка '$path' существовала, но её прежние права не сохранены: оставлены как есть." Yellow }
            }
            else {
                # Создана этим шагом: удаляем только пустую (данные не трогаем).
                if (@(Get-ChildItem -LiteralPath $path -Force).Count -eq 0) { Remove-Item -LiteralPath $path -Force }
                else { Write-Ui "Папка '$path' не пуста: оставлена (права не откатываются)." Yellow }
            }
        }
        if ($backup.Profiles) { Restore-ProfilesRoot -Backup $backup.Profiles -Root $root }
        if (-not $backup.RootExisted -and (Test-Path -LiteralPath $root) -and @(Get-ChildItem -LiteralPath $root -Force).Count -eq 0) {
            Remove-Item -LiteralPath $root -Force
        }
    }
}
