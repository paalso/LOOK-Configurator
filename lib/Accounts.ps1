# Помощники: локальные учётные записи, группы, личные папки и их права (NTFS).
# Группы и системные учётки определяются по SID, поэтому не зависят от языка Windows
# (Administrators = «Администраторы» и т.п.).

$Script:WellKnownSids = @{
    Administrators = 'S-1-5-32-544'
    Users          = 'S-1-5-32-545'
    System         = 'S-1-5-18'
}

function Get-GroupSidString {
    # Имя из конфига (Administrators / Users / любое имя локальной группы / сам SID) -> строка SID.
    param([Parameter(Mandatory)][string]$Name)
    if ($Script:WellKnownSids.ContainsKey($Name)) { return $Script:WellKnownSids[$Name] }
    if ($Name -match '^S-1-\d') { return $Name }
    (Get-LocalGroup -Name $Name -ErrorAction Stop).SID.Value
}

function Get-ConfiguredGroup {
    param([Parameter(Mandatory)][string]$Name)
    Get-LocalGroup -SID (Get-GroupSidString $Name) -ErrorAction Stop
}

function Test-LocalGroupMember {
    param([Parameter(Mandatory)]$Group, [Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$UserSid)
    try {
        $members = @(Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop)
        return [bool]($members | Where-Object { $_.SID.Value -eq $UserSid })
    }
    catch {
        # Get-LocalGroupMember в PS 5.1 падает на «осиротевших» SID в группе; читаем через net.exe
        $lines = Invoke-Native -File 'net.exe' -Arguments @('localgroup', $Group.Name)
        $pattern = '(^|\\)' + [regex]::Escape($UserName) + '$'
        return [bool]($lines | Where-Object { ([string]$_).Trim() -match $pattern })
    }
}

function Get-AccountPasswordNeverExpires {
    param([Parameter(Mandatory)][string]$Name)
    $acc = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='$Name'"
    if (-not $acc) { return $null }
    -not [bool]$acc.PasswordExpires
}

function Test-AccountIsAdmin {
    param([Parameter(Mandatory)][hashtable]$Account)
    $sids = @(@($Account.Groups) | ForEach-Object { Get-GroupSidString $_ })
    $sids -contains $Script:WellKnownSids.Administrators
}

function Test-AccountConfig {
    param($Params)
    if (-not $Params -or -not $Params.ContainsKey('Accounts') -or @($Params.Accounts).Count -eq 0) {
        throw "В profile.json нет списка steps -> local-accounts -> Accounts"
    }
    $root = if ($Params.ContainsKey('UsersRoot')) { [string]$Params.UsersRoot } else { 'D:\Users' }
    if ([string]::IsNullOrWhiteSpace($root)) { throw 'UsersRoot пуст' }
    $modes = @('adopt', 'skip', 'ask')
    if ($Params.ContainsKey('ExistingAccount') -and $modes -notcontains ([string]$Params.ExistingAccount).ToLowerInvariant()) {
        throw "ExistingAccount: допустимо adopt | skip | ask, указано '$($Params.ExistingAccount)'"
    }
    foreach ($a in @($Params.Accounts)) {
        if ($a.Name -notmatch '^[A-Za-z0-9._-]{1,20}$') { throw "Недопустимое имя учётной записи: '$($a.Name)'" }
        if (-not $a.ContainsKey('Groups') -or @($a.Groups).Count -eq 0) { throw "У '$($a.Name)' не указаны группы (Groups)" }
        foreach ($g in @($a.Groups)) { [void](Get-GroupSidString $g) }
        if ($a.ContainsKey('Existing') -and $a.Existing -and $modes -notcontains ([string]$a.Existing).ToLowerInvariant()) {
            throw "У '$($a.Name)': Existing допустимо adopt | skip | ask"
        }
    }
}

function Get-UsersRoot {
    param($Params)
    if ($Params.ContainsKey('UsersRoot')) { [string]$Params.UsersRoot } else { 'D:\Users' }
}

function Get-AccountFolderPath {
    param([string]$Root, [hashtable]$Account)
    $leaf = if ($Account.ContainsKey('FolderName') -and $Account.FolderName) { $Account.FolderName } else { $Account.Name }
    Join-Path $Root $leaf
}

function Test-AccountWantsFolder {
    param([hashtable]$Account)
    -not ($Account.ContainsKey('HomeFolder') -and -not [bool]$Account.HomeFolder)
}

function Get-AccountPassword {
    # Пароль из конфига; если пусто, спрашиваем интерактивно. Пароли не логируются.
    param([hashtable]$Account)
    if ($Account.ContainsKey('Password') -and -not [string]::IsNullOrEmpty([string]$Account.Password)) {
        return ConvertTo-SecureString -String ([string]$Account.Password) -AsPlainText -Force
    }
    while ($true) {
        $p1 = Read-Host "Пароль для '$($Account.Name)'" -AsSecureString
        $p2 = Read-Host 'Повторите пароль' -AsSecureString
        $a = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
        $b = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
        if ($a -and $a -ceq $b) { return $p1 }
        Write-Ui 'Пароли пусты или не совпадают, повторите.' Yellow
    }
}

function Initialize-LocalAccount {
    param([Parameter(Mandatory)][hashtable]$Account)
    $name = $Account.Name
    $never = [bool]$Account.PasswordNeverExpires
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue

    if (-not $user) {
        $p = @{
            Name                 = $name
            Password             = (Get-AccountPassword $Account)
            AccountNeverExpires  = $true
            PasswordNeverExpires = $never
        }
        if ($Account.ContainsKey('FullName') -and $Account.FullName) { $p.FullName = [string]$Account.FullName }
        if ($Account.ContainsKey('Description') -and $Account.Description) { $p.Description = [string]$Account.Description }
        New-LocalUser @p | Out-Null
        Write-Log "Создана учётная запись '$name' (PasswordNeverExpires=$never)" 'OK'
    }
    else {
        Set-LocalUser -Name $name -PasswordNeverExpires $never
        if (-not $user.Enabled) { Enable-LocalUser -Name $name }
        Write-Log "Учётная запись '$name' уже существует: пароль не менялся, параметры приведены к профилю" 'WARN'
    }

    $user = Get-LocalUser -Name $name
    foreach ($g in @($Account.Groups)) {
        $group = Get-ConfiguredGroup $g
        if (-not (Test-LocalGroupMember -Group $group -UserName $name -UserSid $user.SID.Value)) {
            Add-LocalGroupMember -Group $group.Name -Member $name
            Write-Log "'$name' добавлена в группу '$($group.Name)'"
        }
    }
}

function Format-SidName {
    param([string]$Sid)
    try { (New-Object System.Security.Principal.SecurityIdentifier $Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

function Get-PersonalFolderSids {
    # Таблица 2: Администраторы и СИСТЕМА всегда; владелец-пользователь, если он не администратор.
    param([hashtable]$Account, [string]$UserSid)
    $sids = @($Script:WellKnownSids.Administrators, $Script:WellKnownSids.System)
    if (-not (Test-AccountIsAdmin $Account)) { $sids += $UserSid }
    $sids
}

function Set-PersonalFolderAcl {
    # Отключает наследование, удаляет унаследованные и прежние записи, выдаёт «Полный доступ»
    # перечисленным SID для папки, подпапок и файлов.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$FullControlSids)
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
    foreach ($s in $FullControlSids) {
        $id = New-Object System.Security.Principal.SecurityIdentifier $s
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Test-PersonalFolderAcl {
    # Возвращает @{ Ok; Actual } — точное соответствие ожидаемому набору записей.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$ExpectedSids)
    $acl = Get-Acl -Path $Path
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inh = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $good = @(); $bad = @()
    foreach ($r in $acl.Access) {
        $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $isGood = ($r.AccessControlType -eq 'Allow') -and ($r.FileSystemRights -eq $full) -and
                  ($r.InheritanceFlags -eq $inh) -and ($r.PropagationFlags -eq 'None') -and (-not $r.IsInherited)
        if ($isGood) { $good += $sid } else { $bad += "$sid (нестандартная запись: $($r.FileSystemRights))" }
    }
    $missing = @($ExpectedSids | Where-Object { $good -notcontains $_ })
    $extra = @($good | Where-Object { $ExpectedSids -notcontains $_ })
    $ok = $acl.AreAccessRulesProtected -and $missing.Count -eq 0 -and $extra.Count -eq 0 -and $bad.Count -eq 0 -and
          (@($good | Select-Object -Unique).Count -eq $good.Count)
    $parts = @(($good | ForEach-Object { Format-SidName $_ }) | ForEach-Object { "$_ : Full" }) + $bad
    if (-not $acl.AreAccessRulesProtected) { $parts += 'наследование включено' }
    @{ Ok = $ok; Actual = ($parts -join '; ') }
}

function Restore-FolderAcl {
    # Возвращает DACL папки из SDDL, сохранённого до применения шага.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sddl)
    $acl = Get-Acl -Path $Path
    $acl.SetSecurityDescriptorSddlForm($Sddl, [System.Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -Path $Path -AclObject $acl
}

# ---------- Политика для учёток, существовавших ДО мастера ----------

function Get-ExistingPolicy {
    param($Params, [hashtable]$Account)
    $p = if ($Account.ContainsKey('Existing') -and $Account.Existing) { [string]$Account.Existing }
         elseif ($Params.ContainsKey('ExistingAccount')) { [string]$Params.ExistingAccount }
         else { 'ask' }
    $p.ToLowerInvariant()
}

function Get-AccountDecision {
    # Без вопросов. manage = учётку создаёт/ведёт мастер; adopt = существовала, приводим к профилю; skip = не трогаем.
    param($Ctx, [hashtable]$Account)
    $st = Get-StepState -Id $Ctx.Id
    $b = $null
    if ($st -and $st.ContainsKey('backup') -and $st.backup.Users.ContainsKey($Account.Name)) { $b = $st.backup.Users[$Account.Name] }
    if (-not $b -or -not $b.Existed) { return 'manage' }
    switch (Get-ExistingPolicy $Ctx.Params $Account) {
        'skip'  { return 'skip' }
        'adopt' { return 'adopt' }
        default {
            $d = Get-StepData -Id $Ctx.Id
            if ($d.ContainsKey('Decisions') -and $d.Decisions.ContainsKey($Account.Name)) { return $d.Decisions[$Account.Name] }
            return 'adopt'
        }
    }
}

function Get-ExistingAccountDiff {
    # Что именно изменит мастер у уже существующей учётки (список строк; пусто = менять нечего).
    param([hashtable]$Account, [string]$Root)
    $name = $Account.Name
    $user = Get-LocalUser -Name $name
    $lines = @()
    if (-not $user.Enabled) { $lines += 'учётная запись отключена -> будет ВКЛЮЧЕНА' }
    $fmt = { param($v) if ($null -eq $v) { 'неизвестно' } elseif ($v) { 'не истекает' } else { 'ограничен' } }
    $have = Get-AccountPasswordNeverExpires $name
    $want = [bool]$Account.PasswordNeverExpires
    if ($have -ne $want) { $lines += ("срок действия пароля: сейчас «{0}» -> будет «{1}»" -f (& $fmt $have), (& $fmt $want)) }
    foreach ($g in @($Account.Groups)) {
        $grp = Get-ConfiguredGroup $g
        if (-not (Test-LocalGroupMember -Group $grp -UserName $name -UserSid $user.SID.Value)) {
            $lines += "не входит в группу '$($grp.Name)' -> будет ДОБАВЛЕНА"
        }
    }
    if (Test-AccountWantsFolder $Account) {
        $path = Get-AccountFolderPath $Root $Account
        if (-not (Test-Path -LiteralPath $path)) { $lines += "папка '$path' будет создана" }
        else {
            $r = $null
            try { $r = Test-PersonalFolderAcl -Path $path -ExpectedSids (Get-PersonalFolderSids $Account $user.SID.Value) } catch { }
            if (-not $r -or -not $r.Ok) {
                $cur = if ($r) { $r.Actual } else { 'не удалось прочитать' }
                $lines += "права папки '$path' будут ЗАМЕНЕНЫ (сейчас: $cur); прежние права сохранятся в резервной копии"
            }
        }
    }
    $lines
}

function Resolve-AccountDecision {
    # То же, что Get-AccountDecision, но при Existing=ask спрашивает пользователя и запоминает ответ.
    param($Ctx, [hashtable]$Account, [string]$Root)
    $d = Get-AccountDecision $Ctx $Account
    if ($d -ne 'adopt' -or (Get-ExistingPolicy $Ctx.Params $Account) -ne 'ask') { return $d }
    $data = Get-StepData -Id $Ctx.Id
    if ($data.ContainsKey('Decisions') -and $data.Decisions.ContainsKey($Account.Name)) { return $data.Decisions[$Account.Name] }

    $diff = @(Get-ExistingAccountDiff -Account $Account -Root $Root)
    if ($diff.Count -eq 0) { return 'adopt' }    # менять нечего: вопрос не нужен
    Write-Ui ''
    Write-Ui "Учётная запись '$($Account.Name)' уже существует (создана не этим мастером)." Yellow
    Write-Ui 'Пароль и профиль пользователя не изменяются. Будут внесены изменения:' Yellow
    foreach ($l in $diff) { Write-Ui "  - $l" }
    $answer = Read-Choice -Prompt '1 = привести к профилю, 0 = не трогать эту учётку и её папку' -Allowed @('1', '0')
    $decision = if ($answer -eq '1') { 'adopt' } else { 'skip' }
    if (-not $data.ContainsKey('Decisions')) { $data.Decisions = @{} }
    $data.Decisions[$Account.Name] = $decision
    Set-StepData -Id $Ctx.Id -Data $data
    Write-Log "Решение по существующей учётке '$($Account.Name)': $decision"
    $decision
}
