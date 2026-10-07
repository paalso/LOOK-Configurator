# Помощники шага security-options: разбор профиля, сравнение и отображение значений.

function Test-DomainController {
    try { $role = [int](Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole; $role -ge 4 } catch { $false }
}

function Get-BuiltinAccount {
    # Вбудована учётка по RID (500 = Administrator, 501 = Guest): имя может быть уже изменено.
    param([Parameter(Mandatory)][int]$Rid)
    Get-LocalUser | Where-Object { $_.SID.Value -match "-$Rid$" } | Select-Object -First 1
}

function Rename-BuiltinAccount {
    param([Parameter(Mandatory)][int]$Rid, [Parameter(Mandatory)][string]$NewName)
    $acc = Get-BuiltinAccount -Rid $Rid
    if (-not $acc) { throw "Вбудований обліковий запис (RID $Rid) не знайдено." }
    if ($acc.Name -ne $NewName) {
        Rename-LocalUser -Name $acc.Name -NewName $NewName
        Write-Log "Учётная запись RID $Rid переименована: '$($acc.Name)' -> '$NewName'" 'WARN'
    }
}

function Get-SecurityOptionPlan {
    # Values из профиля -> список @{ Item; Value; Skip; SkipReason } в порядке таблицы. Проверяет id и типы значений.
    param($Ctx)
    if (-not $Ctx.Params.ContainsKey('Values') -or $Ctx.Params.Values.Count -eq 0) {
        throw 'В profile.json нет steps -> security-options -> Values'
    }
    $byId = @{}
    foreach ($i in $Ctx.Step.Items) { $byId[$i.Id] = $i }
    $order = @($Ctx.Step.Items | ForEach-Object { $_.Id })
    $forceDc = $Ctx.Params.ContainsKey('ApplyDomainControllerItems') -and [bool]$Ctx.Params.ApplyDomainControllerItems
    $isDc = $null
    $otherNames = @()
    if ($Ctx.Profile.steps -and $Ctx.Profile.steps.ContainsKey('local-accounts')) {
        $otherNames = @($Ctx.Profile.steps['local-accounts'].Accounts | ForEach-Object { [string]$_.Name })
    }
    $plan = @()
    foreach ($id in $Ctx.Params.Values.Keys) {
        if (-not $byId.ContainsKey($id)) { throw "Values: неизвестный параметр '$id'. Допустимые: $(($order) -join ', ')" }
        $item = $byId[$id]
        $raw = $Ctx.Params.Values[$id]
        switch ($item.Kind) {
            { $_ -in 'DWord', 'SystemAccess' } {
                $n = 0L
                if (-not [int64]::TryParse([string]$raw, [ref]$n)) { throw "Values.$id`: ожидается целое число, указано '$raw'" }
                $v = $n
            }
            'String' {
                if ($raw -isnot [string]) { throw "Values.$id`: ожидается строка" }
                $v = $raw
            }
            'RenameBuiltin' {
                # Имя SAM-учётки: до 20 символов; латиница, цифры, . _ - и одиночные пробелы между словами (не по краям).
                if ($raw -isnot [string] -or $raw.Length -gt 20 -or $raw -notmatch '^[A-Za-z0-9._-]+( [A-Za-z0-9._-]+)*$') {
                    throw "Values.$id`: допустимое имя - до 20 символов (латиница, цифры, . _ -, пробелы между словами), указано '$raw'"
                }
                if ($otherNames -contains $raw) { throw "Values.$id`: имя '$raw' уже используется учётной записью из local-accounts." }
                $v = $raw
            }
            'MultiString' { $v = @(@($raw) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }
            default { throw "Параметр '$id': неизвестный тип $($item.Kind)" }
        }
        $skip = $false; $reason = $null
        if ($item.ContainsKey('Scope') -and $item.Scope -eq 'DC' -and -not $forceDc) {
            if ($null -eq $isDc) { $isDc = Test-DomainController }
            if (-not $isDc) { $skip = $true; $reason = 'лише для контролера домену (ApplyDomainControllerItems = false)' }
        }
        $plan += [pscustomobject]@{ Item = $item; Value = $v; Skip = $skip; SkipReason = $reason }
    }
    @($plan | Sort-Object { [array]::IndexOf($order, $_.Item.Id) })
}

function Format-OptionValue {
    param([string]$Kind, $Value, [bool]$Exists = $true)
    if (-not $Exists) { return 'не задано' }
    switch ($Kind) {
        'MultiString' { if (@($Value).Count -eq 0) { '(порожньо)' } else { @($Value) -join '; ' } }
        'String' {
            $s = [string]$Value
            if ($s.Length -gt 70) { $s.Substring(0, 67) + '...' } else { $s }
        }
        default { "$Value" }
    }
}

function Test-OptionMatches {
    param($Item, $Want, $Info)
    if (-not $Info.Exists) { return $false }
    switch ($Item.Kind) {
        'DWord'        { return ($Info.Kind -eq 'DWord' -and [int64]$Info.Value -eq [int64]$Want) }
        'SystemAccess' { return ([int64]$Info.Value -eq [int64]$Want) }
        'String'       { return ($Info.Kind -eq 'String' -and [string]$Info.Value -ceq [string]$Want) }
        'MultiString'  {
            $a = @($Info.Value | Where-Object { $null -ne $_ }); $b = @($Want | Where-Object { $null -ne $_ })
            return ($Info.Kind -eq 'MultiString' -and $a.Count -eq $b.Count -and (($a -join "`n") -ceq ($b -join "`n")))
        }
    }
    $false
}

function Get-SecurityLogInfo {
    # Справочно: режим хранения и размер журнала безопасности (от этого зависит срабатывание CrashOnAuditFail).
    try {
        $l = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
        $mode = switch ([string]$l.LogMode) {
            'Circular'   { 'з перезаписом старих подій' }
            'Retain'     { 'БЕЗ перезапису (повний журнал зупинить систему)' }
            'AutoBackup' { 'з архівуванням повного журналу' }
            default      { [string]$l.LogMode }
        }
        '{0}; розмір {1:N1} MB' -f $mode, ([double]$l.MaximumSizeInBytes / 1MB)
    }
    catch { 'не вдалося прочитати' }
}
