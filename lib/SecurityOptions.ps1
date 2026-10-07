# Помощники шага security-options: разбор профиля, сравнение и отображение значений.

function Get-SecurityOptionPlan {
    # Values из профиля -> список @{ Item; Value } в порядке таблицы. Проверяет id и типы значений.
    param($Ctx)
    if (-not $Ctx.Params.ContainsKey('Values') -or $Ctx.Params.Values.Count -eq 0) {
        throw 'В profile.json нет steps -> security-options -> Values'
    }
    $byId = @{}
    foreach ($i in $Ctx.Step.Items) { $byId[$i.Id] = $i }
    $order = @($Ctx.Step.Items | ForEach-Object { $_.Id })
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
            'MultiString' { $v = @(@($raw) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }
            default { throw "Параметр '$id': неизвестный тип $($item.Kind)" }
        }
        $plan += [pscustomobject]@{ Item = $item; Value = $v }
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
