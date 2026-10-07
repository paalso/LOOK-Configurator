# Шаг: Політика обмеженого використання програм (Software Restriction Policies), розділ 5.1, ЦПБ CM-11.
# Параметры: config\profile.json -> steps -> software-restriction.
#   Rules - правила пути (таблица правил), Enforcement - таблица 11, DesignatedFileTypes - назначенные типы файлов,
#   TrustedPublishers - довірені видавці.
# Правила пути заменяются целиком (политика авторитетна); хеш-правила и правила сертификатов не затрагиваются.
# Изменения вступают в силу для новых процессов / после повторного входа пользователя.

@{
    Id          = 'software-restriction'
    Title       = 'Політика обмеженого використання програм (SRP)'
    Reference   = 'ЦПБ CM-11; розділ 5.1, табл. 11'
    Description = 'Правила шляху, застосування (Enforcement), призначені типи файлів, довірені видавці. Застосовується до всіх користувачів, окрім локальних адміністраторів.'
    Reversible  = $true

    Backup      = {
        param($ctx)
        Get-SrpPlan $ctx | Out-Null
        $tp = Get-RegValueInfo -Path $Script:SrpTrustedKey -Name 'TrustedPublisherFlags'
        @{
            Srp             = Export-RegTree -Path $Script:SrpKey
            SrpFirstMissing = Get-RegFirstMissingKey -Path $Script:SrpKey
            Tp              = @{ Exists = [bool]$tp.Exists; Kind = $tp.Kind; Value = $tp.Value }
            TpFirstMissing  = Get-RegFirstMissingKey -Path $Script:SrpTrustedKey
        }
    }

    Apply       = {
        param($ctx)
        $plan = Get-SrpPlan $ctx
        $key = $Script:SrpKey

        # Типы файлов: берём текущий список (если есть) или список Windows по умолчанию.
        $cur = Get-RegValueInfo -Path $key -Name 'ExecutableTypes'
        $base = if ($cur.Exists -and $cur.Kind -eq 'MultiString') { @($cur.Value) } else { $Script:SrpDefaultTypes }
        $types = Get-SrpExecutableTypes -Base $base -Remove $plan.TypesRemove -Add $plan.TypesAdd

        # Старые правила пути убираем (по всем уровням), затем создаём заново.
        foreach ($lvl in @(Get-RegSubKeyNames -Path $key | Where-Object { $_ -match '^\d+$' })) { Remove-RegKeyTree -Path "$key\$lvl\Paths" }

        Set-RegValue -Path $key -Name 'DefaultLevel' -Value $plan.DefaultLevel -Kind DWord
        Set-RegValue -Path $key -Name 'TransparentEnabled' -Value $plan.Transparent -Kind DWord
        Set-RegValue -Path $key -Name 'PolicyScope' -Value $plan.PolicyScope -Kind DWord
        Set-RegValue -Path $key -Name 'AuthenticodeEnabled' -Value $plan.Authenticode -Kind DWord
        Set-RegValue -Path $key -Name 'ExecutableTypes' -Value $types -Kind MultiString
        Set-RegValue -Path $key -Name 'LastModified' -Value ((Get-Date).ToFileTimeUtc()) -Kind QWord

        foreach ($r in $plan.Rules) {
            $rk = '{0}\{1}\Paths\{{{2}}}' -f $key, $r.Level, ([guid]::NewGuid().ToString().ToUpperInvariant())
            Set-RegValue -Path $rk -Name 'ItemData' -Value $r.Path -Kind ExpandString
            Set-RegValue -Path $rk -Name 'SaferFlags' -Value 0 -Kind DWord
            Set-RegValue -Path $rk -Name 'LastModified' -Value ((Get-Date).ToFileTimeUtc()) -Kind QWord
        }
        Set-RegValue -Path $Script:SrpTrustedKey -Name 'TrustedPublisherFlags' -Value $plan.TrustedFlags -Kind DWord
        Write-Log "SRP применена: правил $($plan.Rules.Count), типов файлов $($types.Count)" 'OK'
    }

    Verify      = {
        param($ctx)
        $plan = Get-SrpPlan $ctx
        $key = $Script:SrpKey
        $dw = { param($n) $i = Get-RegValueInfo -Path $key -Name $n; if ($i.Exists -and $i.Kind -eq 'DWord') { [int]$i.Value } else { $null } }
        $show = { param($v, $map) if ($null -eq $v) { 'не задано' } elseif ($map.ContainsKey([int]$v)) { $map[[int]$v] } else { "$v" } }

        $act = & $dw 'DefaultLevel'
        New-Check 'Default security level (рівень за замовчуванням)' (Format-SrpLevel $plan.DefaultLevel) (& $show $act $Script:SrpLevelNames) ($act -eq $plan.DefaultLevel)

        $m1 = @{ 1 = 'All software files except libraries (крім DLL)'; 2 = 'All software files (усі файли)' }
        $act = & $dw 'TransparentEnabled'
        New-Check 'Enforcement 1. Apply software restriction policies to the following' (& $show $plan.Transparent $m1) (& $show $act $m1) ($act -eq $plan.Transparent)
        $m2 = @{ 0 = 'All users (усі користувачі)'; 1 = 'All users except local administrators (крім локальних адміністраторів)' }
        $act = & $dw 'PolicyScope'
        New-Check 'Enforcement 2. Apply software restriction policies to the following users' (& $show $plan.PolicyScope $m2) (& $show $act $m2) ($act -eq $plan.PolicyScope)
        $m3 = @{ 0 = 'Ignore certificate rules (ігнорувати)'; 1 = 'Enforce certificate rules (застосовувати)' }
        $act = & $dw 'AuthenticodeEnabled'
        New-Check 'Enforcement 3. When applying software restriction policies' (& $show $plan.Authenticode $m3) (& $show $act $m3) ($act -eq $plan.Authenticode)

        $t = Get-RegValueInfo -Path $key -Name 'ExecutableTypes'
        $have = if ($t.Exists -and $t.Kind -eq 'MultiString') { @($t.Value | ForEach-Object { Format-TypeName $_ }) } else { @() }
        foreach ($x in $plan.TypesRemove) { $n = Format-TypeName $x; New-Check "Designated file types: .$n" 'REMOVE (відсутній у списку)' $(if ($have -contains $n) { 'є в списку' } else { 'відсутній' }) ($have -notcontains $n) }
        foreach ($x in $plan.TypesAdd) { $n = Format-TypeName $x; New-Check "Designated file types: .$n" 'ADD (присутній у списку)' $(if ($have -contains $n) { 'є в списку' } else { 'відсутній' }) ($have -contains $n) }

        $actual = @(Get-SrpActualRules)
        $i = 0
        foreach ($r in $plan.Rules) {
            $i++
            $hit = @($actual | Where-Object { $_.Path -ieq $r.Path })
            $text = if ($hit.Count -eq 0) { 'відсутнє' } else { (@($hit | ForEach-Object { Format-SrpLevel $_.Level }) -join ' + ') }
            New-Check ("Правило {0}: {1}" -f $i, $r.Path) (Format-SrpLevel $r.Level) $text ($hit.Count -eq 1 -and $hit[0].Level -eq $r.Level)
            $reg = Test-SrpRegistryPathRule -Path $r.Path
            if ($reg -and -not $reg.Exists) {
                New-Check ("Правило {0} (довідково)" -f $i) 'значення реєстру існує' ("значення {0}\{1} відсутнє: правило ні на що не вказує" -f $reg.Key, $reg.Name) $true
            }
        }
        $extra = @($actual | Where-Object { $p = $_.Path; -not @($plan.Rules | Where-Object { $_.Path -ieq $p }) })
        New-Check 'Зайві правила шляху (яких немає в профілі)' 'немає' $(if ($extra.Count -eq 0) { 'немає' } else { (@($extra | ForEach-Object { "$($_.Path) = $(Format-SrpLevel $_.Level)" }) -join '; ') }) ($extra.Count -eq 0)

        $tf = Get-RegValueInfo -Path $Script:SrpTrustedKey -Name 'TrustedPublisherFlags'
        $dec = { param($f) if ($null -eq $f) { 'не задано' } else { $who = @('кінцеві користувачі', 'локальні адміністратори', 'адміністратори підприємства')[[int]$f -band 3]; "керують: $who; перевірка відкликання видавця: $(if ([int]$f -band 0x100) { 'так' } else { 'ні' }); часової мітки: $(if ([int]$f -band 0x200) { 'так' } else { 'ні' })" } }
        $actF = if ($tf.Exists -and $tf.Kind -eq 'DWord') { [int]$tf.Value } else { $null }
        New-Check 'Trusted Publishers (довірені видавці)' (& $dec $plan.TrustedFlags) (& $dec $actF) ($actF -eq $plan.TrustedFlags)
    }

    Rollback    = {
        param($ctx, $backup)
        Import-RegTree -Path $Script:SrpKey -Tree $backup.Srp
        if ($backup.Tp.Exists) { Set-RegValue -Path $Script:SrpTrustedKey -Name 'TrustedPublisherFlags' -Value $backup.Tp.Value -Kind $backup.Tp.Kind }
        else { Remove-RegValue -Path $Script:SrpTrustedKey -Name 'TrustedPublisherFlags' }
        foreach ($k in @($backup.SrpFirstMissing, $backup.TpFirstMissing)) { if ($k) { Remove-RegKeyIfEmpty -Path $k } }
    }
}
