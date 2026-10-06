# Помощники: защита системы, лимит места под точки восстановления, создание точки без GUI.
# Работают в Windows PowerShell 5.1 (Checkpoint-Computer и т.п. в PowerShell 7 недоступны).

function Get-RestorePointSettings {
    param($Params)
    $drive = if ($Params.ContainsKey('Drive') -and $Params.Drive) { [string]$Params.Drive } elseif ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    $drive = $drive.TrimEnd('\', '/')
    if ($drive.Length -eq 1) { $drive += ':' }
    @{
        Drive            = $drive.ToUpperInvariant()
        MaxSize          = $(if ($Params.ContainsKey('MaxSize') -and $Params.MaxSize) { [string]$Params.MaxSize } else { '15GB' })
        PointName        = $(if ($Params.ContainsKey('PointName') -and $Params.PointName) { [string]$Params.PointName } else { 'Clean system' })
        AskForName       = $(if ($Params.ContainsKey('AskForName')) { [bool]$Params.AskForName } else { $true })
        MinRestorePoints = $(if ($Params.ContainsKey('MinRestorePoints')) { [int]$Params.MinRestorePoints } else { 1 })
    }
}

function Test-RestorePointConfig {
    param($Params)
    $s = Get-RestorePointSettings $Params
    if ($s.Drive -notmatch '^[A-Z]:$') { throw "Drive: ожидается буква диска вида 'C:', указано '$($s.Drive)'" }
    # Синтаксис /maxsize у vssadmin: 15GB, 20480MB, 10%, UNBOUNDED
    if ($s.MaxSize -notmatch '^(\d+(\.\d+)?%|\d+(MB|GB|TB)|UNBOUNDED)$') {
        throw "MaxSize: допустимо '15GB', '20480MB', '10%' или 'UNBOUNDED', указано '$($s.MaxSize)'"
    }
    if ($s.PointName.Trim().Length -lt 1 -or $s.PointName.Length -gt 200) { throw 'PointName: от 1 до 200 символов' }
    if ($s.MinRestorePoints -lt 1) { throw 'MinRestorePoints: минимум 1' }
}

function Get-RestoreBlockingPolicy {
    # Если политикой отключено восстановление системы, точка не создастся. Возвращает описание или $null.
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
    $v = (Get-ItemProperty -Path $path -Name 'DisableSR' -ErrorAction SilentlyContinue).DisableSR
    if ($v -eq 1) { return 'DisableSR=1' }
    $null
}

function Get-ExpectedMaxBytes {
    param([Parameter(Mandatory)][string]$MaxSize, [Parameter(Mandatory)][uint64]$Capacity)
    if ($MaxSize -match '^(\d+(?:\.\d+)?)%$') { return [uint64]([double]$Capacity * [double]$Matches[1] / 100) }
    if ($MaxSize -match '^(\d+)(MB|GB|TB)$') {
        $mult = switch ($Matches[2].ToUpperInvariant()) { 'MB' { 1MB } 'GB' { 1GB } 'TB' { 1TB } }
        return [uint64]([double]$Matches[1] * $mult)
    }
    throw "Неизвестный формат размера: $MaxSize"
}

function Test-MaxSizeMatch {
    # vssadmin округляет значения, поэтому допускаем отклонение 2% (но не менее 128 МБ).
    param([string]$MaxSize, [uint64]$Capacity, $Actual)
    if ($null -eq $Actual) { return $false }
    if ($MaxSize -ieq 'UNBOUNDED') { return [uint64]$Actual -ge $Capacity }
    $exp = Get-ExpectedMaxBytes -MaxSize $MaxSize -Capacity $Capacity
    $tol = [math]::Max(128MB, [double]$exp * 0.02)
    [math]::Abs([double]$Actual - [double]$exp) -le $tol
}

function Format-Bytes {
    param($Bytes)
    if ($null -eq $Bytes) { return 'невідомо' }
    if ([double]$Bytes -ge 4.6e18) { return 'без обмеження' }
    '{0:N1} GB' -f ([double]$Bytes / 1GB)
}

function Get-ShadowStorageInfo {
    # Лимит места под теневые копии (в т.ч. точки восстановления) для тома. Через CIM, без разбора текста vssadmin.
    param([Parameter(Mandatory)][string]$Drive)
    $vol = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='$Drive'"
    if (-not $vol) { return $null }
    $ss = Get-CimInstance -ClassName Win32_ShadowStorage | Where-Object { $_.Volume.DeviceID -eq $vol.DeviceID } | Select-Object -First 1
    [pscustomobject]@{
        Capacity = [uint64]$vol.Capacity
        Exists   = [bool]$ss
        MaxSpace = $(if ($ss) { [uint64]$ss.MaxSpace } else { $null })
        Used     = $(if ($ss) { [uint64]$ss.UsedSpace } else { $null })
    }
}

function Set-ShadowStorageLimit {
    # $true при успехе. Если связи тома с хранилищем ещё нет (до первой точки), vssadmin вернёт ошибку.
    param([Parameter(Mandatory)][string]$Drive, [Parameter(Mandatory)][string]$MaxSize)
    try {
        Invoke-Native -File 'vssadmin.exe' -Arguments @('resize', 'shadowstorage', "/for=$Drive", "/on=$Drive", "/maxsize=$MaxSize") | Out-Null
        $true
    }
    catch {
        Write-Log "vssadmin resize shadowstorage: $($_.Exception.Message)" 'WARN'
        $false
    }
}

function Get-RestorePointList {
    $raw = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
    foreach ($p in $raw) {
        $t = $p.CreationTime
        if ($t -isnot [datetime]) {
            # Формат WMI: yyyymmddHHMMSS.ffffff+UUU (локальное время)
            $t = [datetime]::ParseExact(([string]$t).Substring(0, 14), 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture)
        }
        [pscustomobject]@{ Seq = $p.SequenceNumber; Name = [string]$p.Description; Time = $t }
    }
}

function New-SystemRestorePoint {
    # Windows по умолчанию создаёт не чаще одной точки в 24 часа (Checkpoint-Computer молча ничего не делает).
    # На время создания снимаем ограничение и возвращаем прежнее значение.
    param([Parameter(Mandatory)][string]$Name, [string]$Type = 'MODIFY_SETTINGS')
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $prop = 'SystemRestorePointCreationFrequency'
    $old = (Get-ItemProperty -Path $key -Name $prop -ErrorAction SilentlyContinue).$prop
    try {
        Set-ItemProperty -Path $key -Name $prop -Value 0 -Type DWord -Force
        Checkpoint-Computer -Description $Name -RestorePointType $Type -ErrorAction Stop
    }
    finally {
        if ($null -ne $old) { Set-ItemProperty -Path $key -Name $prop -Value $old -Type DWord -Force }
        else { Remove-ItemProperty -Path $key -Name $prop -ErrorAction SilentlyContinue }
    }
}
