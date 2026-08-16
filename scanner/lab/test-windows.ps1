[CmdletBinding()]
param(
    [string]$ScannerPath,
    [string]$DockerPath
)

$ErrorActionPreference = 'Stop'
$labDirectory = $PSScriptRoot
$scannerDirectory = Split-Path -Parent $labDirectory
$artifactDirectory = Join-Path $labDirectory 'artifacts'
$composeFile = Join-Path $labDirectory 'compose.yml'
$windowsComposeFile = Join-Path $labDirectory 'compose.windows.yml'
$projectName = "otserver-scanner-lab-windows-$PID"

if (-not $DockerPath) {
    $dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($dockerCommand) {
        $DockerPath = $dockerCommand.Source
    } else {
        $DockerPath = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'
    }
}
if (-not (Test-Path -LiteralPath $DockerPath -PathType Leaf)) {
    throw 'Docker Desktop docker.exe was not found. Start Docker Desktop or pass -DockerPath.'
}

$dockerBin = Split-Path -Parent $DockerPath
$env:PATH = "$dockerBin;$env:PATH"

if (-not $ScannerPath) {
    $ScannerPath = Join-Path $scannerDirectory 'target\release\otserver-scanner.exe'
}
if (-not (Test-Path -LiteralPath $ScannerPath -PathType Leaf)) {
    Write-Host 'Building the Windows scanner...'
    Push-Location $scannerDirectory
    try {
        & cargo build --locked --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE." }
    } finally {
        Pop-Location
    }
}
$ScannerPath = (Resolve-Path -LiteralPath $ScannerPath).Path

$adapterCandidates = Get-NetAdapter -ErrorAction Stop | Where-Object {
    $_.Status -eq 'Up' -and
    ($_.InterfaceDescription -like '*Hyper-V Virtual Ethernet Adapter*' -or $_.Name -like 'vEthernet*')
}
$labAdapter = $null
$labAddress = $null
foreach ($candidate in $adapterCandidates) {
    $address = Get-NetIPAddress -InterfaceIndex $candidate.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
        Select-Object -First 1
    if ($address) {
        $labAdapter = $candidate
        $labAddress = $address.IPAddress
        break
    }
}
if (-not $labAdapter -or -not $labAddress) {
    throw 'No active Docker/WSL Hyper-V virtual Ethernet adapter with an IPv4 address was found.'
}

$sourceMac = $labAdapter.MacAddress.Replace('-', ':').ToUpperInvariant()
$interfaceGuid = $labAdapter.InterfaceGuid.ToString().Trim('{', '}').ToUpperInvariant()
$interfaceId = "{$interfaceGuid}"
$env:OTSERVER_LAB_BIND_IP = $labAddress
$env:OTSERVER_LAB_SNMP_COMMUNITY = 'lab-public'
New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
$runId = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$outputPath = Join-Path $env:TEMP "otserver-windows-protocol-smoke-$runId.otserver.json"
$logPath = Join-Path $artifactDirectory "windows-compose-$runId.log"
$summaryPath = Join-Path $artifactDirectory "windows-protocol-smoke-$runId.txt"
$composeArguments = @(
    'compose', '-p', $projectName,
    '-f', $composeFile,
    '-f', $windowsComposeFile
)
$services = @('siemens', 'ethernet_ip', 'bacnet', 'fins', 'fox', 'opcua')

Write-Host "Windows lab adapter: $($labAdapter.Name) ($interfaceId), $labAddress, $sourceMac"
Write-Host 'This is a host-routed protocol smoke test. Docker responders share the host adapter MAC.'
Write-Host 'PROFINET DCP is excluded: Docker Desktop does not bridge raw Ethernet DCP frames to Windows.'

try {
    & $DockerPath @composeArguments up --build --wait @services
    if ($LASTEXITCODE -ne 0) { throw "Docker lab startup failed with exit code $LASTEXITCODE." }

    & $ScannerPath scan `
        --target $labAddress `
        --interface $interfaceId `
        --source-mac $sourceMac `
        --snmp-config (Join-Path $labDirectory 'snmp-v2c.json') `
        --no-profinet `
        --output $outputPath `
        --ack-authorized
    if ($LASTEXITCODE -ne 0) { throw "Windows scanner failed with exit code $LASTEXITCODE." }

    & $ScannerPath validate $outputPath
    if ($LASTEXITCODE -ne 0) { throw "Scanner output validation failed with exit code $LASTEXITCODE." }

    $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
    if ($result.format -ne 'otserver-scan' -or $result.schemaVersion -ne 2) {
        throw 'The Windows scan did not produce the otserver-scan v2 contract.'
    }
    if ($result.devices.Count -ne 1) {
        throw "Expected one host-routed lab identity, found $($result.devices.Count)."
    }
    if ($result.devices[0].macAddress -ne $sourceMac) {
        throw 'The host-routed lab identity did not use the selected Hyper-V adapter MAC.'
    }
    $sources = @($result.devices[0].observations | ForEach-Object { $_.source })
    $expectedSources = @('arp', 's7', 'ethernet-ip', 'bacnet', 'omron-fins', 'niagara-fox', 'opc-ua', 'snmp')
    $missingSources = @($expectedSources | Where-Object { $_ -notin $sources })
    if ($missingSources.Count -gt 0) {
        throw "Windows lab is missing observations: $($missingSources -join ', ')."
    }
    if (@($result.links | Where-Object { $_.source -eq 'lldp' }).Count -eq 0) {
        throw 'Windows lab did not produce the expected LLDP link.'
    }

    @(
        'OTserver Scanner Windows Docker protocol smoke test passed.'
        "Windows adapter: $($labAdapter.Name)"
        "Adapter address: $labAddress"
        "Adapter MAC: $sourceMac"
        "Observed protocols: $($sources -join ', ')"
        'The temporary scan represented one Docker host endpoint and was deleted; do not import it as asset data.'
        'PROFINET DCP and distinct device MAC correlation were not tested.'
    ) | Out-File -LiteralPath $summaryPath -Encoding utf8
    Write-Host "OTserver Scanner Windows Docker protocol smoke test passed. Summary: $summaryPath"
} finally {
    try {
        & $DockerPath @composeArguments logs --no-color |
            Out-File -LiteralPath $logPath -Encoding utf8
    } catch {
        Write-Warning "Could not retain Docker lab logs: $($_.Exception.Message)"
    }
    $cleanupErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $DockerPath @composeArguments down --volumes --remove-orphans | Out-Null
    $ErrorActionPreference = $cleanupErrorPreference
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Force
    }
}
