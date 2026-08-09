$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    throw "JLShell Link 安装失败: $Message"
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'Windows 安装器必须从管理员 PowerShell 运行'
}

$websiteUrl = if ($env:JLSHELL_LINK_WEBSITE_URL) { $env:JLSHELL_LINK_WEBSITE_URL.TrimEnd('/') } else { 'https://jlshell.oomn.net' }
$root = if ($env:JLSHELL_LINK_INSTALL_ROOT) { $env:JLSHELL_LINK_INSTALL_ROOT } else { Join-Path $env:ProgramData 'JLShellLink' }
$binDir = Join-Path $root 'bin'
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("jlshell-link-" + [guid]::NewGuid().ToString('N'))
$archive = 'jlshell-link-windows-x64.tar.gz'
$archivePath = Join-Path $tempDir $archive
$checksumPath = "$archivePath.sha256"
$identity = Join-Path $root 'agent-identity.key'
$authority = Join-Path $root 'authority.pb'
$tokenFile = Join-Path $root 'enrollment.token'
$credential = Join-Path $root 'agent.credential'
$serviceName = 'JLShellLinkAgent'

New-Item -ItemType Directory -Force -Path $root, $binDir, $tempDir | Out-Null
try {
    $runtimeUrl = "$websiteUrl/api/v1/link/runtime/latest"
    Write-Host '正在下载 JLShell Link Agent (Windows x64)...'
    Invoke-WebRequest -UseBasicParsing -Uri "$runtimeUrl/$archive" -OutFile $archivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$runtimeUrl/$archive.sha256" -OutFile $checksumPath
    $expected = ((Get-Content -Raw $checksumPath).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') { Fail '下载的 SHA-256 文件无效' }
    $actual = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { Fail 'Agent 安装包 SHA-256 校验失败' }

    tar.exe -xzf $archivePath -C $tempDir
    $agent = Join-Path $tempDir 'jlshell-agent-windows-x64.exe'
    if (-not (Test-Path $agent)) { $agent = Join-Path $tempDir 'jlshell-agent.exe' }
    if (-not (Test-Path $agent)) { Fail '安装包中缺少 Windows Agent' }
    Copy-Item -Force $agent (Join-Path $binDir 'jlshell-agent.exe')
    Invoke-WebRequest -UseBasicParsing -Uri "$websiteUrl/api/v1/link/ticket-authority" -OutFile $authority

    $needsEnrollment = -not (Test-Path $credential) -or (Get-Item $credential).Length -eq 0
    if ($needsEnrollment) {
        $secureToken = Read-Host '请输入 Website 生成的一次性 Agent 注册密钥' -AsSecureString
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        try { $enrollment = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        if ([string]::IsNullOrWhiteSpace($enrollment)) { Fail '注册密钥不能为空' }
        Set-Content -Path $tokenFile -Value $enrollment -Encoding ascii -NoNewline
        $enrollment = $null
    }
    else {
        Remove-Item -Force $tokenFile -ErrorAction SilentlyContinue
        Write-Host '检测到已有 Agent 凭据，将保留现有注册信息。'
    }

    $bootstrap = Invoke-RestMethod -Uri "$websiteUrl/api/v1/link/agent/bootstrap"
    if (-not $bootstrap.relayAddress -or -not $bootstrap.relayPeer) { Fail '当前没有在线的官方 Relay，请稍后重试' }

    $agentExe = Join-Path $binDir 'jlshell-agent.exe'
    $agentArgs = @(
        '--identity', $identity,
        '--authority-public', $authority,
        '--listen', '/ip4/0.0.0.0/tcp/7001',
        '--listen', '/ip4/0.0.0.0/udp/7001/quic-v1',
        '--control-plane-url', $websiteUrl,
        '--credential-file', $credential,
        '--relay-address', [string]$bootstrap.relayAddress,
        '--relay-peer', [string]$bootstrap.relayPeer
    )
    if ($needsEnrollment) {
        $agentArgs += @('--enrollment-token-file', $tokenFile)
    }
    $quotedArgs = ($agentArgs | ForEach-Object { '"' + ([string]$_).Replace('"', '\"') + '"' }) -join ' '
    $binPath = '"' + $agentExe + '" --windows-service ' + $quotedArgs

    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    sc.exe create $serviceName binPath= $binPath start= auto DisplayName= 'JLShell Link Agent' | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail '无法创建 Windows 服务' }
    sc.exe sidtype $serviceName unrestricted | Out-Null
    sc.exe config $serviceName obj= 'NT SERVICE\JLShellLinkAgent' password= '' | Out-Null
    icacls $root /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' 'NT SERVICE\JLShellLinkAgent:(OI)(CI)M' /T | Out-Null
    Start-Service -Name $serviceName

    $attempt = 0
    while ($attempt -lt 30 -and -not (Test-Path $credential)) {
        Start-Sleep -Seconds 1
        $attempt++
    }
    if (-not (Test-Path $credential)) { Fail "Agent 未能在 30 秒内完成注册，请检查服务 $serviceName 的状态" }
    Write-Host 'JLShell Link Agent 安装并注册成功。'
    Write-Host "目录: $root"
    Write-Host '服务: JLShellLinkAgent (Windows SCM)'
    Write-Host '接下来请回到 Website，为该 Agent 添加允许访问的精确 IP 和端口。'
}
finally {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
