param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('install', 'uninstall', 'status')]
    [string]$Action,
    [string]$StateDirectory,
    [string]$LinkWssUri,
    [string]$TlsIdentityP12,
    [string]$TlsPasswordFile,
    [string]$AllowedTargetsFile,
    [string]$TicketIssuer
)

$ErrorActionPreference = 'Stop'
$serviceId = 'JLShellLinkAgent'
$programRoot = Join-Path $env:ProgramFiles 'JLShell\LinkAgent'
$dataRoot = Join-Path $env:ProgramData 'JLShell\LinkAgent'
$stateRoot = Join-Path $dataRoot 'state'
$wrapperVersion = 'v2.12.0'
$wrapperUrl = "https://github.com/winsw/winsw/releases/download/$wrapperVersion/WinSW-x64.exe"
$wrapperSha256 = '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da'
$wrapperPath = Join-Path $programRoot 'JLShellLinkAgent.exe'
$wrapperXml = Join-Path $programRoot 'JLShellLinkAgent.xml'
$serviceSid = "NT SERVICE\$serviceId"

function Fail([string]$Message) { throw "JLShell Link Agent: $Message" }
function Xml([string]$Value) { [System.Security.SecurityElement]::Escape($Value) }
function Quote-Argument([string]$Value) {
    if ($Value.Contains('"')) { Fail '参数路径不能包含双引号' }
    return '"' + $Value + '"'
}
function Set-PrivateAcl([string]$Path, [string]$ServiceAccount, [string]$ServiceRights) {
    & icacls.exe $Path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" `
        "BUILTIN\Administrators:(OI)(CI)F" "${ServiceAccount}:(OI)(CI)$ServiceRights" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "无法保护目录权限: $Path" }
}
function Set-ProgramAcl([string]$Path, [string]$ServiceAccount) {
    & icacls.exe $Path /inheritance:e | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "无法保留程序目录继承权限: $Path" }
    & icacls.exe $Path /grant "${ServiceAccount}:(OI)(CI)RX" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "无法授予服务账号程序读取权限: $Path" }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail '请从管理员 PowerShell 运行。'
}

switch ($Action) {
    status {
        if (-not (Test-Path $wrapperPath)) { Fail '服务尚未安装。' }
        & $wrapperPath status
        exit $LASTEXITCODE
    }
    uninstall {
        if (Test-Path $wrapperPath) {
            & $wrapperPath stop
            & $wrapperPath uninstall
            if ($LASTEXITCODE -ne 0) { Fail '卸载 Windows Service 失败。' }
        }
        Remove-Item -Recurse -Force $programRoot -ErrorAction SilentlyContinue
        Write-Host "服务已移除；Agent 状态和身份仍保存在 $stateRoot。"
        exit 0
    }
    install {
        foreach ($required in @($StateDirectory, $LinkWssUri, $TlsIdentityP12, $TlsPasswordFile, $AllowedTargetsFile)) {
            if ([string]::IsNullOrWhiteSpace($required)) { Fail 'install 必须提供 state、WSS、TLS identity、TLS password file 和 allowed targets。' }
        }
        if ($LinkWssUri -notmatch '^wss://') { Fail 'WSS 地址必须以 wss:// 开头。' }
        if ($TicketIssuer -and $TicketIssuer -notmatch '^https://') { Fail '票据签发者必须以 https:// 开头。' }
        if (-not (Test-Path (Join-Path $StateDirectory 'agent.properties')) -or
            -not (Test-Path (Join-Path $StateDirectory 'agent.credential')) -or
            -not (Test-Path (Join-Path $StateDirectory 'node-key.ed25519'))) {
            Fail '指定状态目录尚未注册 Agent；请先以该状态目录执行 init 和 enroll。'
        }
        if (-not (Test-Path $TlsIdentityP12) -or -not (Test-Path $TlsPasswordFile) -or -not (Test-Path $AllowedTargetsFile)) {
            Fail 'TLS identity、密码文件或目标白名单不存在。'
        }
        if (Get-Service -Name $serviceId -ErrorAction SilentlyContinue) {
            Fail '服务已存在；请先执行 uninstall，再重新安装。'
        }
        $java = (Get-Command java.exe -ErrorAction Stop).Source
        New-Item -ItemType Directory -Force $programRoot, $dataRoot, $stateRoot, (Join-Path $dataRoot 'logs') | Out-Null
        Copy-Item -Force (Join-Path $PSScriptRoot '..\..\link-agent.jar') (Join-Path $programRoot 'link-agent.jar')
        Copy-Item -Recurse -Force (Join-Path $StateDirectory '*') $stateRoot
        Copy-Item -Force $TlsIdentityP12 (Join-Path $stateRoot 'agent-identity.p12')
        Copy-Item -Force $TlsPasswordFile (Join-Path $stateRoot 'tls.password')
        Copy-Item -Force $AllowedTargetsFile (Join-Path $stateRoot 'allowed-targets')

        $download = Join-Path $env:TEMP ('jlshell-winsw-' + [guid]::NewGuid().ToString('N') + '.exe')
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $wrapperUrl -OutFile $download
            $actual = (Get-FileHash -Algorithm SHA256 $download).Hash.ToLowerInvariant()
            if ($actual -ne $wrapperSha256) { Fail 'WinSW SHA-256 校验失败。' }
            Copy-Item -Force $download $wrapperPath
        }
        finally { Remove-Item -Force $download -ErrorAction SilentlyContinue }

        $startArgList = @('-jar', (Join-Path $programRoot 'link-agent.jar'), 'run',
            '--state-dir', $stateRoot,
            '--link-wss', $LinkWssUri,
            '--tls-identity-p12', (Join-Path $stateRoot 'agent-identity.p12'),
            '--tls-password-file', (Join-Path $stateRoot 'tls.password'),
            '--allowed-targets-file', (Join-Path $stateRoot 'allowed-targets'))
        if ($TicketIssuer) { $startArgList += @('--ticket-issuer', $TicketIssuer) }
        $startArguments = ($startArgList | ForEach-Object { Quote-Argument ([string]$_) }) -join ' '
        $stopArguments = @('-jar', (Join-Path $programRoot 'link-agent.jar'), 'stop',
            '--state-dir', $stateRoot) | ForEach-Object { Quote-Argument ([string]$_) }
        $javaXml = Xml $java
        $startXml = Xml $startArguments
        $stopXml = Xml ($stopArguments -join ' ')
        $logXml = Xml (Join-Path $dataRoot 'logs')
        @"
<?xml version="1.0" encoding="UTF-8"?>
<service>
  <id>$serviceId</id>
  <name>JLShell Link Agent</name>
  <description>JLShell Java Link gateway agent</description>
  <executable>$javaXml</executable>
  <startarguments>$startXml</startarguments>
  <stopexecutable>$javaXml</stopexecutable>
  <stoparguments>$stopXml</stoparguments>
  <stoptimeout>20 sec</stoptimeout>
  <workingdirectory>$(Xml $programRoot)</workingdirectory>
  <logpath>$logXml</logpath>
  <log mode="roll" />
  <hidewindow>true</hidewindow>
</service>
"@ | Set-Content -Encoding UTF8 $wrapperXml

        & $wrapperPath install
        if ($LASTEXITCODE -ne 0) { Fail 'WinSW 无法注册 Windows Service。' }
        & sc.exe sidtype $serviceId unrestricted | Out-Null
        $accountResult = & sc.exe config $serviceId "obj=$serviceSid" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Fail "无法将服务账号设置为专属虚拟服务身份：$($accountResult -join ' ')"
        }
        Set-ProgramAcl $programRoot $serviceSid
        Set-PrivateAcl $stateRoot $serviceSid 'M'
        Set-PrivateAcl (Join-Path $dataRoot 'logs') $serviceSid 'M'
        & $wrapperPath start
        if ($LASTEXITCODE -ne 0) { Fail 'Windows Service 已安装但未能启动。' }
        Write-Host "JLShell Link Agent 已安装为 Windows Service；状态目录：$stateRoot"
    }
}
