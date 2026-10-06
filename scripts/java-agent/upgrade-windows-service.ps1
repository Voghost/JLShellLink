param(
    [Parameter(Mandatory=$true)][string]$StateDirectory,
    [Parameter(Mandatory=$true)][string]$LinkWssUri,
    [Parameter(Mandatory=$true)][string]$TlsIdentityP12,
    [Parameter(Mandatory=$true)][string]$TlsPasswordFile,
    [Parameter(Mandatory=$true)][string]$AllowedTargetsFile,
    [Parameter(Mandatory=$true)][string]$Manifest,
    [string]$TicketIssuer
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '请使用管理员 SSH 会话安装 Windows 服务。' }
$serviceId = 'JLShellLinkAgent'
$root = Join-Path $env:ProgramFiles 'JLShell\LinkAgent'
$parent = Split-Path -Parent $root
New-Item -ItemType Directory -Force $parent | Out-Null
$lockPath = Join-Path $parent '.link-agent-upgrade.lock'
$lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$backup = Join-Path $parent ('LinkAgent-backup-' + [guid]::NewGuid().ToString('N'))
$wrapper = Join-Path $root 'JLShellLinkAgent.exe'
$existing = Get-Service -Name $serviceId -ErrorAction SilentlyContinue
$wasRunning = $null -ne $existing -and $existing.Status -eq 'Running'
$hadProgram = Test-Path -LiteralPath $root
$mutated = $false
$success = $false
try {
    $package = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $java = Join-Path $package 'runtime\bin\java.exe'
    if ($null -ne $existing) { $StateDirectory = Join-Path $env:ProgramData 'JLShell\LinkAgent\state' }
    $arguments = @('-jar', (Join-Path $package 'link-agent.jar'), 'diagnose', '--state-dir', $StateDirectory,
        '--link-wss', $LinkWssUri, '--tls-identity-p12', $TlsIdentityP12, '--tls-password-file', $TlsPasswordFile,
        '--allowed-targets-file', $AllowedTargetsFile)
    & $java @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Agent 安装前诊断失败。' }
    if ($hadProgram) { Copy-Item -LiteralPath $root -Destination $backup -Recurse }
    $mutated = $true
    if ($null -ne $existing) {
        if ($wasRunning) { Stop-Service -Name $serviceId; $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
        & $wrapper uninstall | Out-Null
        if ($LASTEXITCODE -ne 0) { throw '旧 Agent 服务注销失败。' }
    }
    if ($hadProgram) { Remove-Item -LiteralPath $root -Recurse -Force }
    & (Join-Path $PSScriptRoot 'install-windows-service.ps1') -Action install -StateDirectory $StateDirectory `
        -LinkWssUri $LinkWssUri -TlsIdentityP12 $TlsIdentityP12 -TlsPasswordFile $TlsPasswordFile `
        -AllowedTargetsFile $AllowedTargetsFile -TicketIssuer $TicketIssuer
    Start-Sleep -Seconds 2
    if ((Get-Service -Name $serviceId).Status -ne 'Running') { throw '新 Agent 服务未保持运行。' }
    Copy-Item -LiteralPath $Manifest -Destination (Join-Path $root 'release.manifest.json')
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $Manifest) 'release.signature.json') `
        -Destination (Join-Path $root 'release.signature.json')
    $success = $true
    Write-Host 'Java Agent 服务已安装并通过进程检查；请核对 Website 在线状态。'
}
catch {
    if ($mutated) {
        $newService = Get-Service -Name $serviceId -ErrorAction SilentlyContinue
        if ($null -ne $newService) {
            if ($newService.Status -ne 'Stopped') { Stop-Service -Name $serviceId -Force }
            & $wrapper uninstall | Out-Null
            if ($LASTEXITCODE -ne 0) { throw '安装失败且新服务注销失败；保留备份以便手动恢复。' }
        }
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        if ($hadProgram) { Move-Item -LiteralPath $backup -Destination $root }
        if ($null -ne $existing) {
            & $wrapper install | Out-Null
            if ($LASTEXITCODE -ne 0) { throw '文件已恢复，但旧服务重新注册失败。' }
            & sc.exe sidtype $serviceId unrestricted | Out-Null
            if ($LASTEXITCODE -ne 0) { throw '旧服务 SID 恢复失败。' }
            & sc.exe config $serviceId "obj=NT SERVICE\$serviceId" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw '旧服务专属账号恢复失败。' }
            if ($wasRunning) { Start-Service -Name $serviceId }
        }
    }
    throw 'Java Agent 安装失败；已尝试恢复上一版本，请核对服务状态。'
}
finally {
    if ($success -and (Test-Path -LiteralPath $backup)) { Remove-Item -LiteralPath $backup -Recurse -Force }
    $lock.Dispose()
    Remove-Item -LiteralPath $lockPath -ErrorAction SilentlyContinue
}
