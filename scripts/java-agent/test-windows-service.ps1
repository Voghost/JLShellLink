param(
    [Parameter(Mandatory = $true)]
    [string]$AgentJarPath
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') {
    throw 'This privileged lifecycle test is restricted to a disposable GitHub Actions runner.'
}

$serviceId = 'JLShellLinkAgent'
$programRoot = Join-Path $env:ProgramFiles 'JLShell\LinkAgent'
$dataRoot = Join-Path $env:ProgramData 'JLShell\LinkAgent'
$stateRoot = Join-Path $dataRoot 'state'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$installer = Join-Path $PSScriptRoot 'install-windows-service.ps1'
$expectedJar = Join-Path $repoRoot 'link-agent.jar'
$expectedJarExisted = Test-Path $expectedJar
$testRoot = Join-Path $env:TEMP ('jlshell-agent-service-' + [guid]::NewGuid().ToString('N'))
$sourceState = Join-Path $testRoot 'source-state'
$fakeJavaSource = @'
using System;
using System.IO;
using System.Threading;
public static class FakeJava {
    public static int Main(string[] args) {
        string state = null;
        for (int i = 0; i + 1 < args.Length; i++) {
            if (args[i] == "--state-dir") { state = args[i + 1]; break; }
        }
        if (state == null) return 2;
        if (Array.IndexOf(args, "run") >= 0) {
            Directory.CreateDirectory(state);
            File.WriteAllText(Path.Combine(state, "ci-service-started"), "running");
            string stop = Path.Combine(state, "ci-service-stop-requested");
            while (!File.Exists(stop)) Thread.Sleep(100);
            return 0;
        }
        if (Array.IndexOf(args, "stop") >= 0) {
            File.WriteAllText(Path.Combine(state, "ci-service-stop-requested"), "stopped");
            return 0;
        }
        return 2;
    }
}
'@

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Install-TestService {
    New-Item -ItemType Directory -Force $programRoot | Out-Null
    Add-Type -TypeDefinition $fakeJavaSource -OutputType ConsoleApplication `
        -OutputAssembly (Join-Path $programRoot 'java.exe')
    $env:PATH = "$programRoot;$env:PATH"
    & pwsh -NoProfile -File $installer install -StateDirectory $sourceState `
        -LinkWssUri 'wss://127.0.0.1:1/link/v2/control' `
        -TlsIdentityP12 (Join-Path $testRoot 'agent.p12') `
        -TlsPasswordFile (Join-Path $testRoot 'tls.password') `
        -AllowedTargetsFile (Join-Path $testRoot 'allowed-targets') `
        -TicketIssuer 'https://127.0.0.1:1'
    if ($LASTEXITCODE -ne 0) { throw 'Windows service installer returned a failure exit code.' }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    Assert $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) `
        'Windows service lifecycle test requires the disposable runner administrator.'
    Assert ($env:ProgramFiles -and $env:ProgramData) 'Expected Windows service directories are unavailable.'
    Assert (-not (Get-Service -Name $serviceId -ErrorAction SilentlyContinue)) `
        'A JLShellLinkAgent service already exists on this runner.'
    Assert (-not (Test-Path $programRoot) -and -not (Test-Path $dataRoot)) `
        'JLShell service data already exists on this runner.'
    Assert (Test-Path $AgentJarPath) 'The built Agent JAR was not found.'
    New-Item -ItemType Directory -Force $sourceState | Out-Null
    Set-Content -Path (Join-Path $sourceState 'agent.properties') -Value 'ci-test=true'
    Set-Content -Path (Join-Path $sourceState 'agent.credential') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $sourceState 'node-key.ed25519') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $testRoot 'agent.p12') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $testRoot 'tls.password') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $testRoot 'allowed-targets') -Value '192.0.2.1:22'
    Copy-Item -Force $AgentJarPath $expectedJar

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Remove-Item -Force -Path @(
            (Join-Path $stateRoot 'ci-service-started'),
            (Join-Path $stateRoot 'ci-service-stop-requested')
        ) -ErrorAction SilentlyContinue
        Install-TestService
        $startedMarker = Join-Path $stateRoot 'ci-service-started'
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path $startedMarker) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        Assert (Test-Path $startedMarker) "Windows service failed to start on lifecycle attempt $attempt."
        & pwsh -NoProfile -File $installer status
        if ($LASTEXITCODE -ne 0) { throw "Windows service status failed on lifecycle attempt $attempt." }
        & pwsh -NoProfile -File $installer uninstall
        if ($LASTEXITCODE -ne 0) { throw "Windows service uninstall failed on lifecycle attempt $attempt." }
        Assert (-not (Get-Service -Name $serviceId -ErrorAction SilentlyContinue)) `
            "Windows service remained registered after lifecycle attempt $attempt."
        Assert (Test-Path (Join-Path $stateRoot 'agent.credential')) `
            'Uninstall removed the registered Agent state instead of preserving it.'
        Assert (Test-Path (Join-Path $stateRoot 'ci-service-stop-requested')) `
            'Service uninstall did not request the Agent graceful stop command.'
        Write-Host "Windows service lifecycle attempt $attempt passed."
    }
}
finally {
    if (Get-Service -Name $serviceId -ErrorAction SilentlyContinue) {
        & pwsh -NoProfile -File $installer uninstall
    }
    if (-not $expectedJarExisted) { Remove-Item -Force $expectedJar -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $programRoot, $dataRoot, $testRoot -ErrorAction SilentlyContinue
}
