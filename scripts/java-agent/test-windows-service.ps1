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
$testRoot = Join-Path $env:TEMP ('jlshell-agent-service-' + [guid]::NewGuid().ToString('N'))
$sourceState = Join-Path $testRoot 'source-state'
$testRootsOwned = $false
$expectedJarCreated = $false
$fakeAgentSource = @'
import java.nio.file.Files;
import java.nio.file.Path;

public final class FakeAgent {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) throw new IllegalArgumentException("missing test action");
        Path state = null;
        for (int i = 1; i + 1 < args.length; i++) {
            if ("--state-dir".equals(args[i])) { state = Path.of(args[i + 1]); break; }
        }
        if (state == null) throw new IllegalArgumentException("missing state directory");
        Files.createDirectories(state);
        if ("run".equals(args[0])) {
            String issuer = option(args, "--ticket-issuer");
            int marker = issuer == null ? -1 : issuer.lastIndexOf("ci=");
            if (marker < 0) throw new IllegalArgumentException("missing test run identifier");
            String runId = issuer.substring(marker + 3);
            Files.writeString(state.resolve("ci-current-run-id"), runId);
            Path started = state.resolve("ci-service-started-" + runId);
            Path stop = state.resolve("ci-service-stop-requested-" + runId);
            Files.writeString(started, "running");
            while (!Files.exists(stop)) Thread.sleep(100);
            return;
        }
        if ("stop".equals(args[0])) {
            String runId = Files.readString(state.resolve("ci-current-run-id"));
            Files.writeString(state.resolve("ci-service-stop-requested-" + runId), "stopped");
            return;
        }
        throw new IllegalArgumentException("unexpected test action");
    }

    private static String option(String[] args, String name) {
        for (int i = 0; i + 1 < args.length; i++) {
            if (name.equals(args[i])) return args[i + 1];
        }
        return null;
    }
}
'@

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Install-TestService([string]$RunId) {
    New-Item -ItemType Directory -Force $programRoot | Out-Null
    $env:PATH = "$programRoot;$env:PATH"
    & pwsh -NoProfile -File $installer install -StateDirectory $sourceState `
        -LinkWssUri 'wss://127.0.0.1:1/link/v2/control' `
        -TlsIdentityP12 (Join-Path $testRoot 'agent.p12') `
        -TlsPasswordFile (Join-Path $testRoot 'tls.password') `
        -AllowedTargetsFile (Join-Path $testRoot 'allowed-targets') `
        -TicketIssuer "https://127.0.0.1:1/?ci=$RunId"
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
    Assert (-not (Test-Path $expectedJar)) 'A root link-agent.jar already exists; refusing to overwrite it.'
    Assert (-not (Test-Path $testRoot)) 'Generated Windows test directory unexpectedly already exists.'
    Assert (Test-Path $AgentJarPath) 'The built Agent JAR was not found.'
    $testRootsOwned = $true
    New-Item -ItemType Directory -Force $testRoot | Out-Null
    New-Item -ItemType Directory -Force $sourceState | Out-Null
    Set-Content -Path (Join-Path $sourceState 'agent.properties') -Value 'ci-test=true'
    Set-Content -Path (Join-Path $sourceState 'agent.credential') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $sourceState 'node-key.ed25519') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $testRoot 'agent.p12') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $testRoot 'tls.password') -Value 'ci-test-only'
    Set-Content -Path (Join-Path $testRoot 'allowed-targets') -Value '192.0.2.1:22'
    $classes = Join-Path $testRoot 'classes'
    $sourceFile = Join-Path $testRoot 'FakeAgent.java'
    $manifest = Join-Path $testRoot 'MANIFEST.MF'
    $fakeJar = Join-Path $testRoot 'link-agent-ci-test.jar'
    New-Item -ItemType Directory -Force $classes | Out-Null
    Set-Content -Path $sourceFile -Value $fakeAgentSource
    [System.IO.File]::WriteAllText($manifest, "Manifest-Version: 1.0`r`nMain-Class: FakeAgent`r`n`r`n",
        [System.Text.Encoding]::ASCII)
    & javac.exe -d $classes $sourceFile
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the isolated Java service test process.' }
    & jar.exe --create --file $fakeJar --manifest $manifest -C $classes .
    if ($LASTEXITCODE -ne 0) { throw 'Could not package the isolated Java service test process.' }
    $expectedJarCreated = $true
    Copy-Item -Force $fakeJar $expectedJar

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $attemptStarted = [DateTime]::UtcNow
        $runId = [guid]::NewGuid().ToString('N')
        Install-TestService $runId
        $startedMarker = Join-Path $stateRoot "ci-service-started-$runId"
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ((-not (Test-Path $startedMarker) -or
                (Get-Service -Name $serviceId -ErrorAction SilentlyContinue).Status -ne 'Running') -and
                [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        $serviceStatus = (Get-Service -Name $serviceId -ErrorAction SilentlyContinue).Status
        if (-not (Test-Path $startedMarker) -or $serviceStatus -ne 'Running') {
            Write-Host "Windows test service diagnostic: run marker present=$([bool](Test-Path $startedMarker)); service status=$serviceStatus."
            $logDirectory = Join-Path $dataRoot 'logs'
            if (Test-Path $logDirectory) {
                Get-ChildItem -Path $logDirectory -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Host "--- WinSW log: $($_.Name) ---"
                    Get-Content -Path $_.FullName -Tail 80 -ErrorAction SilentlyContinue
                }
            }
            Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                StartTime = $attemptStarted.AddSeconds(-5)
                Id = @(7000, 7009, 7011, 7023, 7031, 7034, 7040, 7045)
            } -MaxEvents 12 -ErrorAction SilentlyContinue |
                Format-List TimeCreated, Id, ProviderName, Message | Out-String | Write-Host
            throw "Windows service failed to start on lifecycle attempt $attempt."
        }
        & pwsh -NoProfile -File $installer status
        if ($LASTEXITCODE -ne 0) { throw "Windows service status failed on lifecycle attempt $attempt." }
        & pwsh -NoProfile -File $installer uninstall
        if ($LASTEXITCODE -ne 0) { throw "Windows service uninstall failed on lifecycle attempt $attempt." }
        Assert (-not (Get-Service -Name $serviceId -ErrorAction SilentlyContinue)) `
            "Windows service remained registered after lifecycle attempt $attempt."
        Assert (Test-Path (Join-Path $stateRoot 'agent.credential')) `
            'Uninstall removed the registered Agent state instead of preserving it.'
        Assert (Test-Path (Join-Path $stateRoot "ci-service-stop-requested-$runId")) `
            'Service uninstall did not request the Agent graceful stop command.'
        Write-Host "Windows service lifecycle attempt $attempt passed."
        if ($attempt -lt 2) {
            $removalDeadline = [DateTime]::UtcNow.AddSeconds(10)
            while ((Get-Service -Name $serviceId -ErrorAction SilentlyContinue) -and
                   [DateTime]::UtcNow -lt $removalDeadline) {
                Start-Sleep -Milliseconds 250
            }
            Assert (-not (Get-Service -Name $serviceId -ErrorAction SilentlyContinue)) `
                'Windows Service Control Manager did not finish removing the previous service.'
            # Let SCM release the deleted service identity before the reinstall cycle.
            Start-Sleep -Seconds 5
        }
    }
}
finally {
    if ($testRootsOwned) {
        if (Get-Service -Name $serviceId -ErrorAction SilentlyContinue) {
            & pwsh -NoProfile -File $installer uninstall
        }
        Remove-Item -Recurse -Force $programRoot, $dataRoot -ErrorAction SilentlyContinue
    }
    if ($expectedJarCreated) { Remove-Item -Force $expectedJar -ErrorAction SilentlyContinue }
    if ($testRootsOwned) { Remove-Item -Recurse -Force $testRoot -ErrorAction SilentlyContinue }
}
