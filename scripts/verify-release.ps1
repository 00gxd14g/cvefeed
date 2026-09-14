<#
.SYNOPSIS
    The release gate, for Windows PowerShell. Mirrors scripts/verify-release.sh.

.DESCRIPTION
    Hosted CI minutes are a billing relationship, and whether this code is fit
    to publish must not depend on one. Everything here runs on a developer
    machine.

    Docker is needed for two things only — a disposable database and the image
    build — so -PostgresDsn together with -SkipImage removes the dependency.

.EXAMPLE
    .\scripts\verify-release.ps1

.EXAMPLE
    .\scripts\verify-release.ps1 -PostgresDsn 'postgres://cvefeed:test@127.0.0.1:5432/cvefeed?sslmode=disable' -SkipImage
#>
[CmdletBinding()]
param(
    [int]$PostgresPort = 55432,
    # A PostgreSQL you already run. It is used as it is: not created, not
    # migrated, not removed. The integration tests build and drop their own
    # schema objects, so it must be a database you are willing to have written to.
    [string]$PostgresDsn,
    [switch]$SkipAnalyzers,
    [switch]$SkipImage,
    [switch]$KeepPostgres
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root

$Container = 'cvefeed-verify-postgres'
$UsingSuppliedDatabase = -not [string]::IsNullOrWhiteSpace($PostgresDsn)
$Dsn = if ($UsingSuppliedDatabase) { $PostgresDsn } else { "postgres://cvefeed:test@127.0.0.1:$PostgresPort/cvefeed?sslmode=disable" }
$StartedPostgres = $false

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments = @())
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required"
    }
}

function Assert-Docker {
    param([Parameter(Mandatory)][string]$Because)
    Assert-Command docker
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) { throw "Docker daemon is not reachable; $Because" }
}

Assert-Command go

try {
    if ($UsingSuppliedDatabase) {
        Write-Host '==> Using the PostgreSQL named by -PostgresDsn'
    }
    else {
        Assert-Docker -Because 'or pass -PostgresDsn to use a PostgreSQL you already run'

        & docker rm -f $Container *> $null

        Write-Host "==> Starting PostgreSQL 16 on 127.0.0.1:$PostgresPort"
        Invoke-Checked docker @(
            'run', '-d', '--rm', '--name', $Container,
            '-e', 'POSTGRES_USER=cvefeed',
            '-e', 'POSTGRES_PASSWORD=test',
            '-e', 'POSTGRES_DB=cvefeed',
            '-p', "127.0.0.1:$PostgresPort`:5432",
            'docker.io/library/postgres:16-alpine'
        )
        $StartedPostgres = $true

        $ready = $false
        for ($i = 0; $i -lt 60; $i++) {
            & docker exec $Container pg_isready -U cvefeed -d cvefeed *> $null
            if ($LASTEXITCODE -eq 0) {
                $ready = $true
                break
            }
            Start-Sleep -Seconds 1
        }
        if (-not $ready) {
            throw 'PostgreSQL did not become ready within 60 seconds'
        }
    }

    if (-not $SkipImage) {
        Assert-Docker -Because 'pass -SkipImage to skip the image build'
    }

    Write-Host '==> Checking formatting'
    $unformatted = & gofmt -l .
    if ($LASTEXITCODE -ne 0) { throw 'gofmt failed' }
    if ($unformatted) {
        $unformatted | ForEach-Object { Write-Error $_ }
        throw 'gofmt changes are required'
    }

    Write-Host '==> Running go vet'
    Invoke-Checked go @('vet', './...')

    # One invocation covers every tier the gate can reach: the hermetic unit
    # tests, the database-backed integration tests (enabled by the variable
    # below), and the seed corpus of each Fuzz target.
    Write-Host '==> Running race-enabled unit and PostgreSQL integration tests'
    $env:CVEFEED_TEST_DATABASE_URL = $Dsn
    Invoke-Checked go @('test', '-race', '-count=1', './...')

    Write-Host '==> Building release binary'
    New-Item -ItemType Directory -Force -Path bin | Out-Null
    $env:CGO_ENABLED = '0'
    Invoke-Checked go @('build', '-trimpath', '-o', 'bin/cvefeed.exe', './cmd/cvefeed')

    Write-Host '==> Checking cross-platform compilation'
    New-Item -ItemType Directory -Force -Path .verify-build | Out-Null
    foreach ($target in @(
        @{ OS = 'linux';   Output = '.verify-build/cvefeed-linux-amd64' },
        @{ OS = 'windows'; Output = '.verify-build/cvefeed-windows-amd64.exe' },
        @{ OS = 'darwin';  Output = '.verify-build/cvefeed-darwin-amd64' }
    )) {
        $env:GOOS = $target.OS
        $env:GOARCH = 'amd64'
        Invoke-Checked go @('build', '-trimpath', '-o', $target.Output, './cmd/cvefeed')
    }
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force .verify-build

    if (-not $SkipAnalyzers) {
        # Both analysers are pinned. @latest made every run depend on whatever
        # was published that morning. Bump them deliberately, with the toolchain.
        Write-Host '==> Running pinned staticcheck'
        Invoke-Checked go @('run', 'honnef.co/go/tools/cmd/staticcheck@v0.8.1', './...')

        # The tool is pinned; the vulnerability database it consults is not,
        # which is the point. Not reaching that database is a different outcome
        # from a clean run, and saying so is the difference between "no known
        # vulnerable dependency" and "nobody asked".
        Write-Host '==> Running pinned govulncheck against the current vulnerability database'
        $vulnOutput = & go run 'golang.org/x/vuln/cmd/govulncheck@v1.7.0' './...' 2>&1
        $vulnExit = $LASTEXITCODE
        $vulnOutput | ForEach-Object { Write-Host $_ }
        if ($vulnExit -ne 0) {
            $joined = ($vulnOutput | Out-String)
            if ($joined -match '(?i)fetching vulnerabilities|vuln\.go\.dev|no such host|connection refused|forbidden|timeout') {
                throw 'govulncheck could not reach the vulnerability database; this run proves nothing about dependency vulnerabilities. Restore network access, or re-run with -SkipAnalyzers and record that the check was not performed.'
            }
            throw 'govulncheck reported findings'
        }
    }

    if (-not $SkipImage) {
        Write-Host '==> Building the runtime image'
        $vendored = if (Test-Path 'vendor/modules.txt') { '1' } else { '0' }
        Invoke-Checked docker @(
            'build', '-f', 'deploy/Dockerfile',
            '--build-arg', 'VERSION=local-verify',
            '--build-arg', "VENDORED=$vendored",
            '-t', 'cvefeed:local-verify', '.'
        )
    }

    Write-Host ''
    Write-Host 'Release verification passed.'
    if ($UsingSuppliedDatabase) {
        Write-Host 'PostgreSQL integration: PASS (supplied database)'
    }
    else {
        Write-Host 'PostgreSQL integration: PASS'
    }
    Write-Host 'go test -race:          PASS'
    Write-Host 'go vet/gofmt:           PASS'
    Write-Host 'cross-platform build:   PASS'
    if (-not $SkipAnalyzers) { Write-Host 'staticcheck/govulncheck: PASS' } else { Write-Host 'staticcheck/govulncheck: NOT RUN' }
    if (-not $SkipImage) { Write-Host 'Docker image:            PASS' } else { Write-Host 'Docker image:            NOT RUN' }
}
finally {
    Remove-Item Env:CVEFEED_TEST_DATABASE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    if ($StartedPostgres -and -not $KeepPostgres) {
        & docker rm -f $Container *> $null
    }
}
