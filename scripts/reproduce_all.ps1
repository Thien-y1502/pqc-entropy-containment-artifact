param(
    [string]$OutputDirectory = ""
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $Root "reproduced-results"
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Refusing to overwrite existing output: $OutputDirectory"
}
$Confirmation = New-Item -ItemType Directory -Path (Join-Path $OutputDirectory "confirmation")
$Performance = New-Item -ItemType Directory -Path (Join-Path $OutputDirectory "performance")

docker build -f (Join-Path $Root "docker\Dockerfile.go") -t p01-artifact-go:1.0 $Root
docker build -f (Join-Path $Root "docker\Dockerfile.rust") -t p01-artifact-rust:1.0 $Root
docker build -f (Join-Path $Root "docker\Dockerfile.liboqs") -t p01-artifact-liboqs:1.0 $Root

function Invoke-Confirmation($Image, $Name, $Phase, $Seed) {
    docker run --rm --mount "type=bind,source=$($Confirmation.FullName),target=/data" $Image `
        --output-dir "/data/$Name" --phase $Phase --pairs 8 --anchor-base 1000 --schedule-seed $Seed
}
Invoke-Confirmation "p01-artifact-go:1.0" "go124-primary" "primary" 2026102511
Invoke-Confirmation "p01-artifact-go:1.0" "go124-replay" "replay" 2026102521
Invoke-Confirmation "p01-artifact-rust:1.0" "xwing-primary" "primary" 2026102512
Invoke-Confirmation "p01-artifact-rust:1.0" "xwing-replay" "replay" 2026102522
Invoke-Confirmation "p01-artifact-liboqs:1.0" "liboqs-primary" "primary" 2026102513
Invoke-Confirmation "p01-artifact-liboqs:1.0" "liboqs-replay" "replay" 2026102523

python (Join-Path $Root "runners\verify_evidence.py") $Confirmation.FullName --output (Join-Path $Confirmation.FullName "evidence-integrity.json")
python (Join-Path $Root "runners\compare_replay.py") (Join-Path $Confirmation.FullName "go124-primary\records.jsonl") (Join-Path $Confirmation.FullName "go124-replay\records.jsonl") (Join-Path $Confirmation.FullName "go124-replay-check.json")
python (Join-Path $Root "runners\compare_replay.py") (Join-Path $Confirmation.FullName "xwing-primary\records.jsonl") (Join-Path $Confirmation.FullName "xwing-replay\records.jsonl") (Join-Path $Confirmation.FullName "xwing-replay-check.json")
python (Join-Path $Root "runners\compare_replay.py") (Join-Path $Confirmation.FullName "liboqs-primary\records.jsonl") (Join-Path $Confirmation.FullName "liboqs-replay\records.jsonl") (Join-Path $Confirmation.FullName "liboqs-replay-check.json")

function Invoke-Performance($Image, $Implementation, $Name, $Phase, $Seed, $TrialBase) {
    docker run --rm --entrypoint python --mount "type=bind,source=$($Performance.FullName),target=/data" $Image `
        /opt/p01/benchmark_runner.py --binary /opt/p01/pair-worker `
        --implementation $Implementation --contract /opt/p01/performance_contract.frozen.json `
        --output-dir "/data/$Name" --phase $Phase --blocks 40 --warmups-per-cell 2 `
        --trial-base $TrialBase --schedule-seed $Seed
}
Invoke-Performance "p01-artifact-go:1.0" "go-crypto-tls-go1.24.13" "go124-primary" "primary" 2026102601 100000
Invoke-Performance "p01-artifact-go:1.0" "go-crypto-tls-go1.24.13" "go124-replay" "replay" 2026102611 200000
Invoke-Performance "p01-artifact-rust:1.0" "rustcrypto-x-wing" "xwing-primary" "primary" 2026102602 300000
Invoke-Performance "p01-artifact-rust:1.0" "rustcrypto-x-wing" "xwing-replay" "replay" 2026102612 400000
Invoke-Performance "p01-artifact-liboqs:1.0" "liboqs-dual-pqc" "liboqs-primary" "primary" 2026102603 500000
Invoke-Performance "p01-artifact-liboqs:1.0" "liboqs-dual-pqc" "liboqs-replay" "replay" 2026102613 600000

$Analysis = Join-Path $OutputDirectory "performance-analysis"
python (Join-Path $Root "runners\analyze_performance.py") $Performance.FullName $Analysis
$checksumLines = Get-ChildItem -LiteralPath $OutputDirectory -Recurse -File |
    Where-Object Name -ne "CHECKSUMS.sha256" |
    Sort-Object FullName |
    ForEach-Object { $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(); "$hash  $($_.FullName.Substring($OutputDirectory.Length + 1).Replace('\','/'))" }
[IO.File]::WriteAllLines((Join-Path $OutputDirectory "CHECKSUMS.sha256"), $checksumLines, [Text.UTF8Encoding]::new($false))
Write-Host "Reproduction complete: $OutputDirectory"
