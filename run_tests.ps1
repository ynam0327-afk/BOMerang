
# BOMerang - Automated Python Parser Tests

$ErrorActionPreference = "Stop"

# Project paths
$root = $PSScriptRoot
$parserDir = Join-Path $root "python-parser"
$testDir = Join-Path $parserDir "test"
$reportDir = Join-Path $root "test-reports"
$summaryScript = Join-Path $root "summarize_test_results.py"

# Prepare report directory
New-Item -ItemType Directory -Path $reportDir -Force |
    Out-Null

# Validate required files
if (-not (Test-Path $testDir)) {
    throw "Test directory not found: $testDir"
}

if (-not (Test-Path $summaryScript)) {
    throw "Summary script not found: $summaryScript"
}

# Preserve original environment
$originalPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = $parserDir

try {
    Write-Host "=================================="
    Write-Host " BOMerang Automated Test Runner"
    Write-Host "=================================="

    Write-Host "[1/3] Running pytest..."

    $xmlPath = Join-Path $reportDir "pytest-results.xml"
    $logPath = Join-Path $reportDir "pytest-output.txt"

    # Run pytest and save console output
    python -m pytest $testDir -v --tb=short `
        "--junitxml=$xmlPath" 2>&1 |
        Tee-Object -FilePath $logPath

    $pytestExitCode = $LASTEXITCODE

    Write-Host "[2/3] Generating JSON summary..."

    if (Test-Path $xmlPath) {
        python $summaryScript
        $summaryExitCode = $LASTEXITCODE
    } else {
        Write-Host "[ERROR] XML report was not generated."
        exit 1
    }

    Write-Host "[3/3] Finished."
    Write-Host ""
    Write-Host "Reports saved in: $reportDir"

    if ($pytestExitCode -ne 0) {
        Write-Host "[FAIL] Some tests failed."
        exit $pytestExitCode
    }

    if ($summaryExitCode -ne 0) {
        Write-Host "[FAIL] JSON summary generation failed."
        exit $summaryExitCode
    }

    Write-Host "[PASS] All tests passed."
}
finally {
    $env:PYTHONPATH = $originalPythonPath
}
