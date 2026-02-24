# =============================================================================
# Security Detections MCP — Company Machine Setup Script
# =============================================================================
# Run this script on your new company machine to set up the MCP server.
# Prerequisites: Node.js 18+, npm, git
#
# Usage:
#   .\setup-company.ps1
# =============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Security Detections MCP — Setup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Verify prerequisites
# ---------------------------------------------------------------------------
Write-Host "[1/7] Checking prerequisites..." -ForegroundColor Yellow

$nodeVersion = & node --version 2>$null
if (-not $nodeVersion) {
    Write-Host "  ERROR: Node.js not found. Install from https://nodejs.org/" -ForegroundColor Red
    exit 1
}
Write-Host "  Node.js: $nodeVersion" -ForegroundColor Green

$npmVersion = & npm --version 2>$null
if (-not $npmVersion) {
    Write-Host "  ERROR: npm not found." -ForegroundColor Red
    exit 1
}
Write-Host "  npm: $npmVersion" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 2: Install dependencies
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/7] Installing npm dependencies..." -ForegroundColor Yellow
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: npm install failed." -ForegroundColor Red
    exit 1
}
Write-Host "  Dependencies installed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 3: Build TypeScript
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/7] Building TypeScript..." -ForegroundColor Yellow
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Build failed." -ForegroundColor Red
    exit 1
}
Write-Host "  Build complete." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 4: Set up data directory
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[4/7] Setting up data directory..." -ForegroundColor Yellow

if (-not (Test-Path ".\data")) {
    New-Item -ItemType Directory -Path ".\data" | Out-Null
    Write-Host "  Created data/ directory." -ForegroundColor Green
}

if (Test-Path ".\data\detections.db") {
    $dbSize = (Get-Item ".\data\detections.db").Length / 1MB
    Write-Host "  Database found: $([math]::Round($dbSize, 1)) MB" -ForegroundColor Green
} else {
    Write-Host "  WARNING: No database found at data\detections.db" -ForegroundColor Yellow
    Write-Host "  The database will be created on first run + indexing." -ForegroundColor Yellow
    Write-Host "  To restore from backup, copy detections.db to data\ before running." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 5: Check environment variables
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[5/7] Checking environment variables..." -ForegroundColor Yellow

$envFile = ".\.env"
$envExampleFile = ".\.env.example"

if (Test-Path $envFile) {
    Write-Host "  .env file found." -ForegroundColor Green
} else {
    Write-Host "  No .env file found. Creating from .env.example..." -ForegroundColor Yellow
    if (Test-Path $envExampleFile) {
        Copy-Item $envExampleFile $envFile
        Write-Host "  Created .env from .env.example." -ForegroundColor Green
        Write-Host "  IMPORTANT: Edit .env and add your API keys!" -ForegroundColor Red
    } else {
        Write-Host "  WARNING: No .env.example found. Set env vars manually." -ForegroundColor Yellow
    }
}

# Check critical env vars
$criticalVars = @(
    @{Name="DETECTIONS_DB_PATH"; Desc="Database path"},
    @{Name="OTX_API_KEY"; Desc="AlienVault OTX"},
    @{Name="MALPEDIA_API_KEY"; Desc="Malpedia"},
    @{Name="NVD_API_KEY"; Desc="NIST NVD"}
)

foreach ($var in $criticalVars) {
    $val = [Environment]::GetEnvironmentVariable($var.Name)
    if ($val) {
        Write-Host "  $($var.Name): SET" -ForegroundColor Green
    } else {
        Write-Host "  $($var.Name): NOT SET ($($var.Desc))" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 6: Check detection rule paths
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[6/7] Checking detection rule repositories..." -ForegroundColor Yellow

$rulePaths = @(
    @{Name="Sigma"; Path=".\rules\sigma"},
    @{Name="Splunk ESCU"; Path=".\rules\splunk"},
    @{Name="Elastic"; Path=".\rules\elastic"},
    @{Name="Sentinel/KQL"; Path=".\rules\sentinel"}
)

foreach ($rp in $rulePaths) {
    if (Test-Path $rp.Path) {
        $count = (Get-ChildItem -Path $rp.Path -Recurse -File | Measure-Object).Count
        Write-Host "  $($rp.Name): $count files" -ForegroundColor Green
    } else {
        Write-Host "  $($rp.Name): NOT FOUND at $($rp.Path)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 7: Verify setup
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[7/7] Running verification..." -ForegroundColor Yellow

# Quick test: try to load the built module
$testResult = & node -e "const m = require('./dist/index.js'); console.log('Module loaded OK');" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Module loads successfully." -ForegroundColor Green
} else {
    Write-Host "  WARNING: Module failed to load. Check build output." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Edit .env and add your API keys (OTX, Malpedia, NVD)" -ForegroundColor White
Write-Host "  2. Set DETECTIONS_DB_PATH=./data/detections.db in .env" -ForegroundColor White
Write-Host "  3. Copy detections.db backup to data/ (if restoring)" -ForegroundColor White
Write-Host "  4. Run: npm run index  (to rebuild detection index)" -ForegroundColor White
Write-Host "  5. Configure Claude Desktop to use this MCP server" -ForegroundColor White
Write-Host ""
Write-Host "Claude Desktop config (claude_desktop_config.json):" -ForegroundColor Yellow
Write-Host '  {' -ForegroundColor Gray
Write-Host '    "mcpServers": {' -ForegroundColor Gray
Write-Host '      "security-detections": {' -ForegroundColor Gray
Write-Host '        "command": "node",' -ForegroundColor Gray
Write-Host '        "args": ["<PATH_TO_PROJECT>/dist/index.js"],' -ForegroundColor Gray
Write-Host '        "env": {' -ForegroundColor Gray
Write-Host '          "DETECTIONS_DB_PATH": "<PATH_TO_PROJECT>/data/detections.db",' -ForegroundColor Gray
Write-Host '          "OTX_API_KEY": "<your_key>",' -ForegroundColor Gray
Write-Host '          "MALPEDIA_API_KEY": "<your_key>",' -ForegroundColor Gray
Write-Host '          "NVD_API_KEY": "<your_key>"' -ForegroundColor Gray
Write-Host '        }' -ForegroundColor Gray
Write-Host '      }' -ForegroundColor Gray
Write-Host '    }' -ForegroundColor Gray
Write-Host '  }' -ForegroundColor Gray
Write-Host ""
