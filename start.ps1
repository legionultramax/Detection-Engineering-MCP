# Security Detections MCP - Startup Script
# This script configures environment variables and starts the MCP server

$ErrorActionPreference = "Stop"

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Configure detection rule paths
$env:SIGMA_PATHS = "$ScriptDir\rules\sigma\rules"
$env:SPLUNK_PATHS = "$ScriptDir\rules\splunk\detections"
$env:ELASTIC_PATHS = "$ScriptDir\rules\elastic\rules"
$env:KQL_PATHS = "$ScriptDir\rules\sentinel\Hunting Queries"
$env:STORY_PATHS = "$ScriptDir\rules\splunk\stories"

# Optional: Set custom database path (default: temp directory)
# $env:DETECTIONS_DB_PATH = "$ScriptDir\detections.db"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Security Detections MCP - Enhanced    " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Detection Sources:" -ForegroundColor Yellow
Write-Host "  Sigma:    $env:SIGMA_PATHS"
Write-Host "  Splunk:   $env:SPLUNK_PATHS"
Write-Host "  Elastic:  $env:ELASTIC_PATHS"
Write-Host "  Sentinel: $env:KQL_PATHS"
Write-Host ""
Write-Host "Starting MCP server..." -ForegroundColor Green
Write-Host ""

# Start the MCP server
node "$ScriptDir\dist\index.js"
