@echo off
REM Security Detections MCP - Startup Script

set SCRIPT_DIR=%~dp0

REM Configure detection rule paths
set SIGMA_PATHS=%SCRIPT_DIR%rules\sigma\rules
set SPLUNK_PATHS=%SCRIPT_DIR%rules\splunk\detections
set ELASTIC_PATHS=%SCRIPT_DIR%rules\elastic\rules
set KQL_PATHS=%SCRIPT_DIR%rules\sentinel\Hunting Queries
set STORY_PATHS=%SCRIPT_DIR%rules\splunk\stories

echo ========================================
echo  Security Detections MCP - Enhanced
echo ========================================
echo.
echo Detection Sources:
echo   Sigma:    %SIGMA_PATHS%
echo   Splunk:   %SPLUNK_PATHS%
echo   Elastic:  %ELASTIC_PATHS%
echo   Sentinel: %KQL_PATHS%
echo.
echo Starting MCP server...
echo.

node "%SCRIPT_DIR%dist\index.js"
