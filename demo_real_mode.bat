@echo off
REM Demo of the REAL pipeline on Windows using a saved OpenSCAP result (2 scans)
cd /d %~dp0
python collect_real.py --asset-name demo-server --criticality 4 --exposure public --oscap-results data\samples\oscap-results-sample.xml.gz --skip-trivy --no-epss
python collect_real.py --asset-name demo-server --criticality 4 --exposure public --oscap-results data\samples\oscap-results-sample.xml.gz --vuln-csv data\samples\vulns-example.csv --no-epss
echo.
echo Now open the dashboard (run_windows.bat) and choose "This machine (real scans)".
pause
