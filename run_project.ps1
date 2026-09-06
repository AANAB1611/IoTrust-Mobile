# IoTrust Project Runner (PowerShell)
# Checks dependencies, starts Flask server, and opens frontend

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "IoTrust Project Launcher" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if required packages are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow

$required = @("flask", "flask_cors", "bleak", "pandas", "numpy", "joblib", "sklearn", "lightgbm")
$missing = @()

foreach ($mod in $required) {
    $result = python -c "import $mod" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $missing += $mod
    }
}

if ($missing.Count -gt 0) {
    Write-Host "Missing packages detected: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    pip install flask flask-cors bleak pandas numpy joblib scikit-learn lightgbm -q
    Write-Host "Dependencies installed." -ForegroundColor Green
}

Write-Host ""
Write-Host "Starting Flask backend..." -ForegroundColor Yellow

# Start Flask in background
$flaskJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    python app.py
}

# Wait for Flask to start
Start-Sleep -Seconds 3

# Check if Flask is running
$flaskRunning = $false
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:5000/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        $flaskRunning = $true
    }
} catch {
    $flaskRunning = $false
}

if ($flaskRunning) {
    Write-Host "Flask server is running on http://127.0.0.1:5000" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Opening frontend in browser..." -ForegroundColor Yellow
    
    # Get the absolute path to frontend.html
    $frontendPath = Join-Path $PWD "frontend.html"
    
    # Open in default browser
    Start-Process $frontendPath
    
    Write-Host "Done! Frontend should open in your browser." -ForegroundColor Green
    Write-Host ""
    Write-Host "Press Ctrl+C to stop the server when done." -ForegroundColor Gray
} else {
    Write-Host "Failed to start Flask server. Check the terminal for errors." -ForegroundColor Red
}

# Keep script running to maintain Flask
Write-Host ""
Write-Host "Flask is running in background..." -ForegroundColor Cyan
Write-Host "Press any key to exit (this will stop the server)..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Stop Flask
Stop-Job -Job $flaskJob -ErrorAction SilentlyContinue
Remove-Job -Job $flaskJob -ErrorAction SilentlyContinue
