# IoTrust Environment Setup (PowerShell)
# Run this script to install all required dependencies

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "IoTrust Environment Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$packages = @("flask", "flask-cors", "bleak", "pandas", "numpy", "joblib", "scikit-learn", "lightgbm")

Write-Host "Installing Python dependencies..." -ForegroundColor Yellow

foreach ($pkg in $packages) {
    Write-Host "  Installing $pkg..." -NoNewline
    pip install $pkg -q
    Write-Host " Done" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run the IoTrust server:" -ForegroundColor White
Write-Host "  python app.py" -ForegroundColor Gray
Write-Host ""
Write-Host "Or use: .\run_project.ps1" -ForegroundColor Gray
Write-Host ""
