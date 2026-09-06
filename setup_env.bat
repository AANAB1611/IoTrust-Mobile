@echo off
echo ============================================
echo IoTrust Environment Setup
echo ============================================
echo.

echo Installing Python dependencies...
pip install flask flask-cors bleak pandas numpy joblib scikit-learn lightgbm

echo.
echo ============================================
echo Setup Complete!
echo ============================================
echo.
echo To run the IoTrust server:
echo   python app.py
echo.
echo Then open frontend.html in your browser.
echo.
pause
