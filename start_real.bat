@echo off
echo Starting SIH26145 Threat Detection Pipeline...

:: Make sure dependencies are installed (optional but helpful)
echo Checking Python dependencies...
pip install scapy scikit-learn numpy requests

echo Starting Node.js Backend/Dashboard...
start cmd /k "node local-server.js"

echo Starting Python Real-World Sensor...
echo (Note: If this throws an interface error, you may need to run this command prompt as Administrator for Scapy)
start cmd /k "python sensor.py"

echo All systems initialized. 
echo Open http://localhost:8080 in your browser!
pause
