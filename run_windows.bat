@echo off
REM One-click: install libraries, run experiment (first time only), open dashboard
cd /d %~dp0
python -m pip install -r requirements.txt
if not exist data\simulation.db python run_experiment.py
python -m streamlit run app.py
