@echo off

rem In case you place `guest.py` in any place other than the `C:`
rem drive, modify the variable below
set FLASK_APP=C:\guest.py

python -m flask run --host=0.0.0.0
