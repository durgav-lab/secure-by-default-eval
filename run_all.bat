@echo off
rem Windows version of run_all.sh: runs experiments E1-E5 from this folder.
setlocal
cd /d "%~dp0"

echo [1/5] Compiling the Java prototype...
javac -encoding UTF-8 -d out Redactor.java EvalDetection.java EvalStructure.java EvalPerf.java || goto :err

echo [2/5] E1 and E2: detection on Gretel documents and Loghub logs...
java -Dfile.encoding=UTF-8 -cp out EvalDetection || goto :err

echo [3/5] E3: building JSON audit events...
java -Dfile.encoding=UTF-8 -cp out EvalStructure || goto :err

echo [4/5] E3: checking JSON validity and trace IDs...
python check_e3.py || goto :err

echo [5/5] E4 and E5: backtracking and latency (takes a few minutes)...
java -Dfile.encoding=UTF-8 -cp out EvalPerf || goto :err

echo.
echo All experiments finished. Results: results_e1.csv ... results_e5.csv in this folder.
goto :eof

:err
echo.
echo A step failed. See the message above.
exit /b 1
