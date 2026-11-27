#!/bin/sh
# Reproduces all results: E1/E2 detection, E3 structure, E4 backtracking, E5 latency.
set -e
javac -d out Redactor.java EvalDetection.java EvalStructure.java EvalPerf.java
java -cp out EvalDetection
java -cp out EvalStructure
python3 check_e3.py
java -cp out EvalPerf
