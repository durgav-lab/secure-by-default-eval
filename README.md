# Evaluation code for "Secure-by-Default Service Templates for Financial Microservices"

Prototype of the field-aware redaction stage (JDK only, Java 17+) and the scripts behind Section VI.

| Experiment | Class / script | Output |
|---|---|---|
| E1 detection on Gretel financial documents | `EvalDetection` | `results_e1.csv`, `results_e1_precision.csv` |
| E2 false positives on Loghub logs | `EvalDetection` | `results_e2.csv` |
| E3 text-level vs field-aware JSON redaction | `EvalStructure` + `check_e3.py` | `results_e3.csv` |
| E4 backtracking on adversarial input | `EvalPerf` | `results_e4.csv` |
| E5 latency of the pattern stage | `EvalPerf` | `results_e5.csv` |

## Run

1. Put the two dataset files in `./data` (see the docstring of `prepare_data.py` for sources).
2. `python3 prepare_data.py`
3. `./run_all.sh` (Java 17+ and Python 3)
4. `python3 plot_fig3.py` (needs matplotlib) to redraw Fig. 3.

`results/` holds the outputs reported in the paper. Timing results depend on the machine.

## Datasets and licences

- Gretel.ai, `synthetic_pii_finance_multilingual` (Apache-2.0), English rows of the test split.
- Loghub 2k samples of 16 systems (logpai/loghub); cite Zhu et al., ISSRE 2023.
