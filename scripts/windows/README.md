# Windows runner scripts

Double-click or run these from any working directory. Each script changes to the **repository root** first, then invokes Git Bash or Python.

| Script | Action |
|--------|--------|
| `run_databases.bat` | Build IDA databases (tool / evaluation set) |
| `run_features.bat` | Compute feature CSVs (tool set) |
| `run_mnemocrypt.bat` | Batch Mnemocrypt predictions |
| `run_findcrypt.bat` | Batch Findcrypt (needs `findcrypt3` in IDA plugins) |
| `run_databases_training.bat` | Build IDA databases (training set) |
| `run_features_training.bat` | Compute feature CSVs (training set) |
| `run_training_databases_then_features.bat` | Both training steps in sequence |
| `run_train.bat` | Retrain random forest → `common/trained_mnemocrypt.pkl` |

**Prerequisite:** set `IDAT_PATH` to your `idat.exe` (or edit `common/building_wrapper.sh`).
