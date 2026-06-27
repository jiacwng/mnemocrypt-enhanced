# Data directory

This repository is configured **without** shipping training binaries, malware samples, or large pre-built datasets in Git.


## What you need locally
- **Executables** for training and/or evaluation: place them under paths expected by `common/building_wrapper.sh` (see project README), or adjust those paths.
- **Pre-trained model** (`trained_mnemocrypt.pkl`): obtain from the project release or train yourself with `training/train_mnemocrypt.py` after generating feature CSVs.
- Optional **password-protected** `data.zip` for testing


