# ZeroPhish — Staging Operations Manual

## Daily Operations & Workload Execution
Run controlled staging workload runs:
```powershell
# 1. Verify Configuration
python -u -m Backend.ml.data.pipeline external-staging-config-check

# 2. Check Live Connectivity
python -u -m Backend.ml.data.pipeline external-staging-check

# 3. Execute 100-request Verification Run
python -u -m Backend.ml.data.pipeline external-staging-shadow --count 100 --rate 10 --max-runtime 60
```

## Stopping Staging
```powershell
.\scripts\staging-down.ps1
```
