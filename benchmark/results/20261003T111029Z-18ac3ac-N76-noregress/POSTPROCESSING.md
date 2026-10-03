# Post-processing

Raw `run*/*.jsonl` (coordinator, nginx, per-pod storm results) and `run*/*.cpu-signer*.txt` (1 Hz signer CPU samples) gzipped; signer audit and journal logs were written gzipped by the driver. The summary regenerated from the gzipped files is identical in every table.
