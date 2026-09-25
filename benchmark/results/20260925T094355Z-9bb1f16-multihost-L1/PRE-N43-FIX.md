# pre-N43-fix

The results in this directory were measured **before** the N43/N46 fix (signer
cancellation checks, admission control, hedged fan-out). They are kept exactly as
produced; no file here except this label was changed afterwards.

Labels: preliminary: arm64, multi-VM on one overloaded 16 GB host; not for publication.
Row labels `L<N>ms` name the configured netem delay only. The measured RTT (taken
before each delay setting, host idle) is in `rtt-L*.json` and is 32–45 ms higher
than configured (NOTES N45). Post-fix results, side by side with these:
see the newer `*-multihost-L1` directory's `summary.md`.
