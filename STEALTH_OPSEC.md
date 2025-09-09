ATT&CK: T1608.001, T1589.002, T1078.003
- Self-healing: If lockfile is missing, auto-generate and commit (no human needed).
- OPSEC: All actions randomized, lockfile/update blends with normal workflow.
- Security: npm audit + secret scan; artifacts staged for exfil if needed.
- Infra: Can rotate runner on failure, add infra jitter for C2.
- No placeholders—every step is operational, not theoretical.