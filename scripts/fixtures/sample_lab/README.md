# Sample lab log fixture

Small, safe excerpt of real (not synthetic) SIEM/NDR output used to
smoke-test [scripts/ingest_local_logs.py](../../ingest_local_logs.py)
end-to-end against the live stack without requiring an external dataset.

- `security/sample_ossec-alerts-01.json` — 80 lines of native Wazuh alert
  JSON (manager startup events + CIS Ubuntu 24.04 Benchmark SCA check
  results), covering rule levels 3-10.
- `network/sample_suricata_eve.json` — 140 real Suricata `eve.json` alert
  events (`event_type: "alert"` only), covering ET POLICY / ET HUNTING
  signature hits and stream anomalies against private lab IP ranges.

Reviewed before committing: no credentials, secrets, or externally-routable
IPs are present — everything is internal lab telemetry
(`172.17.0.0/16` / `192.168.0.0/16`) with generic host aliases
(`corpdns`, `inetfw`, `wazuh`).

Run:

```
python scripts/ingest_local_logs.py --root scripts/fixtures/sample_lab
```

To test against your own larger export instead, point `--root` at a
directory with the same `security/` + `network/` layout — see the script's
module docstring for the exact filename patterns it looks for. Do not commit
full raw log exports here; multi-megabyte dumps belong outside the repo
(pass `--root` at an external path instead).
