# Response Safety Rules

- Never approve destructive response based only on a filename, directory, or suspicious-looking path.
- Never approve deletion of an artifact that is merely similar to a confirmed payload.
- `kill_process` should include PID and expected_path whenever available.
- `remove_file` should target only a file path already observed through process, metadata, or persistence evidence.
- Rejected or closed branches must be reported as evidence-insufficient, not as system failure.

