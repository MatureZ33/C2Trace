# Evidence Rules

Minimum evidence chain for response:

- Process response requires C2 network evidence linking the seed to a local PID or process name.
- File response requires process/file/persistence evidence linking the file path to the C2 seed.
- Registry, scheduled task, and service response requires persistence evidence pointing to the attributed payload.
- If evidence is missing, request more read-only investigation instead of executing response.

