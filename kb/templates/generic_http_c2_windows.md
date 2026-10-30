# Generic HTTP C2 Windows Investigation Template

This is generic investigation knowledge, not a case answer.

Use this pattern for a Windows host with a suspected HTTP/HTTPS C2 seed:

1. Confirm the current or recent network connection by remote IP and port.
2. If a connection is found, extract the owning PID and process context.
3. Inspect the owning process, command line, executable path, and parent process chain.
4. Inspect executable file metadata, hash, signature, and timestamps.
5. Search common persistence locations such as Run Keys, scheduled tasks, and services.
6. Search PowerShell history for launch/download traces related to the C2 address or payload path.
7. Generate response nodes only after evidence links the C2 seed to a process and file/persistence object.
8. Verify cleanup by rechecking network, process, file, and persistence state.

Do not include case-specific sample names, paths, PIDs, registry values, or Caldera operation details.

