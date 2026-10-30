# Windows Tool Catalog

Read-only tools:

- `check_network(remote_ip, remote_port)`: returns matching TCP connections and owning PID/process context.
- `check_process(pid | process_name)`: returns process path, command line, parent PID, and creation time.
- `check_process_tree(pid | process_name)`: returns parent process chain.
- `check_file_metadata(file_path)`: returns existence, SHA256, signature status, and timestamps.
- `check_persistence_all(process_path?)`: returns Run Keys, non-Microsoft scheduled tasks, and auto-start services.
- `check_powershell_history(pattern)`: returns matching PowerShell history lines.
- `check_dns_cache(domain_filter)`: returns matching DNS cache entries.
- `verify_cleanup(remote_ip, remote_port, file_path, pid, process_name)`: rechecks post-response state.

Response tools:

- `kill_process(pid, process_name, expected_path)`: terminates exactly one matching process.
- `remove_file(file_path)`: removes a file.
- `remove_registry(reg_path, value_name, expected_value)`: removes a registry value after optional value check.
- `remove_scheduled_task(task_name, task_path)`: removes a scheduled task.
- `remove_service(service_name)`: removes a service.

Response tools must be audited before execution.

