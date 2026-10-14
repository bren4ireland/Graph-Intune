# Graph-Intune MCP

MCP server (stdio) that uses Microsoft Graph to report Intune device encryption, trends, and last sync.

## Tools
| Tool | Purpose |
|---|---|
| `get_encryption_status` | Detailed per-device state (encryption, readiness, policy, BitLocker/FileVault, TPM) + summary |
| `record_encryption_snapshot` | Save current states to local SQLite history (run daily) |
| `get_encryption_trend` | Encrypted % and state counts over time, plus devices whose state changed |
| `get_encryption_health_insights` | Grade, % by OS, why devices are unencrypted, TPM mix, active-but-unencrypted devices, policy gaps |
| `email_encryption_report` | HTML report by email via Graph. `preview=True` by default; recipients limited to `MAIL_ALLOWED_DOMAINS` |
| `get_last_sync_active_devices` | Last check-in for devices active within N days, flags stale ones |

## Setup
1. Entra app registration with **application** permission (admin consent):
   `DeviceManagementManagedDevices.Read.All`. Create a client secret.
   For email also add `Mail.Send` (application) and set `MAIL_SENDER` (mailbox UPN) and `MAIL_ALLOWED_DOMAINS` (e.g. `contoso.com`). Consider an Exchange application access policy to restrict `Mail.Send` to that one mailbox.
2. `pip install -e .`
3. Env vars: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`; optional `INTUNE_HISTORY_DB` (default `~/.graph-intune-mcp/history.db`).
4. Register in your MCP client, e.g. VS Code `.vscode/mcp.json`:
   ```json
   {"servers": {"graph-intune": {"type": "stdio", "command": "graph-intune-mcp",
     "env": {"AZURE_TENANT_ID": "...", "AZURE_CLIENT_ID": "...", "AZURE_CLIENT_SECRET": "..."}}}}
   ```

Notes: encryption detail uses the Graph **beta** endpoint `managedDeviceEncryptionStates`. Trend data only exists
from the first snapshot onward, so schedule `record_encryption_snapshot` (cron/automation).

## Test
`pip install -e .[dev] && pytest`
