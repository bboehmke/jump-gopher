# Jump Gopher

Jump Gopher is a simple SSH jump/proxy server supporting fine-grained permissions on reachable addresses.

## Features

- OAuth2 authentication for user management
- Web portal for self-service key management
- Per user permission management via YAML configuration supporting dynamic reloading
- Integrated SSH server that only supports forwarding
- Optional websocket proxy for SSH connections

## Configuration

The application is configured via environment variables. The following table lists all available variables, their descriptions and default values.

| Variable Name         | Description                     | Default Value                         |
|-----------------------|---------------------------------|---------------------------------------|
| `OAUTH_ID`            | OAuth2 client ID                |                                       |
| `OAUTH_SECRET`        | OAuth2 client secret            |                                       |
| `OAUTH_SCOPES`        | OAuth2 scopes (comma separated) | `email,openid,profile,offline_access` |
| `OAUTH_AUTH_URL`      | OAuth2 authorization URL        |                                       |
| `OAUTH_TOKEN_URL`     | OAuth2 token URL                |                                       |
| `DATABASE_URL`        | Database connection string      | `file:data/data.db`                   |
| `WEB_PORT`            | Port for the web server         | `8080`                                |
| `WEB_ENABLE_PROXY`    | Enable web SSH proxy            | `false`                               |
| `SSH_PORT`            | Port for the SSH server         | `2222`                                |
| `SSH_HOST_KEY_PATH`   | Path to SSH host keys           | `data/`                               |
| `PERMISSIONS_CONFIG`  | Path to permissions YAML config | `data/permissions.yml`                |

**Note:** If a variable has no default value, it must be set explicitly.

## Permissions YAML Format

Permissions are defined in a YAML file, typically at `data/permissions.yml`. The format is as follows:

```yaml
username1:
  allow:
    - "192\\.168\\.1\\.[0-9]+"
    - "10\\.0\\.0\\.1"
  deny:
    - "192\\.168\\.1\\.100"
username2:
  allow:
    - "example\\.com"
  deny:
    - ".*"
```

- Each top-level key is a username.
- `allow` is a list of regular expressions for addresses the user is allowed to access.
- `deny` is a list of regular expressions for addresses the user is denied access to.
- If a user is not listed, access is denied by default.

**Regex Handling:**
- Each list (`allow` or `deny`) is combined into a single regular expression, with each entry joined by `|` and wrapped with `^` and `$`.
- This means each entry must match the *entire* address (e.g., IP or hostname), not just a substring.

**Matching logic:**
- If an address matches any `deny` pattern, access is denied.
- If an address matches any `allow` pattern and not denied, access is allowed.
- If neither matches, access is denied.
