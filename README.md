# Jump Gopher

Jump Gopher is a simple SSH jump/proxy server supporting fine-grained permissions on reachable addresses.

## Features

- OAuth2 authentication for user management
- Web portal for self-service key management
- Per user permission management via YAML configuration supporting dynamic reloading
- Integrated SSH server that only supports forwarding
- Optional websocket proxy for SSH connections
- Prometheus metrics

### Docker example

The jump proxy is straightforward to run using Docker and Docker Compose:

```yaml
services:
  jump-gopher:
    image: ghcr.io/bboehmke/jump-gopher:latest
    restart: unless-stopped
    ports:
      - "8080:8080"   # web UI
      - "2222:2222"   # SSH jump server
    environment:
      OAUTH_ID: "..."
      OAUTH_SECRET: "..."
      OAUTH_AUTH_URL: "..."
      OAUTH_TOKEN_URL: "..."
    volumes:
      - ./data:/data
```

> **Note:** For production use, a reverse proxy and a postgres database are recommended.

## Configuration

The application is configured via environment variables. The following table 
lists all available variables, their descriptions and default values.

| Variable Name          | Description                         | Default Value                         |
|------------------------|-------------------------------------|---------------------------------------|
| `OAUTH_ID`             | OAuth2 client ID                    |                                       |
| `OAUTH_SECRET`         | OAuth2 client secret                |                                       |
| `OAUTH_SCOPES`         | OAuth2 scopes (comma separated)     | `email,openid,profile,offline_access` |
| `OAUTH_AUTH_URL`       | OAuth2 authorization URL            |                                       |
| `OAUTH_TOKEN_URL`      | OAuth2 token URL                    |                                       |
| `OAUTH_USERNAME_CLAIM` | OAuth2 claim for user name          | `preferred_username`                  |
| `DATABASE_URL`         | Database connection string          | `file:data/data.db`                   |
| `WEB_PORT`             | Port for the web server             | `8080`                                |
| `WEB_ENABLE_PROXY`     | Enable web SSH proxy                | `false`                               |
| `WEB_DEBUG`            | Enable debug logging for web server | `false`                               |
| `SSH_PORT`             | Port for the SSH server             | `2222`                                |
| `SSH_HOST_KEY_PATH`    | Path to SSH host keys               | `data/`                               |
| `PERMISSIONS_CONFIG`   | Path to permissions YAML config     | `data/permissions.yml`                |

**Note:** If a variable has no default value, it must be set explicitly.

### `DATABASE_URL`

The database connection string supports SQLite (`file`) and PostgreSQL. 
By default, it uses a SQLite database stored in `data/data.db`.

To use PostgreSQL, set the `DATABASE_URL` to a valid PostgreSQL connection string like 
`postgres://user:password@localhost:5432/dbname`.

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

## Security Overview

Jump Gopher is designed with a strong security model:

- **User Accounts:**  
  - Managed via OAuth2 (e.g., Google, Microsoft, etc.)
  - OAuth tokens are verified on *every* web request and *every* SSH connection.
  - Expired access tokens are automatically renewed using the refresh token.

- **Permissions:**  
  - Managed per user in a YAML config file (`permissions.yml`).
  - Only users listed in the config file can connect; unknown users are denied access to all hosts.
  - Permissions are enforced for every SSH forwarding request.

- **SSH Authentication:**  
  - SSH sessions require public key authentication.
  - Only public keys added by the user via the web interface are accepted for SSH login.
