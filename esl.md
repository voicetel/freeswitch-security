# ESL Command API

The FreeSWITCH Security application now includes a secure API endpoint to send commands to FreeSWITCH through the Event Socket Layer (ESL).

## Features

- Send arbitrary commands to FreeSWITCH through a simple REST API
- Command whitelist for security (only allowed commands can be executed)
- Configurable via config.json or environment variables
- Proper error handling and logging

## Configuration

The ESL command feature uses a whitelist approach for security. Only commands that are explicitly allowed in the configuration can be executed.

### Setting Up the Command Whitelist

In your `config.json` file, you can specify which commands are allowed:

```json
"security": {
  "esl_allowed_commands": [
    "status",
    "uptime",
    "version"
  ]
}
```

### Environment Variable Configuration

You can also configure the allowed commands via environment variable:

```bash
export SECURITY_ESL_ALLOWED_COMMANDS='["status", "show", "version"]'
```

Note that the environment variable must contain a valid JSON array of strings.

## API Usage

### Endpoint

```
POST /security/esl/command
```

### Request Body

```json
{
  "command": "status"
}
```

### Response

```json
{
  "command": "status",
  "response": "UP 0 years, 0 days, 2 hours, 15 minutes, 30 seconds, 950 milliseconds, 560 microseconds\nFreeSWITCH (Version 1.10.7 -release- 64bit) is ready\n..."
}
```

### Error Responses

If the command is not in the whitelist:

```json
{
  "error": "command not allowed: originate"
}
```

If not connected to ESL:

```json
{
  "error": "not connected to FreeSWITCH ESL"
}
```

## Example Usage

Using curl:

```bash
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command":"status"}'
```

## Security Considerations

- Only use this API in secure environments
- Restrict access to this endpoint using proper authentication and authorization
- Keep the whitelist as restrictive as possible
- Avoid adding potentially dangerous commands to the whitelist
- Consider using a reverse proxy with TLS for secure access
