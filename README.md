# YourPureAI Computer Control API Server

A minimalist HTTPS API server designed to work with Your Pure AI. This lightweight server enables remote execution of scenarios and automation tasks on your computer from any mobile device on your local network.

## Overview

This Python-based HTTPS server creates a secure endpoint that can receive JSON commands from the Your Pure AI app. When a valid request is received, the server saves the request data to a file which can then trigger various automated workflows on your computer.

### Key Features

- **Secure HTTPS Communication**: All traffic between your mobile device and computer is encrypted
- **API Key Authentication**: Requests are validated using a configurable API key
- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux
- **Automation Integration**: Compatible with popular automation tools including:
  - UI.Vision RPA
  - AutoHotKey
  - Bash scripts
  - PowerShell commands
  - Other automation platforms

## Installation

### Prerequisites

- Python 3.6 or higher
- OpenSSL (for generating SSL certificates)

### Step 1: Clone the Repository

```bash
git clone https://github.com/YourPureAI/YourPureAI-Remote-Computer-Control.git
cd yourpureai-computer-control
```

### Step 2: Create SSL Certificate

For secure HTTPS communication, you need to create an SSL certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

When prompted, you can use the default values or customize as needed.

### Step 3: Configuration

Run the server once to generate the default configuration file:

```bash
python https_server.py
```

This will create a `config.json` file with default settings. Edit this file to:
- Change the default API key (`your_secure_api_key`) to a secure value
- Optionally modify the port (default: 8443)

```json
{
    "api_key": "your_secure_api_key",
    "port": 8443,
    "cert_file": "server.crt", 
    "key_file": "server.key"
}
```

## Usage

### Starting the Server

Run the server with:

```bash
python https_server.py
```

The server will output its local address and port, for example:
```
Server running on https://localhost:8443 and is available from local network
```

### Connecting from Your Pure AI Computer Control App

1. Run Your Pure AI Computer Control APP scenario_execution.py. Available on https://github.com/YourPureAI/YourPureAI-Computer-Control-app/tree/main or use direct implementation of automation platforms lik UI.Vision end others (info below)
2. Test the connection

### API Request Format

The server expects POST requests with JSON data including:

```json
{
    "compControlAPIKey": "your_secure_api_key",
    "commandType": "runScript",
    "scriptName": "example_script",
    "parameters": {
        "param1": "value1",
        "param2": "value2"
    }
}
```

When a valid request is received, the server:
1. Validates the API key
2. Saves the request data (excluding the API key) to `actualRequest.json`
3. Returns a success response

## Integrating with Automation Tools

### UI.Vision RPA

Create a script that monitors the `actualRequest.json` file and triggers macros based on the content:

```javascript
// Example UI.Vision script
var fs = require('fs');
var requestData = JSON.parse(fs.readFileSync('actualRequest.json', 'utf8'));

if (requestData.commandType === 'runUiVisionMacro') {
    runMacro(requestData.scriptName);
}
```

### AutoHotKey

```autohotkey
; Example AutoHotKey script
Loop {
    FileReadLine, fileContent, actualRequest.json, 1
    parsedJson := JSON.parse(fileContent)
    if (parsedJson.commandType = "runAhkScript") {
        Run % parsedJson.scriptPath
    }
    Sleep, 5000
}
```

### Bash Integration

```bash
#!/bin/bash
# Example bash monitor script
while true; do
    if [[ -f "actualRequest.json" ]]; then
        COMMAND_TYPE=$(jq -r '.commandType' actualRequest.json)
        if [[ "$COMMAND_TYPE" == "runBashCommand" ]]; then
            COMMAND=$(jq -r '.command' actualRequest.json)
            eval "$COMMAND"
        fi
    fi
    sleep 5
done
```

### PowerShell Integration

```powershell
# Example PowerShell monitor script
while ($true) {
    if (Test-Path "actualRequest.json") {
        $requestData = Get-Content "actualRequest.json" | ConvertFrom-Json
        if ($requestData.commandType -eq "runPowershellCommand") {
            Invoke-Expression $requestData.command
        }
    }
    Start-Sleep -Seconds 5
}
```

## Troubleshooting

### Certificate Warnings

When accessing the server from a browser or app, you may see certificate warnings because the certificate is self-signed. 

For testing purposes, these warnings can be bypassed:
- In browsers: Click "Advanced" and then "Proceed to [IP] (unsafe)"
- In apps: There may be a setting to ignore SSL certificate errors

For more secure usage, you can:
1. Create a proper certificate from a trusted authority
2. Create your own Certificate Authority (CA) and import it into all devices

### Connection Issues

If you can't connect to the server from other devices:

1. Ensure your firewall allows incoming connections on the configured port
2. Verify you're using the correct IP address and port
3. Check that the server is running and listening on all interfaces (0.0.0.0)
4. Confirm your mobile device is on the same network as your computer

## Security Considerations

1. This server uses API key authentication but has minimal security features.
2. It's recommended to use this only on trusted local networks.
3. Update your API key regularly.
4. The server should not be exposed to the public internet.
5. Consider implementing additional security measures for sensitive environments.

## License

[Specify your license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.