import http.server
import socketserver
import ssl
import json
import os
import platform
import subprocess
from urllib.parse import urlparse, parse_qs
from http import HTTPStatus
import re
import urllib.parse
import threading

# --- Configuration Files ---
CONFIG_FILE = "config.json"
OUTPUT_FILE = "actualRequest.json"
ALLOWED_SCENARIOS_FILE = "allowed_scenarios.json"
MANAGEMENT_HTML_FILE = "manage_scenarios.html"

# --- Load/Save Functions ---

def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "api_key": "your secret API key",
            "port": 8443,
            "cert_file": "server.crt",
            "key_file": "server.key"
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)
        print(f"Created initial config file {CONFIG_FILE}")
        return default_config
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading config file {CONFIG_FILE}: {e}. Using default values.")
        return { "api_key": "your secret API key", "port": 8443, "cert_file": "server.crt", "key_file": "server.key" }


def load_scenarios():
    if not os.path.exists(ALLOWED_SCENARIOS_FILE):
        with open(ALLOWED_SCENARIOS_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=4, ensure_ascii=False)
        print(f"Created initial scenarios file {ALLOWED_SCENARIOS_FILE}")
        return []
    try:
        with open(ALLOWED_SCENARIOS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading scenarios file {ALLOWED_SCENARIOS_FILE}: {e}. Returning empty list.")
        return []

def save_scenarios(scenarios):
    try:
        with open(ALLOWED_SCENARIOS_FILE, 'w', encoding='utf-8') as f:
            json.dump(scenarios, f, indent=4, ensure_ascii=False)
        print(f"Scenarios saved to {ALLOWED_SCENARIOS_FILE}")
    except IOError as e:
        print(f"Error saving scenarios to {ALLOWED_SCENARIOS_FILE}: {e}")

# --- Command Execution Logic ---

def substitute_variables(template_string, variables):
    if not variables:
        variables = {}

    def replace_match(match):
        placeholder = match.group(0)
        var_name = match.group(1)

        if var_name in variables:
            value = variables[var_name]
            if var_name.startswith("enc_"):
                encoded_value = urllib.parse.quote(str(value), safe='')
                print(f"Encoding variable '{var_name}' value '{str(value)}' to '{encoded_value}'")
                return encoded_value
            else:
                return str(value)
        else:
            print(f"Varování: Proměnná {placeholder} nebyla nalezena v dataForExecution.")
            return placeholder

    pattern = re.compile(r'\$\{\s*([a-zA-Z0-9_]+)\s*\}')
    substituted_string = pattern.sub(replace_match, template_string)
    return substituted_string

def execute_scenario_command(scenario, data_for_execution):
    """Executes the command defined in the scenario with substituted variables."""
    command_template = scenario.get("command_template", "")
    command_type = str(scenario.get("command_type", "")).lower()

    if not command_template:
        print(f"Execute Scenario: Error - Scenario '{scenario.get('name')}' has no 'command_template'.")
        return False, "Scenario has no command template"

    if not command_type:
        print(f"Execute Scenario: Error - Scenario '{scenario.get('name')}' has no 'command_type'.")
        return False, "Scenario has no command type"

    # --- Substitute Variables ---
    try:
        command_to_execute = substitute_variables(command_template, data_for_execution)
    except Exception as e:
        error_message = f"Execute Scenario: Error during variable substitution for scenario '{scenario.get('name')}': {e}"
        print(error_message)
        return False, error_message

    # --- Prepare Arguments for subprocess ---
    args = []
    shell_name = ""
    current_os = platform.system()

    if command_type == "cmd":
        if current_os != "Windows":
            msg = f"Cannot execute 'cmd' type on {current_os}"
            print(f"Execute Scenario: Warning - {msg}")
            return False, msg
        shell_name = "Command Prompt (cmd.exe)"
        args = ['cmd', '/d', '/c', command_to_execute]
    elif command_type == "powershell":
        if current_os != "Windows":
            msg = f"Cannot execute 'powershell' type on {current_os}"
            print(f"Execute Scenario: Warning - {msg}")
            return False, msg
        shell_name = "PowerShell"
        args = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command_to_execute]
    elif command_type == "linux_shell":
        if current_os == "Windows":
            msg = f"Cannot execute 'linux_shell' type on {current_os}"
            print(f"Execute Scenario: Warning - {msg}")
            return False, msg
        shell_name = "Linux Shell (/bin/sh or similar)"
        args = ['/bin/sh', '-c', command_to_execute]
    else:
        error_message = f"Execute Scenario: Invalid 'command_type' ('{command_type}') in scenario '{scenario.get('name')}'. Must be 'cmd', 'powershell', or 'linux_shell'."
        print(error_message)
        return False, error_message

    print(f"Execute Scenario: Running action '{scenario.get('name')}' via {shell_name}:")
    print(f"--- Start Command ---")
    print(command_to_execute)
    print(f"--- End Command ---")

    # --- Execute Command ---
    try:
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='replace',
            startupinfo=startupinfo,
            shell=False
        )

        print(f"Execute Scenario: Process for '{scenario.get('name')}' finished with return code: {result.returncode}")
        if result.stdout:
            print("--- Command Output (stdout) ---")
            print(result.stdout.strip())
            print("-------------------------------")
        if result.stderr:
            print("--- Command Error Output (stderr) ---")
            print(result.stderr.strip())
            print("-----------------------------------")

        success = result.returncode == 0
        message = f"Command executed. Return code: {result.returncode}."
        if result.stderr:
             message += f" Stderr: {result.stderr.strip()}"

        return success, message

    except FileNotFoundError:
        error_message = f"Execute Scenario: Error - {shell_name} executable not found. Is it installed and in your PATH?"
        print(error_message)
        return False, error_message
    except OSError as e:
        error_message = f"Execute Scenario: OS error launching process for scenario '{scenario.get('name')}': {e}"
        print(error_message)
        return False, error_message
    except Exception as e:
        error_message = f"Execute Scenario: An unexpected error occurred during execution for scenario '{scenario.get('name')}': {e}"
        import traceback
        print(error_message)
        traceback.print_exc()
        return False, error_message

# --- HTTP Request Handler ---

class APIHandler(http.server.SimpleHTTPRequestHandler):

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def send_text_response(self, status_code, content, content_type="text/plain"):
        self.send_response(status_code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.end_headers()
        if isinstance(content, str):
            content = content.encode('utf-8')
        self.wfile.write(content)

    def send_error_response(self, code, message=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        error_message = f"Error {code}: {message if message else http.server.BaseHTTPRequestHandler.responses[code][0]}"
        self.wfile.write(error_message.encode('utf-8'))
        print(f"Sent error response: {error_message}")

    def serve_management_page(self):
        if not os.path.exists(MANAGEMENT_HTML_FILE):
            self.send_error_response(HTTPStatus.NOT_FOUND, f"Management UI file '{MANAGEMENT_HTML_FILE}' not found.")
            return
        try:
            with open(MANAGEMENT_HTML_FILE, 'rb') as f:
                content = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading management UI file: {e}")

    def do_GET(self):
        config = load_config()

        if self.path == '/' or self.path == '/manage':
            self.serve_management_page()
        elif self.path == '/api/scenarios':
            scenarios = load_scenarios()
            self.send_json_response(HTTPStatus.OK, scenarios)
        else:
            self.send_text_response(
                HTTPStatus.OK,
                "API Server is running. Use POST to /api for actions or GET /manage for UI.",
                "text/html"
            )

    def do_POST(self):
        config = load_config()
        expected_api_key = config.get("api_key", "MISSING_API_KEY")

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error_response(HTTPStatus.BAD_REQUEST, "Empty request body")
            return

        post_data = self.rfile.read(content_length)

        try:
            json_data = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid JSON format")
            return
        except Exception as e:
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading request body: {str(e)}")
            return

        received_api_key = json_data.get('compControlAPIKey')
        if expected_api_key == "your secret API key":
             print("Warning: Using default API key. Please change it in config.json for security.")
        elif received_api_key != expected_api_key:
            print(f"Unauthorized attempt with key: {received_api_key}")
            self.send_error_response(HTTPStatus.UNAUTHORIZED, "Invalid API key")
            return

        parsed_path = urlparse(self.path)
        path = parsed_path.path

        try:
            if path == '/api':
                action_name = json_data.get('actionName')
                data_for_execution = json_data.get('dataForExecution', {})

                if not action_name:
                    self.send_error_response(HTTPStatus.BAD_REQUEST, "Missing 'actionName' in request")
                    return

                scenarios = load_scenarios()
                found_scenario = None
                for scenario in scenarios:
                    if scenario.get('name') == action_name:
                        found_scenario = scenario
                        break

                if found_scenario and found_scenario.get('allowed', False):
                    print(f"Executing allowed scenario: {action_name}")

                    # --- Start Execution in a Thread ---
                    def execute_in_thread(scenario, data, handler):
                        success, message = execute_scenario_command(scenario, data)
                        if success:
                            response_data = {"status": "success", "message": f"Scenario '{action_name}' executed. {message}"}
                            # handler.send_json_response(HTTPStatus.OK, response_data) # Can't call this from thread
                            print(f"Scenario '{action_name}' executed successfully in thread.")
                        else:
                            response_data = {"status": "error", "message": f"Scenario '{action_name}' execution failed. {message}"}
                            # handler.send_json_response(HTTPStatus.INTERNAL_SERVER_ERROR, response_data) # Can't call this from thread
                            print(f"Scenario '{action_name}' failed in thread: {message}")


                    # Send immediate response
                    response_data = {"status": "processing", "message": f"Scenario '{action_name}' execution started in background."}
                    self.send_json_response(HTTPStatus.ACCEPTED, response_data) # Changed to ACCEPTED

                    thread = threading.Thread(target=execute_in_thread, args=(found_scenario, data_for_execution, self))
                    thread.daemon = True  # Allow the main program to exit even if the thread is running
                    thread.start()

                else:
                    if found_scenario:
                         print(f"Scenario '{action_name}' found but is not allowed. Saving request to file.")
                    else:
                         print(f"Scenario '{action_name}' not found in allowed scenarios. Saving request to file.")

                    json_data_to_save = {k: v for k, v in json_data.items() if k != 'compControlAPIKey'}
                    try:
                        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                            json.dump(json_data_to_save, f, indent=4, ensure_ascii=False)
                        print(f"Data received and stored in {OUTPUT_FILE}")
                        response_data = {"status": "success", "message": f"Scenario '{action_name}' not configured or not allowed. Data saved."}
                        self.send_json_response(HTTPStatus.OK, response_data)
                    except IOError as e:
                         self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error saving data to file: {e}")

            elif path == '/api/scenarios/save':
                 new_scenarios_list = json_data.get('scenarios')
                 if not isinstance(new_scenarios_list, list):
                     self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid data format: 'scenarios' key must contain a list.")
                     return

                 for i, scenario in enumerate(new_scenarios_list):
                      if not isinstance(scenario, dict) or 'name' not in scenario or 'command_type' not in scenario or 'command_template' not in scenario or 'allowed' not in scenario:
                           self.send_error_response(HTTPStatus.BAD_REQUEST, f"Invalid format for scenario at index {i}")
                           return

                 save_scenarios(new_scenarios_list)
                 self.send_json_response(HTTPStatus.OK, {"status": "success", "message": "Scenarios saved successfully."})

            else:
                self.send_error_response(HTTPStatus.NOT_FOUND, "Endpoint not found")

        except Exception as e:
            error_message = f"Internal Server Error: {str(e)}"
            import traceback
            print(error_message)
            traceback.print_exc()
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "An internal server error occurred.")

# --- Server Startup ---

def run_server():
    config = load_config()
    port = config.get("port", 8443)
    cert_file = config.get("cert_file", "server.crt")
    key_file = config.get("key_file", "server.key")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("\n--- Certificate Warning ---")
        print(f"Certificate file ('{cert_file}') or key file ('{key_file}') not found.")
        print("The server cannot start in HTTPS mode without them.")
        print("\nTo create a self-signed certificate for testing, use OpenSSL:")
        print(f"  openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj \"/CN=localhost\"")
        print("\nAlternatively, configure valid certificate paths in config.json.")
        print("Server startup aborted.")
        return

    if not os.path.exists(MANAGEMENT_HTML_FILE):
        create_default_management_html()

    handler = APIHandler
    try:
        httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    except OSError as e:
        print(f"\n--- Server Startup Error ---")
        print(f"Could not bind to address 0.0.0.0:{port}. Error: {e}")
        print("Possible reasons:")
        print(f"  - Another application is already using port {port}.")
        print("  - Insufficient permissions to bind to the port.")
        print("Server startup aborted.")
        return


    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"\nServer starting on https://0.0.0.0:{port}")
        print(f"Access the management UI at: https://<your-server-ip>:{port}/manage")
        print(f"API endpoint: https://<your-server-ip>:{port}/api")
        print("Press Ctrl+C to stop the server.")
        httpd.serve_forever()
    except ssl.SSLError as e:
        print(f"\n--- SSL Error ---")
        print(f"Failed to wrap socket with SSL: {e}")
        print("Possible reasons:")
        print(f"  - Certificate ('{cert_file}') and key ('{key_file}') mismatch.")
        print("  - Incorrect certificate/key format.")
        print("  - Certificate expired (if not self-signed).")
        print("Server startup aborted.")
    except Exception as e:
        print(f"\n--- Unexpected Server Error ---")
        print(f"An error occurred during server setup or runtime: {e}")
        import traceback
        traceback.print_exc()


def create_default_management_html():
    html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Manage Allowed Scenarios</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" integrity="sha512-9usAa10IRO0HhonpyAIVpjrylPvoDwiPUiKdWk5t3PyolY1cOd4DSE0Ga+ri4AuTroPR5aQvXU9xC6qOPnzFeg==" crossorigin="anonymous" referrerpolicy="no-referrer" />
            <style>
                body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
                .container { max-width: 900px; margin: 20px auto; background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                h1, h2 { color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input[type="text"], input[type="password"], textarea, select {
                    width: calc(100% - 22px); /* Account for padding and border */
                    padding: 10px;
                    margin-bottom: 15px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    box-sizing: border-box;
                    font-size: 14px;
                }
                textarea { height: 80px; resize: vertical; }
                button {
                    padding: 8px 15px;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    margin-left: 5px; /* Spacing between buttons */
                    transition: background-color 0.3s ease;
                    font-size: 14px;
                    vertical-align: middle; /* Align icons and text */
                }
                button i { margin-right: 5px; } /* Space between icon and text */
                button:hover { opacity: 0.9; }

                .btn-save-all { background-color: #337ab7; }
                .btn-add { background-color: #5cb85c; }
                .btn-edit { background-color: #f0ad4e; }
                .btn-copy { background-color: #6c757d; }
                .btn-delete { background-color: #d9534f; }
                .btn-toggle { width: 40px; text-align: center; padding: 8px 0; } /* Fixed width for toggle */
                .btn-toggle.allowed { background-color: #5cb85c; } /* Green when allowed */
                .btn-toggle.disallowed { background-color: #f0ad4e; } /* Yellow when disallowed */

                .api-key-input, .scenario-form, .scenarios-list-container { margin-bottom: 25px; }
                .actions-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }

                #messageArea {
                    margin-top: 15px; padding: 12px; border-radius: 4px; font-weight: bold; display: none; /* Hidden by default */
                    text-align: center;
                }
                .error-message { color: #a94442; background-color: #f2dede; border: 1px solid #ebccd1; }
                .success-message { color: #3c763d; background-color: #dff0d8; border: 1px solid #d6e9c6; }
                .info-message { color: #31708f; background-color: #d9edf7; border: 1px solid #bce8f1; }

                #scenariosList { list-style: none; padding: 0; }
                #scenariosList li {
                    background-color: #f9f9f9;
                    border: 1px solid #eee;
                    margin-bottom: 10px;
                    border-radius: 4px;
                    padding: 15px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                }
                .scenario-summary { display: flex; justify-content: space-between; align-items: center; }
                .scenario-name { font-weight: bold; flex-grow: 1; margin-right: 15px; }
                .scenario-actions button { margin-left: 8px; }
                .scenario-details {
                    display: none; /* Hidden by default */
                    margin-top: 15px;
                    padding-top: 15px;
                    border-top: 1px dashed #ccc;
                }
                .scenario-details.visible { display: block; } /* Shown when editing */
                .form-group { margin-bottom: 15px; }
                small { color: #666; font-size: 12px; display: block; margin-top: -10px; margin-bottom: 10px; }

            </style>
        </head>
        <body>
            <div class="container">
                <h1>Manage Allowed Scenarios</h1>

                <div class="api-key-input form-group">
                    <label for="apiKey">API Key (required for saving):</label>
                    <input type="password" id="apiKey" placeholder="Enter your API key">
                    <small>Needed to save changes. Get this from your config.json.</small>
                </div>

                <div class="actions-header">
                    <h2>Current Scenarios</h2>
                    <button onclick="saveAllScenarios()" class="btn-save-all"><i class="fas fa-save"></i> Save All Changes</button>
                </div>
                <div id="messageArea"></div> <!-- Message area moved here -->

                <div class="scenarios-list-container">
                    <ul id="scenariosList">
                        <!-- Scenarios will be loaded here by JavaScript -->
                    </ul>
                </div>

                <h2>Add New Scenario</h2>
                <div class="scenario-form">
                    <div class="form-group">
                        <label for="newName">Name:</label>
                        <input type="text" id="newName" placeholder="Unique scenario name (e.g., run_backup)">
                    </div>
                    <div class="form-group">
                        <label for="newType">Command Type:</label>
                        <select id="newType">
                            <option value="cmd">Windows CMD</option>
                            <option value="powershell">Windows PowerShell</option>
                            <option value="linux_shell">Linux Shell</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="newTemplate">Command Template:</label>
                        <textarea id="newTemplate" placeholder="Enter command(s). Use ${variable_name} for placeholders (e.g., echo Hello ${user})"></textarea>
                        <small>Variables from API calls (dataForExecution) like ${myVar} will be substituted. If variable starts with enc_ (e.g. ${enc_myUrlParam}), it will be URL-encoded.</small>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="newAllowed" checked> Allow Execution
                        </label>
                    </div>
                    <button onclick="addScenario()" class="btn-add"><i class="fas fa-plus"></i> Add Scenario</button>
                </div>
            </div>

            <script>
                let scenarios = []; // Holds the current state of scenarios
                let currentlyEditingIndex = null; // Track which scenario detail is open

                // --- Data Fetching and Saving ---

                async function fetchScenarios() {
                    try {
                        const response = await fetch('/api/scenarios');
                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }
                        scenarios = await response.json();
                        if (!Array.isArray(scenarios)) { // Basic validation
                            console.error("Received invalid scenario data:", scenarios);
                            throw new Error("Invalid data format received from server.");
                        }
                        renderScenariosList();
                        setMessage(''); // Clear messages on successful load
                    } catch (error) {
                        console.error('Error fetching scenarios:', error);
                        setMessage(`Error loading scenarios: ${error.message}`, true);
                        scenarios = []; // Reset scenarios on error
                        renderScenariosList(); // Render empty list
                    }
                }

                async function saveAllScenarios() {
                    const apiKey = document.getElementById('apiKey').value;
                    if (!apiKey) {
                        setMessage('API Key is required to save changes.', true);
                        return;
                    }

                    // Basic validation before saving
                    const names = scenarios.map(s => s.name ? s.name.trim() : '');
                    const uniqueNames = new Set(names.filter(name => name !== '')); // Filter empty names before checking uniqueness
                    if (names.some(name => name === '')) {
                        setMessage('Error: Scenario names cannot be empty.', true);
                        return;
                    }
                    if (names.filter(name => name !== '').length !== uniqueNames.size) {
                        setMessage('Error: Scenario names must be unique.', true);
                        return;
                    }

                    console.log("Saving scenarios:", scenarios);
                    setMessage('Saving...', false, true); // Indicate progress

                    try {
                        const response = await fetch('/api/scenarios/save', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ compControlAPIKey: apiKey, scenarios: scenarios })
                        });

                        // --- Start of Correction ---
                        // Check if the response status indicates success (e.g., 200 OK)
                        if (response.ok) {
                            // Only try to parse JSON if the response is OK
                            const result = await response.json();
                            if (result.status === 'success') {
                                setMessage('Scenarios saved successfully!', false);
                                currentlyEditingIndex = null; // Close any open edit forms
                                await fetchScenarios(); // Re-fetch to confirm and re-render
                            } else {
                                // Handle cases where the server responded OK but reported an error in the JSON
                                throw new Error(result.message || 'Unknown server error after successful save request.');
                            }
                        } else {
                            // Handle non-OK responses (like 401 Unauthorized, 400 Bad Request, 500 Internal Server Error)
                            let errorText = `Server responded with status ${response.status}`;
                            try {
                                // Try to read the plain text error message from the server
                                const textResponse = await response.text();
                                if (textResponse) {
                                    // If the server sent a text message (like "Invalid API key"), use it.
                                    // Remove potential HTML tags or extra quotes for clarity
                                    errorText = textResponse.replace(/<[^>]*>?/gm, '').trim().replace(/^"|"$/g, '');
                                }
                            } catch (textError) {
                                // Ignore errors trying to read the text body, stick with the status code message
                                console.error("Could not read error response text:", textError);
                            }
                            // Display the specific error (e.g., "Invalid API key")
                            throw new Error(errorText);
                        }
                        // --- End of Correction ---

                    } catch (error) {
                        console.error('Error saving scenarios:', error);
                        // Display the extracted or generated error message
                        setMessage(`Error saving scenarios: ${error.message}`, true);
                    }
                }

                // --- UI Rendering ---

                function renderScenariosList() {
                    const listElement = document.getElementById('scenariosList');
                    listElement.innerHTML = ''; // Clear existing items

                    scenarios.forEach((scenario, index) => {
                        const listItem = document.createElement('li');
                        listItem.setAttribute('data-index', index); // Store index for easy access

                        const isEditing = index === currentlyEditingIndex;

                        listItem.innerHTML = `
                            <div class="scenario-summary">
                                <span class="scenario-name">${escapeHtml(scenario.name || 'Unnamed Scenario')}</span>
                                <div class="scenario-actions">
                                    <button class="btn-toggle ${scenario.allowed ? 'allowed' : 'disallowed'}" onclick="toggleAllowed(${index}, event)" title="${scenario.allowed ? 'Disable' : 'Enable'}">
                                        <i class="fas ${scenario.allowed ? 'fa-toggle-on' : 'fa-toggle-off'}"></i>
                                    </button>
                                    <button class="btn-edit" onclick="toggleEdit(${index}, event)" title="Edit">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button class="btn-copy" onclick="copyScenario(${index}, event)" title="Copy">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                    <button class="btn-delete" onclick="deleteScenario(${index}, event)" title="Delete">
                                        <i class="fas fa-trash-alt"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="scenario-details ${isEditing ? 'visible' : ''}" id="details-${index}">
                                ${isEditing ? renderEditForm(scenario, index) : ''}
                            </div>
                        `;
                        listElement.appendChild(listItem);
                    });
                }

                function renderEditForm(scenario, index) {
                    // Note: Using oninput for text/textarea for more responsive updates to the underlying data model
                    return `
                        <div class="form-group">
                            <label for="editName-${index}">Name:</label>
                            <input type="text" id="editName-${index}" value="${escapeHtml(scenario.name || '')}" oninput="updateScenario(${index}, 'name', this.value)">
                        </div>
                        <div class="form-group">
                            <label for="editType-${index}">Command Type:</label>
                            <select id="editType-${index}" onchange="updateScenario(${index}, 'command_type', this.value)">
                                <option value="cmd" ${scenario.command_type === 'cmd' ? 'selected' : ''}>Windows CMD</option>
                                <option value="powershell" ${scenario.command_type === 'powershell' ? 'selected' : ''}>Windows PowerShell</option>
                                <option value="linux_shell" ${scenario.command_type === 'linux_shell' ? 'selected' : ''}>Linux Shell</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="editTemplate-${index}">Command Template:</label>
                            <textarea id="editTemplate-${index}" oninput="updateScenario(${index}, 'command_template', this.value)">${escapeHtml(scenario.command_template || '')}</textarea>
                            <small>Use \ or \ for substitutions.</small>
                        </div>
                        <div class="form-group">
                            <label>
                                <input type="checkbox" ${scenario.allowed ? 'checked' : ''} onchange="updateScenario(${index}, 'allowed', this.checked); rerenderToggleButton(${index}, this.checked);"> Allow Execution
                            </label>
                        </div>
                        <button onclick="toggleEdit(${index}, event)" class="btn-edit" style="background-color: #aaa;"><i class="fas fa-times"></i> Close Edit</button>
                    `;
                }

                // --- Scenario Actions ---

                function addScenario() {
                    const nameInput = document.getElementById('newName');
                    const typeInput = document.getElementById('newType');
                    const templateInput = document.getElementById('newTemplate');
                    const allowedInput = document.getElementById('newAllowed');

                    const name = nameInput.value.trim();
                    const type = typeInput.value;
                    const template = templateInput.value.trim();
                    const allowed = allowedInput.checked;

                    if (!name) {
                        setMessage('Scenario name cannot be empty.', true);
                        return;
                    }
                    if (scenarios.some(s => s.name === name)) {
                        setMessage(`Scenario name "${name}" already exists. Please choose a unique name.`, true);
                        return;
                    }

                    scenarios.push({ name, command_type: type, command_template: template, allowed });

                    // Clear the form
                    nameInput.value = '';
                    templateInput.value = '';
                    allowedInput.checked = true;
                    // typeInput.value = 'cmd'; // Reset or keep last? Keeping last is often convenient.

                    setMessage('Scenario added locally. Click "Save All Changes" to make it permanent.', false, true);
                    currentlyEditingIndex = null; // Ensure no edit form is open
                    renderScenariosList(); // Re-render the list
                }

                function updateScenario(index, field, value) {
                    if (scenarios[index]) {
                        scenarios[index][field] = value;
                        console.log(`Updated scenario ${index}, field ${field} to:`, value);
                        // Optionally provide feedback that changes are unsaved
                        setMessage('Changes made. Click "Save All Changes" to make them permanent.', false, true);
                    }
                }

                function rerenderToggleButton(index, isAllowed) {
                    // Helper to update only the toggle button's appearance after checkbox change in edit form
                    const listItem = document.querySelector(`li[data-index="${index}"]`);
                    if (listItem) {
                        const button = listItem.querySelector('.btn-toggle');
                        const icon = button.querySelector('i');
                        button.title = isAllowed ? 'Disable' : 'Enable';
                        button.className = `btn-toggle ${isAllowed ? 'allowed' : 'disallowed'}`;
                        icon.className = `fas ${isAllowed ? 'fa-toggle-on' : 'fa-toggle-off'}`;
                    }
                }

                function toggleAllowed(index, event) {
                    event.stopPropagation(); // Prevent triggering edit/other parent events
                    if (scenarios[index]) {
                        scenarios[index].allowed = !scenarios[index].allowed;
                        setMessage('Scenario enabled/disabled status changed locally. Click "Save All Changes" to make it permanent.', false, true);
                        renderScenariosList(); // Re-render the whole list to update button style/icon
                    }
                }

                function toggleEdit(index, event) {
                    event.stopPropagation();
                    if (currentlyEditingIndex === index) {
                        // Close the current editor
                        currentlyEditingIndex = null;
                    } else {
                        // Close any other editor and open this one
                        currentlyEditingIndex = index;
                    }
                    renderScenariosList(); // Re-render to show/hide the correct detail form
                }


                function copyScenario(index, event) {
                    event.stopPropagation();
                    if (scenarios[index]) {
                        const originalScenario = scenarios[index];
                        let newName = originalScenario.name + '_copy';
                        let counter = 1;
                        // Ensure the copied name is unique
                        while (scenarios.some(s => s.name === newName)) {
                            counter++;
                            newName = `${originalScenario.name}_copy${counter}`;
                        }
                        const newScenario = { ...originalScenario, name: newName };
                        scenarios.splice(index + 1, 0, newScenario); // Insert copy below original
                        setMessage(`Scenario "${originalScenario.name}" copied as "${newName}". Click "Save All Changes" to make it permanent.`, false, true);
                        currentlyEditingIndex = null; // Close edit forms
                        renderScenariosList();
                    }
                }

                function deleteScenario(index, event) {
                    event.stopPropagation();
                    if (scenarios[index] && confirm(`Are you sure you want to delete the scenario "${scenarios[index].name}"? This action is temporary until you save.`)) {
                        const deletedName = scenarios[index].name;
                        scenarios.splice(index, 1);
                        setMessage(`Scenario "${deletedName}" deleted locally. Click "Save All Changes" to make it permanent.`, false, true);
                        if (currentlyEditingIndex === index) {
                            currentlyEditingIndex = null; // Close editor if it was the deleted one
                        } else if (currentlyEditingIndex > index) {
                            currentlyEditingIndex--; // Adjust index if an item before it was deleted
                        }
                        renderScenariosList();
                    }
                }

                // --- Utility Functions ---

                function setMessage(message, isError = false, isInfo = false) {
                    const messageArea = document.getElementById('messageArea');
                    messageArea.textContent = message;
                    let className = 'success-message'; // Default to success
                    if (isError) className = 'error-message';
                    else if (isInfo) className = 'info-message';
                    messageArea.className = className; // Set the class
                    messageArea.style.display = message ? 'block' : 'none'; // Show/hide
                }

                function escapeHtml(unsafe) {
                    if (unsafe === null || typeof unsafe === 'undefined') return '';
                    return String(unsafe)
                        .replace(/&/g, "&amp;") // Must be first
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;")
                        .replace(/'/g, "&#039;");
                }

                // --- Initial Load ---
                document.addEventListener('DOMContentLoaded', fetchScenarios);

            </script>
        </body>
        </html>
        """
    try:
        with open(MANAGEMENT_HTML_FILE, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Created default management UI file: {MANAGEMENT_HTML_FILE}")
    except IOError as e:
        print(f"Error creating default management UI file: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    try:
        load_config()
        load_scenarios()
        run_server()
    except KeyboardInterrupt:
        print("\nServer stopped by user (Ctrl+C).")
    except Exception as e:
        print(f"\n--- Critical Error ---")
        print(f"An unexpected error occurred: {str(e)}")
        import traceback
        traceback.print_exc()