import http.server
import socketserver
import ssl
import json
import os
from urllib.parse import urlparse, parse_qs
from http import HTTPStatus

# Config file
CONFIG_FILE = "config.json"
# Input JSON data file
OUTPUT_FILE = "actualRequest.json"

# Read config
def load_config():
    if not os.path.exists(CONFIG_FILE):
        # Create initial config file
        default_config = {
            "api_key": "your secret API key",
            "port": 8443,
            "cert_file": "server.crt",
            "key_file": "server.key"
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)
        print(f"Create initial config file {CONFIG_FILE}")
        return default_config
    
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# Handler for HTTP requests
class APIHandler(http.server.SimpleHTTPRequestHandler):
    def send_response_content(self, status_code, content_type, content):
        self.send_response(status_code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.end_headers()
        
        if isinstance(content, str):
            content = content.encode('utf-8')
        self.wfile.write(content)

    def do_GET(self):
        self.send_response_content(
            HTTPStatus.OK, 
            "text/html", 
            "API Server is running. Use POST request"
        )

    def send_error(self, code, message=None, explain=None):
        """Managing UTF-8"""
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        
        error_message = f"Error {code}: {message if message else http.server.BaseHTTPRequestHandler.responses[code][0]}"
        self.wfile.write(error_message.encode('utf-8'))

    def do_POST(self):
        config = load_config()
        expected_api_key = config["api_key"]
        
        # Check if path is /api
        if not self.path.startswith('/api'):
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")
            return
        
        # Get the length of data
        content_length = int(self.headers['Content-Length'])
        # Read data
        post_data = self.rfile.read(content_length)
        
        try:
            # Parse JSON data
            json_data = json.loads(post_data.decode('utf-8'))
            
            # Check API key
            if 'compControlAPIKey' not in json_data or json_data['compControlAPIKey'] != expected_api_key:
                self.send_error(HTTPStatus.UNAUTHORIZED, "Invalid API key")
                return
            
            # Remove API key from the JSON before store in file
            json_data_to_save = {k: v for k, v in json_data.items() if k != 'compControlAPIKey'}
            
            # Write data to file
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(json_data_to_save, f, indent=4, ensure_ascii=False)
            
            # Answer to client
            response_data = {"status": "success", "message": "Data successfully received and stored"}
            self.send_response_content(
                HTTPStatus.OK,
                "application/json",
                json.dumps(response_data, ensure_ascii=False)
            )
            
            print(f"Data received and stored in{OUTPUT_FILE}")
            
        except json.JSONDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON format")
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error: {str(e)}")

def run_server():
    config = load_config()
    port = config.get("port", 8443)
    cert_file = config.get("cert_file", "server.crt")
    key_file = config.get("key_file", "server.key")

    # Check if certificate exist
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("Varning: Certificate or key not found")
        print("To create self signed certificate use command:")
        print(f"openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} -days 365 -nodes")
        return

    handler = APIHandler
    # Allow to get requests from local network (0.0.0.0)
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    
    # Setting HTTPS
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile=cert_file,
        keyfile=key_file,
        ssl_version=ssl.PROTOCOL_TLS
    )
    
    print(f"Server running on https://localhost:{port} and is available from local network")
    httpd.serve_forever()

if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("\nServer stopped")
    except Exception as e:
        print(f"Error: {str(e)}")