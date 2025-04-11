import http.server
import socketserver
import ssl
import json
import os
from urllib.parse import urlparse, parse_qs
from http import HTTPStatus

# Konfigurační soubor
CONFIG_FILE = "config.json"
# Výstupní soubor pro JSON data
OUTPUT_FILE = "actualRequest.json"

# Načtení konfigurace
def load_config():
    if not os.path.exists(CONFIG_FILE):
        # Vytvoření výchozí konfigurace
        default_config = {
            "api_key": "vas_tajny_klic",
            "port": 8443,
            "cert_file": "server.crt",
            "key_file": "server.key"
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)
        print(f"Vytvořen výchozí konfigurační soubor {CONFIG_FILE}")
        return default_config
    
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# Handler pro HTTP požadavky
class APIHandler(http.server.SimpleHTTPRequestHandler):
    def send_response_content(self, status_code, content_type, content):
        self.send_response(status_code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.end_headers()
        
        # Zajistíme, že obsah je v bytes s UTF-8 kódováním
        if isinstance(content, str):
            content = content.encode('utf-8')
        self.wfile.write(content)

    def do_GET(self):
        self.send_response_content(
            HTTPStatus.OK, 
            "text/html", 
            "API Server je funkční. Použijte POST požadavek pro zaslání dat."
        )

    def send_error(self, code, message=None, explain=None):
        """Přepisujeme send_error, abychom zajistili správné kódování UTF-8"""
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        
        error_message = f"Chyba {code}: {message if message else http.server.BaseHTTPRequestHandler.responses[code][0]}"
        self.wfile.write(error_message.encode('utf-8'))

    def do_POST(self):
        config = load_config()
        expected_api_key = config["api_key"]
        
        # Kontrola, zda je cesta /api
        if not self.path.startswith('/api'):
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint nenalezen")
            return
        
        # Získání délky obsahu
        content_length = int(self.headers['Content-Length'])
        # Čtení dat
        post_data = self.rfile.read(content_length)
        
        try:
            # Parsování JSON dat
            json_data = json.loads(post_data.decode('utf-8'))
            
            # Kontrola API klíče
            if 'compControlAPIKey' not in json_data or json_data['compControlAPIKey'] != expected_api_key:
                self.send_error(HTTPStatus.UNAUTHORIZED, "Neplatný API klíč")
                return
            
            # Odstranění API klíče z dat před uložením
            json_data_to_save = {k: v for k, v in json_data.items() if k != 'compControlAPIKey'}
            
            # Uložení dat do souboru
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(json_data_to_save, f, indent=4, ensure_ascii=False)
            
            # Odpověď klientovi
            response_data = {"status": "success", "message": "Data byla úspěšně uložena"}
            self.send_response_content(
                HTTPStatus.OK,
                "application/json",
                json.dumps(response_data, ensure_ascii=False)
            )
            
            print(f"Data přijata a uložena do {OUTPUT_FILE}")
            
        except json.JSONDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Neplatný JSON formát")
        except Exception as e:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Chyba: {str(e)}")

def run_server():
    config = load_config()
    port = config.get("port", 8443)
    cert_file = config.get("cert_file", "server.crt")
    key_file = config.get("key_file", "server.key")

    # Kontrola existence certifikátu a klíče
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("VAROVÁNÍ: Certifikát nebo klíč nenalezen!")
        print("Pro vytvoření self-signed certifikátu použijte příkaz:")
        print(f"openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} -days 365 -nodes")
        return

    handler = APIHandler
    # Povolení přijímání požadavků z lokální sítě (0.0.0.0)
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    
    # Nastavení HTTPS
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile=cert_file,
        keyfile=key_file,
        ssl_version=ssl.PROTOCOL_TLS
    )
    
    print(f"Server běží na https://localhost:{port} a je přístupný z lokální sítě")
    httpd.serve_forever()

if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("\nServer byl ukončen")
    except Exception as e:
        print(f"Chyba: {str(e)}")