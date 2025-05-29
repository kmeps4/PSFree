import sys
import socket
import os
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import json
from datetime import datetime
import hashlib
import urllib.request
import re

console = Console()

# Configuration for manifest generation
EXCLUDED_DIRS = {'.venv', '.git', 'noneed'}
EXCLUDED_EXTENSIONS = {
    '.bat', '.txt', '.exe', '.mp4', '.py', '.bak', '.zip',
    '.mp3', '.sh', '.h', '.c', '.o', '.ld', '.md', '.d'
}
EXCLUDED_FILES = {'.gitignore', 'COPYING', 'LICENSE', 'MAKEFILE', 'dockerfile'}
OUTPUT_FILE = 'PSFree.manifest'

def get_machine_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't have to be reachable
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def is_docker():
    # Check for .dockerenv file
    if os.path.exists('/.dockerenv'):
        return True
    # Check cgroup info for docker
    try:
        with open('/proc/1/cgroup', 'rt') as f:
            return 'docker' in f.read() or 'kubepods' in f.read()
    except Exception:
        return False

def get_host_ip():
    try:
        # Try resolving Docker internal host (works on Docker Desktop and configured Linux setups)
        host_ip = socket.gethostbyname('host.docker.internal')
        return host_ip
    except socket.error:
        # Fallback if not resolved, may use default gateway IP (requires extra code) or local IP
        return 'Could not determine host IP'

def get_ipv4():
    if is_docker():
        ip = get_host_ip()
        if ip:
            print(f"Running inside Docker. Host IPv4: {ip}")
        else:
            print("Running inside Docker, but could not resolve host.docker.internal.")
    else:
        ip = get_machine_ip()
        print(f"Not in Docker. Machine IPv4: {ip}")
    return ip

def create_manifest():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    manifest_path = os.path.join(root_dir, OUTPUT_FILE)
    with open(manifest_path, 'w', encoding='utf-8') as f:
        # Write header
        f.write("CACHE MANIFEST\n")
        f.write(f"# v1\n")
        f.write(f"# Generated on {datetime.now()}\n\n")
        f.write("CACHE:\n")
        # Walk through all files
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Remove excluded directories (modifies the dirnames list in-place)
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                relpath = os.path.relpath(filepath, root_dir)
                # Skip excluded files, extensions and the manifest file itself
                ext = os.path.splitext(filename)[1].lower()
                if (ext in EXCLUDED_EXTENSIONS or
                    filename in EXCLUDED_FILES or
                    filename == OUTPUT_FILE):
                    continue
                # Write relative path to manifest
                f.write(f"{relpath.replace(os.sep, '/')}\n")
        # Write network section
        f.write("\nNETWORK:\n")
        f.write("*\n")


class CustomHandler(SimpleHTTPRequestHandler):

    def do_POST(self):
        if self.path == '/generate_manifest':
            try:
                create_manifest()
                response = {
                    'status': 'success',
                    'message': f'{OUTPUT_FILE} created successfully.\nThe cache has been updated, Please refresh the page.'
                }
                self.send_response(200)
            except Exception as e:
                response = {
                    'status': 'error',
                    'message': f"{str(e)}\nThis option only works on local server!\nPlease make sure your server is up."
                }
                self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))

        elif self.path == '/update_exploit':
            root_dir = os.path.abspath(os.path.dirname(__file__))
            files_to_update = [
                ("psfree/lapse.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/refs/heads/main/lapse.mjs"),
                ("psfree/psfree.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/refs/heads/main/psfree.mjs"),
                ("psfree/config.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/refs/heads/main/config.mjs"),
                ("psfree/send.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/refs/heads/main/send.mjs"),
                ("psfree/kpatch/900.elf", "https://raw.githubusercontent.com/kmeps4/PSFree/main/kpatch/900.elf"),
                ("psfree/rop/900.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/rop/900.mjs"),
                #("module/chain.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/chain.mjs"),
                ("psfree/module/constants.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/constants.mjs"),
                ("psfree/module/int64.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/int64.mjs"),
                ("psfree/module/mem.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/mem.mjs"),
                ("psfree/module/memtools.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/memtools.mjs"),
                ("psfree/module/offset.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/offset.mjs"),
                ("psfree/module/rw.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/rw.mjs"),
                ("psfree/module/utils.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/utils.mjs"),
                #("module/view.mjs", "https://raw.githubusercontent.com/kmeps4/PSFree/main/module/view.mjs")
            ]
            results = []

            #def file_hash(data):
            #    return hashlib.sha256(data).hexdigest()

            def is_mjs_file(filename):
                return filename.lower().endswith('.mjs')

            for local_rel_path, url in files_to_update:
                try:
                    abs_local_path = os.path.abspath(os.path.join(root_dir, local_rel_path))
                    if not abs_local_path.startswith(root_dir):
                        raise ValueError(f"Invalid path {local_rel_path}")

                    # Attempt to download file
                    try:
                        with urllib.request.urlopen(url) as response:
                            raw_data = response.read()
                    except Exception as download_error:
                        results.append(f"{local_rel_path}: download failed ({download_error})")
                        continue  # skip to next file

                    # If .mjs file, decode, replace strings using regex, then encode back
                    if is_mjs_file(local_rel_path):
                        text_data = raw_data.decode('utf-8')
                        text_data = re.sub(r'(?<!\.)\./kpatch\b', './psfree/kpatch', text_data)
                        text_data = re.sub(r'(?<!\.)\./module\b', './module', text_data)
                        text_data = re.sub(r'(?<!\.)\./rop\b', '../rop', text_data)
                        text_data = text_data.replace('alert("kernel exploit succeeded!");', '//alert("kernel exploit succeeded!");')
                        text_data = text_data.replace("const textarea = document.createElement('textarea');", "const textarea = document.createElement('textarea');\n       textarea.style.opacity = '0'; // Set the opacity to 0")
                        text_data = text_data.replace("const fset = document.createElement('frameset');", "const fset = document.createElement('frameset');\n           fset.style.opacity = '0'; // Set the opacity to 0")
                        text_data = text_data.replace("const input = document.createElement('input');", "const input = document.createElement('input');\n    input.style.opacity = '0'; // Set the opacity to 0")
                        text_data = text_data.replace("const foo = document.createElement('input');", "const foo = document.createElement('input');\n    foo.style.opacity = '0'; // Set the opacity to 0")
                        text_data = text_data.replace("const bar = document.createElement('a');", "const bar = document.createElement('a');\n    bar.style.opacity = '0'; // Set the opacity to 0")
                        new_data = text_data.encode('utf-8')
                    else:
                        new_data = raw_data

                    # Read old file content if exists
                    old_data = b""
                    if os.path.exists(abs_local_path):
                        with open(abs_local_path, 'rb') as f:
                            old_data = f.read()

                    # Compare hashes and write if different (need to be fixed)
                    #if file_hash(new_data) != file_hash(old_data):
                    #    os.makedirs(os.path.dirname(abs_local_path), exist_ok=True)
                    #    with open(abs_local_path, 'wb') as f:
                    #        f.write(new_data)
                    #    results.append(f"{local_rel_path}: updated")
                    #else:
                    #    results.append(f"{local_rel_path}: skipped (no change)")
                        
                    os.makedirs(os.path.dirname(abs_local_path), exist_ok=True)
                    with open(abs_local_path, 'wb') as f:
                            f.write(new_data)
                    results.append(f"{local_rel_path}: updated")

                except Exception as e:
                    results.append(f"{local_rel_path}: error ({e})")

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'results': results}).encode('utf-8'))

        else:
            # existing 404
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')


PORT = 52721
IP = get_ipv4()

if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        console.print("[bold red]Usage:[/] python serve.py [port]", style="red")
        sys.exit(1)

console.print(Panel(Text("Simple Python HTTP Server", style="bold white on blue"),
                    subtitle="Press [bold yellow]Ctrl+C[/] to stop the server", expand=False))

console.print(
    f"[green]Server is running![/]\n"
    f"Listening on [bold magenta]http://{IP}:{PORT}/PSFree[/]\n",
    style="bold",
)

try:
    with TCPServer(("0.0.0.0", PORT), CustomHandler) as httpd:
        httpd.serve_forever()
except KeyboardInterrupt:
    console.print("\n[bold red]Server stopped by user.[/]")
except OSError as e:
    console.print(f"[bold red]Error:[/] {e}")