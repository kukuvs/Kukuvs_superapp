import platform
import socket
import json
import psutil
import netifaces
import screeninfo
import subprocess

def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        processes.append(proc.info)
    return processes

def get_wireless_status():
    return psutil.net_if_stats()

def get_network_settings():
    return netifaces.interfaces()

def get_screen_resolution():
    screen = screeninfo.get_monitors()[0]
    return screen.width, screen.height

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Декодируем из cp866 (кодировка консоли Windows)
            output = result.stdout.decode('cp866')
        except UnicodeDecodeError:
            output = result.stdout.decode('cp866', errors='replace')
        return output
    except subprocess.CalledProcessError as e:
        try:
            error_output = e.stderr.decode('cp866')
        except UnicodeDecodeError:
            error_output = e.stderr.decode('cp866', errors='replace')
        return error_output



def handle_client(conn):
    try:
        data = conn.recv(4096).decode('utf-8')
        if not data:
            return
        request = json.loads(data)
        cmd = request.get('command')
        if cmd == 'get_processes':
            response = get_processes()
        elif cmd == 'get_wireless_status':
            response = get_wireless_status()
        elif cmd == 'get_network_settings':
            response = get_network_settings()
        elif cmd == 'get_screen_resolution':
            response = get_screen_resolution()
        elif cmd == 'execute_command':
            command = request.get('data', '')
            response = execute_command(command)
        elif cmd == 'get_network_config':
            response = get_network_config()
        else:
            response = {'error': 'Unknown command'}
        conn.sendall(json.dumps(response, ensure_ascii=False).encode('utf-8'))
    except json.JSONDecodeError:
        conn.sendall(json.dumps({'error': 'Invalid JSON'}, ensure_ascii=False).encode('utf-8'))
    except Exception as e:
        conn.sendall(json.dumps({'error': str(e)}, ensure_ascii=False).encode('utf-8'))
    finally:
        conn.close()



def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)
    print("Server started...")
    while True:
        try:
            conn, addr = server.accept()
            handle_client(conn)
        except Exception as e:
            print(f"Server error: {e}")
            
            
def get_network_config():
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = 'ipconfig /all'
            encoding = 'cp866'
        else:
            # Linux / MacOS
            # Попытаемся использовать ifconfig, если нет - ip addr
            try:
                subprocess.run(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                cmd = 'ifconfig -a'
            except Exception:
                cmd = 'ip addr'
            encoding = 'utf-8'

        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output = result.stdout.decode(encoding)
        except UnicodeDecodeError:
            output = result.stdout.decode(encoding, errors='replace')
        return output
    except Exception as e:
        return f"Error getting network config: {e}"

if __name__ == "__main__":
    start_server()
