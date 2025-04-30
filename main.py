import platform
import socket
import json
import psutil
import netifaces
import screeninfo
import subprocess
import threading
import datetime

# Глобальный список для хранения процессов, запущенных во время работы приложения
tracked_processes = {}

# Лог-файл для сохранения отчетов
LOG_FILE = "process_report.log"

def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
        info = proc.info
        # Сохраняем процессы, запущенные во время работы приложения
        pid = info['pid']
        if pid not in tracked_processes:
            tracked_processes[pid] = info['create_time']
        processes.append({
            'pid': pid,
            'name': info['name'],
            'username': info['username'],
            'create_time': datetime.datetime.fromtimestamp(info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
        })
    return processes

def get_tracked_processes_report():
    # Возвращает список процессов, запущенных во время работы приложения (имя + время старта)
    report = []
    for pid, start_time in tracked_processes.items():
        try:
            p = psutil.Process(pid)
            report.append({
                'name': p.name(),
                'start_time': datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
            })
        except psutil.NoSuchProcess:
            # Процесс уже завершился
            continue
    return report

def save_report_to_file(report, filename="process_report.txt"):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for proc in report:
                f.write(f"Process: {proc['name']}, Start Time: {proc['start_time']}\n")
        return f"Отчет сохранен в {filename}"
    except Exception as e:
        return f"Ошибка при сохранении отчета: {e}"

def get_removable_drives():
    # Получаем список съемных носителей
    partitions = psutil.disk_partitions(all=False)
    removable = []
    for p in partitions:
        # В Windows съемные носители имеют opts с 'removable'
        # В Linux можно проверить через p.device или p.opts
        if 'removable' in p.opts or ('/media' in p.mountpoint) or ('/run/media' in p.mountpoint):
            removable.append({
                'device': p.device,
                'mountpoint': p.mountpoint,
                'fstype': p.fstype,
                'opts': p.opts
            })
    return removable

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

def get_network_config():
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = 'ipconfig /all'
            encoding = 'cp866'
        else:
            # Linux / MacOS
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

# Реализация простого командного интерпретатора Linux с 10 командами
def linux_terminal(command):
    commands = {
        'ls': 'ls -la',
        'pwd': 'pwd',
        'whoami': 'whoami',
        'date': 'date',
        'uptime': 'uptime',
        'df': 'df -h',
        'free': 'free -m',
        'ps': 'ps aux',
        'top': 'top -b -n 1',
        'uname': 'uname -a',
        'help': 'echo "Доступные команды: ls, pwd, whoami, date, uptime, df, free, ps, top, uname, help"'
    }
    cmd = command.strip().split()[0]
    if cmd not in commands:
        return f"Команда '{cmd}' не найдена. Введите 'help' для списка команд."
    # Выполняем команду
    try:
        result = subprocess.run(commands[cmd], shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8', errors='replace')
        return output
    except subprocess.CalledProcessError as e:
        return e.stderr.decode('utf-8', errors='replace')

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
        elif cmd == 'get_removable_drives':
            response = get_removable_drives()
        elif cmd == 'get_tracked_processes_report':
            response = get_tracked_processes_report()
        elif cmd == 'save_process_report':
            filename = request.get('data', 'process_report.txt')
            report = get_tracked_processes_report()
            response = save_report_to_file(report, filename)
        elif cmd == 'linux_terminal':
            command = request.get('data', '')
            response = linux_terminal(command)
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
            # Обработка клиента в отдельном потоке для параллельности
            client_thread = threading.Thread(target=handle_client, args=(conn,))
            client_thread.daemon = True
            client_thread.start()
        except Exception as e:
            print(f"Server error: {e}")

if __name__ == "__main__":
    start_server()
