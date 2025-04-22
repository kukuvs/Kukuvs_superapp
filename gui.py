import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import json

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("System Monitor")
        self.geometry("900x700")
        self.server_address = ('localhost', 12345)
        self.create_widgets()

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill='both')

        # Вкладка Процессы
        self.process_frame = ttk.Frame(notebook)
        notebook.add(self.process_frame, text="Processes")
        self.create_process_tab()

        # Вкладка Сетевые настройки
        self.network_frame = ttk.Frame(notebook)
        notebook.add(self.network_frame, text="Network Config")
        self.create_network_tab()

        # Вкладка Беспроводной статус
        self.wireless_frame = ttk.Frame(notebook)
        notebook.add(self.wireless_frame, text="Wireless Status")
        self.create_wireless_tab()

        # Вкладка Разрешение экрана
        self.screen_frame = ttk.Frame(notebook)
        notebook.add(self.screen_frame, text="Screen Resolution")
        self.create_screen_tab()

        # Вкладка Терминал
        self.terminal_frame = ttk.Frame(notebook)
        notebook.add(self.terminal_frame, text="Terminal")
        self.create_terminal_tab()

    def create_process_tab(self):
        btn = ttk.Button(self.process_frame, text="Get Processes", command=self.get_processes)
        btn.pack(pady=5)

        columns = ("pid", "name", "username")
        self.process_table = ttk.Treeview(self.process_frame, columns=columns, show='headings')
        self.process_table.heading("pid", text="PID")
        self.process_table.heading("name", text="Name")
        self.process_table.heading("username", text="User")
        self.process_table.column("pid", width=80, anchor='center')
        self.process_table.column("name", width=300)
        self.process_table.column("username", width=200)
        self.process_table.pack(expand=True, fill='both', padx=10, pady=10)

        # Добавим скроллбар
        scrollbar = ttk.Scrollbar(self.process_frame, orient="vertical", command=self.process_table.yview)
        self.process_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

    def create_network_tab(self):
        btn = ttk.Button(self.network_frame, text="Get Network Config", command=self.get_network_config)
        btn.pack(pady=5)

        self.network_text = scrolledtext.ScrolledText(self.network_frame, wrap=tk.WORD)
        self.network_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_wireless_tab(self):
        btn = ttk.Button(self.wireless_frame, text="Get Wireless Status", command=self.get_wireless_status)
        btn.pack(pady=5)

        self.wireless_text = scrolledtext.ScrolledText(self.wireless_frame, wrap=tk.WORD)
        self.wireless_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_screen_tab(self):
        btn = ttk.Button(self.screen_frame, text="Get Screen Resolution", command=self.get_screen_resolution)
        btn.pack(pady=5)

        self.screen_label = ttk.Label(self.screen_frame, text="", font=("Arial", 14))
        self.screen_label.pack(pady=20)

    def create_terminal_tab(self):
        label = ttk.Label(self.terminal_frame, text="Enter Command:")
        label.pack(pady=5)

        self.command_entry = ttk.Entry(self.terminal_frame, width=80)
        self.command_entry.pack(pady=5)

        run_btn = ttk.Button(self.terminal_frame, text="Run Command", command=self.run_command)
        run_btn.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.terminal_frame, wrap=tk.WORD)
        self.output_text.pack(expand=True, fill='both', padx=10, pady=10)

    def send_request(self, command, data=None):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(self.server_address)
                request_data = {'command': command}
                if data:
                    request_data['data'] = data
                sock.sendall(json.dumps(request_data, ensure_ascii=False).encode('utf-8'))

                chunks = []
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                response_bytes = b''.join(chunks)
                response_str = response_bytes.decode('utf-8')
                return json.loads(response_str)
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response'}
        except Exception as e:
            return {'error': str(e)}

    def get_processes(self):
        response = self.send_request('get_processes')
        if 'error' in response:
            self.show_error(self.process_table, response['error'])
            return
        # Очистим таблицу
        for row in self.process_table.get_children():
            self.process_table.delete(row)
        # Добавим новые данные
        for proc in response:
            pid = proc.get('pid', '')
            name = proc.get('name', '')
            user = proc.get('username', '')
            self.process_table.insert('', 'end', values=(pid, name, user))

    def get_network_config(self):
        response = self.send_request('get_network_config')
        if 'error' in response:
            self.network_text.delete(1.0, tk.END)
            self.network_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.network_text.delete(1.0, tk.END)
        # response - строка с выводом ipconfig/ifconfig
        self.network_text.insert(tk.END, response)

    def get_wireless_status(self):
        response = self.send_request('get_wireless_status')
        if 'error' in response:
            self.wireless_text.delete(1.0, tk.END)
            self.wireless_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.wireless_text.delete(1.0, tk.END)
        # response - словарь с интерфейсами и статусами
        import pprint
        pretty = pprint.pformat(response, indent=2, width=80)
        self.wireless_text.insert(tk.END, pretty)

    def get_screen_resolution(self):
        response = self.send_request('get_screen_resolution')
        if 'error' in response:
            self.screen_label.config(text=f"Error: {response['error']}")
            return
        # response - кортеж (width, height)
        self.screen_label.config(text=f"Screen resolution: {response[0]} x {response[1]}")

    def run_command(self):
        command = self.command_entry.get()
        response = self.send_request('execute_command', data=command)
        self.output_text.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.output_text.insert(tk.END, f"Error: {response['error']}")
        else:
            self.output_text.insert(tk.END, response)

    def show_error(self, widget, message):
        if isinstance(widget, ttk.Treeview):
            for row in widget.get_children():
                widget.delete(row)
            widget.insert('', 'end', values=(message,))
        else:
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, message)

if __name__ == "__main__":
    app = App()
    app.mainloop()
