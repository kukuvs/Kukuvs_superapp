import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import multiprocessing

SERVER_ADDRESS = ('localhost', 12345)

def popup_process():
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
    import socket
    import json

    class PopupApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Popup Process Report")
            self.geometry("600x400")
            self.create_widgets()
            self.refresh_report()

        def create_widgets(self):
            self.text = scrolledtext.ScrolledText(self, wrap=tk.WORD)
            self.text.pack(expand=True, fill='both', padx=10, pady=10)
            btn_frame = ttk.Frame(self)
            btn_frame.pack(pady=5)
            refresh_btn = ttk.Button(btn_frame, text="Обновить", command=self.refresh_report)
            refresh_btn.pack(side='left', padx=5)
            save_btn = ttk.Button(btn_frame, text="Сохранить в файл", command=self.save_report)
            save_btn.pack(side='left', padx=5)

        def send_request(self, command, data=None):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(SERVER_ADDRESS)
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
            except Exception as e:
                return {'error': str(e)}

        def refresh_report(self):
            response = self.send_request('get_tracked_processes_report')
            self.text.delete(1.0, tk.END)
            if isinstance(response, dict) and 'error' in response:
                self.text.insert(tk.END, f"Ошибка: {response['error']}")
                return
            for proc in response:
                self.text.insert(tk.END, f"Process: {proc['name']}, Start Time: {proc['start_time']}\n")

        def save_report(self):
            filename = "popup_process_report.txt"
            response = self.send_request('save_process_report', data=filename)
            messagebox.showinfo("Сохранение", response)

    app = PopupApp()
    app.mainloop()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("System Monitor")
        self.geometry("900x700")
        self.server_address = SERVER_ADDRESS
        self.detached_tabs = {}  # key: tab_text, value: (frame, index, window)
        self.create_widgets()
        self.create_menu()
        self.bind_hotkeys()

    def create_menu(self):
        menubar = tk.Menu(self)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Горячие клавиши", command=self.show_hotkeys)
        helpmenu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=helpmenu)
        self.config(menu=menubar)

    def show_about(self):
        about_text = "Бахметьев Д.А ПРИ-33"
        messagebox.showinfo("О программе", about_text)

    def show_hotkeys(self):
        hotkeys_text = (
            "Горячие клавиши:\n"
            "Ctrl+P - Получить процессы\n"
            "Ctrl+N - Получить сетевые настройки\n"
            "Ctrl+W - Получить статус беспроводных интерфейсов\n"
            "Ctrl+S - Получить разрешение экрана\n"
            "Ctrl+T - Открыть терминал\n"
        )
        messagebox.showinfo("Горячие клавиши", hotkeys_text)

    def bind_hotkeys(self):
        self.bind_all("<Control-p>", lambda e: self.hotkey_get_processes())
        self.bind_all("<Control-n>", lambda e: self.hotkey_get_network_config())
        self.bind_all("<Control-w>", lambda e: self.hotkey_get_wireless_status())
        self.bind_all("<Control-s>", lambda e: self.hotkey_get_screen_resolution())
        self.bind_all("<Control-t>", lambda e: self.hotkey_show_terminal_tab())

    def hotkey_get_processes(self):
        idx = self.notebook.index(self.process_frame)
        self.notebook.select(idx)
        self.get_processes()

    def hotkey_get_network_config(self):
        idx = self.notebook.index(self.network_frame)
        self.notebook.select(idx)
        self.get_network_config()

    def hotkey_get_wireless_status(self):
        idx = self.notebook.index(self.wireless_frame)
        self.notebook.select(idx)
        self.get_wireless_status()

    def hotkey_get_screen_resolution(self):
        idx = self.notebook.index(self.screen_frame)
        self.notebook.select(idx)
        self.get_screen_resolution()

    def hotkey_show_terminal_tab(self):
        idx = self.notebook.index(self.terminal_frame)
        self.notebook.select(idx)
        self.command_entry.focus_set()

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill='both')

        # Создаем вкладки и добавляем их в notebook
        self.process_frame = ttk.Frame(notebook)
        notebook.add(self.process_frame, text="Processes")
        self.create_process_tab()

        self.network_frame = ttk.Frame(notebook)
        notebook.add(self.network_frame, text="Network Config")
        self.create_network_tab()

        self.wireless_frame = ttk.Frame(notebook)
        notebook.add(self.wireless_frame, text="Wireless Status")
        self.create_wireless_tab()

        self.screen_frame = ttk.Frame(notebook)
        notebook.add(self.screen_frame, text="Screen Resolution")
        self.create_screen_tab()

        self.terminal_frame = ttk.Frame(notebook)
        notebook.add(self.terminal_frame, text="Terminal")
        self.create_terminal_tab()

        self.removable_frame = ttk.Frame(notebook)
        notebook.add(self.removable_frame, text="Removable Drives")
        self.create_removable_tab()

        self.notebook = notebook

    def create_process_tab(self):
        btn_frame = ttk.Frame(self.process_frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Processes", command=self.get_processes).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save Report", command=self.save_process_report).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Open Popup Window", command=self.open_popup_window).pack(side='left', padx=5)

        detach_btn = ttk.Button(btn_frame, text="⇱", width=3, command=self.open_detached_processes_window)
        detach_btn.pack(side='left', padx=5)

        columns = ("pid", "name", "username", "start_time")
        self.process_table = ttk.Treeview(self.process_frame, columns=columns, show='headings')
        for col, text, width in zip(columns, ("PID", "Name", "User", "Start Time"), (80, 250, 150, 150)):
            self.process_table.heading(col, text=text)
            self.process_table.column(col, width=width, anchor='center' if col == "pid" else 'w')
        self.process_table.pack(expand=True, fill='both', padx=10, pady=10)

        scrollbar = ttk.Scrollbar(self.process_frame, orient="vertical", command=self.process_table.yview)
        self.process_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

    def create_network_tab(self):
        btn_frame = ttk.Frame(self.network_frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Network Config", command=self.get_network_config).pack(side='left', padx=5)
        detach_btn = ttk.Button(btn_frame, text="⇱", width=3, command=self.open_detached_network_config_window)
        detach_btn.pack(side='left', padx=5)

        self.network_text = scrolledtext.ScrolledText(self.network_frame, wrap=tk.WORD)
        self.network_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_wireless_tab(self):
        btn_frame = ttk.Frame(self.wireless_frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Wireless Status", command=self.get_wireless_status).pack(side='left', padx=5)
        detach_btn = ttk.Button(btn_frame, text="⇱", width=3, command=lambda: self.detach_tab("Wireless Status", self.wireless_frame))
        detach_btn.pack(side='left', padx=5)

        self.wireless_text = scrolledtext.ScrolledText(self.wireless_frame, wrap=tk.WORD)
        self.wireless_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_screen_tab(self):
        btn_frame = ttk.Frame(self.screen_frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Screen Resolution", command=self.get_screen_resolution).pack(side='left', padx=5)
        detach_btn = ttk.Button(btn_frame, text="⇱", width=3, command=lambda: self.detach_tab("Screen Resolution", self.screen_frame))
        detach_btn.pack(side='left', padx=5)

        self.screen_label = ttk.Label(self.screen_frame, text="", font=("Arial", 14))
        self.screen_label.pack(pady=20)

    def create_terminal_tab(self):
        btn_frame = ttk.Frame(self.terminal_frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Label(btn_frame, text="Enter Command:").pack(side='left', padx=5)
        self.command_entry = ttk.Entry(btn_frame, width=60)
        self.command_entry.pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Run Command", command=self.run_command).pack(side='left', padx=5)

        detach_btn = ttk.Button(btn_frame, text="⇱", width=3, command=lambda: self.detach_tab("Terminal", self.terminal_frame))
        detach_btn.pack(side='left', padx=5)

        self.output_text = scrolledtext.ScrolledText(self.terminal_frame, wrap=tk.WORD)
        self.output_text.pack(expand=True, fill='both', padx=10, pady=10)

    def create_removable_tab(self):
        btn_frame = ttk.Frame(self.removable_frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Removable Drives", command=self.get_removable_drives).pack(side='left', padx=5)
        detach_btn = ttk.Button(btn_frame, text="⇱", width=3, command=lambda: self.detach_tab("Removable Drives", self.removable_frame))
        detach_btn.pack(side='left', padx=5)

        self.removable_text = scrolledtext.ScrolledText(self.removable_frame, wrap=tk.WORD)
        self.removable_text.pack(expand=True, fill='both', padx=10, pady=10)

    def get_tab_index(self, frame):
        for i in range(self.notebook.index("end")):
            if self.notebook.nametowidget(self.notebook.tabs()[i]) == frame:
                return i
        return None

    def detach_tab(self, tab_text, frame):
        if tab_text in self.detached_tabs:
            messagebox.showinfo("Info", f"Вкладка '{tab_text}' уже вынесена в отдельное окно.")
            return

        idx = self.get_tab_index(frame)
        if idx is None:
            # Вкладка не найдена, возможно уже отделена
            return

        # Удаляем вкладку из notebook
        self.notebook.forget(idx)

        # Создаем новое окно
        new_window = tk.Toplevel(self)
        new_window.title(tab_text)
        new_window.geometry("900x700")

        # Перемещаем frame в новое окно
        frame.pack_forget()
        frame.master = new_window
        frame.pack(expand=True, fill='both')

        self.detached_tabs[tab_text] = (frame, idx, new_window)

        def on_close():
            frame.pack_forget()
            frame.master = self.notebook
            max_index = self.notebook.index("end")
            insert_index = idx if idx <= max_index else max_index
            self.notebook.insert(insert_index, frame, text=tab_text)
            del self.detached_tabs[tab_text]
            new_window.destroy()

        new_window.protocol("WM_DELETE_WINDOW", on_close)

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
        for row in self.process_table.get_children():
            self.process_table.delete(row)
        for proc in response:
            pid = proc.get('pid', '')
            name = proc.get('name', '')
            user = proc.get('username', '')
            start_time = proc.get('create_time', '')
            self.process_table.insert('', 'end', values=(pid, name, user, start_time))

    def save_process_report(self):
        filename = "process_report.txt"
        response = self.send_request('save_process_report', data=filename)
        messagebox.showinfo("Сохранение отчета", response)

    def open_popup_window(self):
        p = multiprocessing.Process(target=popup_process)
        p.daemon = True
        p.start()

    def get_network_config(self):
        response = self.send_request('get_network_config')
        if 'error' in response:
            self.network_text.delete(1.0, tk.END)
            self.network_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.network_text.delete(1.0, tk.END)
        self.network_text.insert(tk.END, response)

    def get_wireless_status(self):
        response = self.send_request('get_wireless_status')
        if 'error' in response:
            self.wireless_text.delete(1.0, tk.END)
            self.wireless_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.wireless_text.delete(1.0, tk.END)
        import pprint
        pretty = pprint.pformat(response, indent=2, width=80)
        self.wireless_text.insert(tk.END, pretty)

    def get_screen_resolution(self):
        response = self.send_request('get_screen_resolution')
        if 'error' in response:
            self.screen_label.config(text=f"Error: {response['error']}")
            return
        self.screen_label.config(text=f"Screen resolution: {response[0]} x {response[1]}")

    def run_command(self):
        command = self.command_entry.get()
        response = self.send_request('linux_terminal', data=command)
        self.output_text.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.output_text.insert(tk.END, f"Error: {response['error']}")
        else:
            self.output_text.insert(tk.END, response)

    def get_removable_drives(self):
        response = self.send_request('get_removable_drives')
        if 'error' in response:
            self.removable_text.delete(1.0, tk.END)
            self.removable_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.removable_text.delete(1.0, tk.END)
        if not response:
            self.removable_text.insert(tk.END, "Съемные носители не найдены.")
            return
        for drive in response:
            self.removable_text.insert(tk.END, f"Device: {drive['device']}\nMountpoint: {drive['mountpoint']}\nFstype: {drive['fstype']}\nOpts: {drive['opts']}\n\n")

    def show_error(self, widget, message):
        if isinstance(widget, ttk.Treeview):
            for row in widget.get_children():
                widget.delete(row)
            widget.insert('', 'end', values=(message,))
        else:
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, message)

    def show_terminal_tab(self):
        idx = self.notebook.index(self.terminal_frame)
        self.notebook.select(idx)

    def open_detached_processes_window(self):
        new_win = tk.Toplevel(self)
        new_win.title("Processes (отдельное окно)")
        new_win.geometry("900x700")

        frame = ttk.Frame(new_win)
        frame.pack(expand=True, fill='both')

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Processes", command=lambda: self.get_processes_detached(tree)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save Report", command=self.save_process_report).pack(side='left', padx=5)

        columns = ("pid", "name", "username", "start_time")
        tree = ttk.Treeview(frame, columns=columns, show='headings')
        for col, text, width in zip(columns, ("PID", "Name", "User", "Start Time"), (80, 250, 150, 150)):
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor='center' if col == "pid" else 'w')
        tree.pack(expand=True, fill='both', padx=10, pady=10)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        self.get_processes_detached(tree)

    def get_processes_detached(self, tree):
        response = self.send_request('get_processes')
        if 'error' in response:
            for row in tree.get_children():
                tree.delete(row)
            tree.insert('', 'end', values=(response['error'],))
            return
        for row in tree.get_children():
            tree.delete(row)
        for proc in response:
            pid = proc.get('pid', '')
            name = proc.get('name', '')
            user = proc.get('username', '')
            start_time = proc.get('create_time', '')
            tree.insert('', 'end', values=(pid, name, user, start_time))


    def open_detached_network_config_window(self):
        new_win = tk.Toplevel(self)
        new_win.title("Network Config (отдельное окно)")
        new_win.geometry("900x700")

        frame = ttk.Frame(new_win)
        frame.pack(expand=True, fill='both')

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Network Config", command=self.get_network_config_detached).pack(side='left', padx=5)

        self.network_text_detached = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.network_text_detached.pack(expand=True, fill='both', padx=10, pady=10)

        self.get_network_config_detached()

    def get_network_config_detached(self):
        response = self.send_request('get_network_config')
        if 'error' in response:
            self.network_text_detached.delete(1.0, tk.END)
            self.network_text_detached.insert(tk.END, f"Error: {response['error']}")
            return
        self.network_text_detached.delete(1.0, tk.END)
        self.network_text_detached.insert(tk.END, response)


    def open_detached_wireless_status_window(self):
        new_win = tk.Toplevel(self)
        new_win.title("Wireless Status (отдельное окно)")
        new_win.geometry("900x700")

        frame = ttk.Frame(new_win)
        frame.pack(expand=True, fill='both')

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Wireless Status", command=self.get_wireless_status_detached).pack(side='left', padx=5)

        self.wireless_text_detached = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.wireless_text_detached.pack(expand=True, fill='both', padx=10, pady=10)

        self.get_wireless_status_detached()

    def get_wireless_status_detached(self):
        response = self.send_request('get_wireless_status')
        if 'error' in response:
            self.wireless_text_detached.delete(1.0, tk.END)
            self.wireless_text_detached.insert(tk.END, f"Error: {response['error']}")
            return
        import pprint
        pretty = pprint.pformat(response, indent=2, width=80)
        self.wireless_text_detached.delete(1.0, tk.END)
        self.wireless_text_detached.insert(tk.END, pretty)


    def open_detached_screen_resolution_window(self):
        new_win = tk.Toplevel(self)
        new_win.title("Screen Resolution (отдельное окно)")
        new_win.geometry("400x200")

        frame = ttk.Frame(new_win)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Screen Resolution", command=self.get_screen_resolution_detached).pack(side='left', padx=5)

        self.screen_label_detached = ttk.Label(frame, text="", font=("Arial", 14))
        self.screen_label_detached.pack(pady=20)

        self.get_screen_resolution_detached()

    def get_screen_resolution_detached(self):
        response = self.send_request('get_screen_resolution')
        if 'error' in response:
            self.screen_label_detached.config(text=f"Error: {response['error']}")
            return
        self.screen_label_detached.config(text=f"Screen resolution: {response[0]} x {response[1]}")


    def open_detached_terminal_window(self):
        new_win = tk.Toplevel(self)
        new_win.title("Terminal (отдельное окно)")
        new_win.geometry("900x700")

        frame = ttk.Frame(new_win)
        frame.pack(expand=True, fill='both')

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Label(btn_frame, text="Enter Command:").pack(side='left', padx=5)

        self.command_entry_detached = ttk.Entry(btn_frame, width=60)
        self.command_entry_detached.pack(side='left', padx=5)

        ttk.Button(btn_frame, text="Run Command", command=self.run_command_detached).pack(side='left', padx=5)

        self.output_text_detached = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.output_text_detached.pack(expand=True, fill='both', padx=10, pady=10)

    def run_command_detached(self):
        command = self.command_entry_detached.get()
        response = self.send_request('linux_terminal', data=command)
        self.output_text_detached.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.output_text_detached.insert(tk.END, f"Error: {response['error']}")
        else:
            self.output_text_detached.insert(tk.END, response)


    def open_detached_removable_drives_window(self):
        new_win = tk.Toplevel(self)
        new_win.title("Removable Drives (отдельное окно)")
        new_win.geometry("900x700")

        frame = ttk.Frame(new_win)
        frame.pack(expand=True, fill='both')

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Removable Drives", command=self.get_removable_drives_detached).pack(side='left', padx=5)

        self.removable_text_detached = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.removable_text_detached.pack(expand=True, fill='both', padx=10, pady=10)

        self.get_removable_drives_detached()

    def get_removable_drives_detached(self):
        response = self.send_request('get_removable_drives')
        if 'error' in response:
            self.removable_text_detached.delete(1.0, tk.END)
            self.removable_text_detached.insert(tk.END, f"Error: {response['error']}")
            return
        self.removable_text_detached.delete(1.0, tk.END)
        if not response:
            self.removable_text_detached.insert(tk.END, "Съемные носители не найдены.")
            return
        for drive in response:
            self.removable_text_detached.insert(tk.END, f"Device: {drive['device']}\nMountpoint: {drive['mountpoint']}\nFstype: {drive['fstype']}\nOpts: {drive['opts']}\n\n")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = App()
    app.mainloop()
