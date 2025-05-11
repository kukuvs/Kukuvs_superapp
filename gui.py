import json
import multiprocessing
import os
import pprint
import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Optional, Dict, List, Union, Callable, Tuple

SERVER_ADDRESS = ('localhost', 12345)


class PopupWindow(tk.Tk):
    """Всплывающее окно с отчетом о процессах, запускается в отдельном процессе."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Popup Process Report")
        self.geometry("600x400")
        self._create_widgets()
        self.refresh_report()

    def _create_widgets(self) -> None:
        self.text = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.text.pack(expand=True, fill='both', padx=10, pady=10)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        self._add_button(btn_frame, "Обновить", self.refresh_report)
        self._add_button(btn_frame, "Сохранить в файл", self.save_report)

    def _add_button(self, parent: tk.Widget, text: str, command: Callable) -> None:
        btn = ttk.Button(parent, text=text, command=command)
        btn.pack(side='left', padx=5)

    def send_request(self, command: str, data: Optional[Any] = None) -> Union[Dict, List, str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(SERVER_ADDRESS)
                request_data = {'command': command}
                if data is not None:
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

    def refresh_report(self) -> None:
        response = self.send_request('get_tracked_processes_report')
        self.text.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.text.insert(tk.END, f"Ошибка: {response['error']}")
            return
        for proc in response:
            self.text.insert(tk.END, f"Process: {proc['name']}, Start Time: {proc['start_time']}\n")

    def save_report(self) -> None:
        filename = "popup_process_report.txt"
        response = self.send_request('save_process_report', data=filename)
        messagebox.showinfo("Сохранение", response)


def run_popup_window() -> None:
    """Функция запуска всплывающего окна в отдельном процессе."""
    app = PopupWindow()
    app.mainloop()


class App(tk.Tk):
    """Основное приложение с вкладками и функционалом."""

    def __init__(self) -> None:
        super().__init__()
        self.title("System Monitor")
        self.geometry("900x700")
        self.server_address = SERVER_ADDRESS
        self.detached_tabs: Dict[str, Tuple[tk.Widget, int, tk.Toplevel]] = {}

        self._create_widgets()
        self._create_menu()
        self._bind_hotkeys()

    def _create_menu(self) -> None:
        menubar = tk.Menu(self)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Горячие клавиши", command=self._show_hotkeys)
        helpmenu.add_command(label="О программе", command=self._show_about)
        menubar.add_cascade(label="Справка", menu=helpmenu)
        self.config(menu=menubar)

    def _show_about(self) -> None:
        messagebox.showinfo("О программе", "Бахметьев Д.А ПРИ-33")

    def _show_hotkeys(self) -> None:
        hotkeys_text = (
            "Горячие клавиши:\n"
            "Ctrl+P - Получить процессы\n"
            "Ctrl+N - Получить сетевые настройки\n"
            "Ctrl+W - Получить статус беспроводных интерфейсов\n"
            "Ctrl+S - Получить разрешение экрана\n"
            "Ctrl+T - Открыть терминал\n"
        )
        messagebox.showinfo("Горячие клавиши", hotkeys_text)

    def _bind_hotkeys(self) -> None:
        hotkey_map = {
            "<Control-p>": self._hotkey_get_processes,
            "<Control-n>": self._hotkey_get_network_config,
            "<Control-w>": self._hotkey_get_wireless_status,
            "<Control-s>": self._hotkey_get_screen_resolution,
            "<Control-t>": self._hotkey_show_terminal_tab,
        }
        for key, func in hotkey_map.items():
            self.bind_all(key, lambda e, f=func: f())

    def _hotkey_get_processes(self) -> None:
        self._select_tab(self.process_frame)
        self.get_processes()

    def _hotkey_get_network_config(self) -> None:
        self._select_tab(self.network_frame)
        self.get_network_config()

    def _hotkey_get_wireless_status(self) -> None:
        self._select_tab(self.wireless_frame)
        self.get_wireless_status()

    def _hotkey_get_screen_resolution(self) -> None:
        self._select_tab(self.screen_frame)
        self.get_screen_resolution()

    def _hotkey_show_terminal_tab(self) -> None:
        self._select_tab(self.terminal_frame)
        self.command_entry.focus_set()

    def _select_tab(self, frame: tk.Widget) -> None:
        idx = self.notebook.index(frame)
        self.notebook.select(idx)

    def _create_widgets(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        # Создаем вкладки и наполняем их
        self.process_frame = self._add_tab("Processes", self._create_process_tab)
        self.network_frame = self._add_tab("Network Config", self._create_network_tab)
        self.wireless_frame = self._add_tab("Wireless Status", self._create_wireless_tab)
        self.screen_frame = self._add_tab("Screen Resolution", self._create_screen_tab)
        self.terminal_frame = self._add_tab("Terminal", self._create_terminal_tab)
        self.removable_frame = self._add_tab("Removable Drives", self._create_removable_tab)
        self.file_manager_frame = self._add_tab("File Manager", self._create_file_manager_tab)

    def _add_tab(self, title: str, create_func: Callable[[tk.Widget], None]) -> ttk.Frame:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        create_func(frame)
        return frame

    def _add_detach_button(self, parent: tk.Widget, tab_name: str, frame: tk.Widget) -> None:
        btn = ttk.Button(parent, text="⇱", width=3, command=lambda: self.detach_tab(tab_name, frame))
        btn.pack(side='left', padx=5)

    def detach_tab(self, tab_text: str, frame: tk.Widget) -> None:
        if tab_text in self.detached_tabs:
            messagebox.showinfo("Info", f"Вкладка '{tab_text}' уже вынесена в отдельное окно.")
            return

        idx = self._get_tab_index(frame)
        if idx is None:
            return

        self.notebook.forget(idx)

        new_window = tk.Toplevel(self)
        new_window.title(tab_text)
        new_window.geometry("900x700")

        frame.pack_forget()
        frame.master = new_window
        frame.pack(expand=True, fill='both')

        self.detached_tabs[tab_text] = (frame, idx, new_window)

        def on_close() -> None:
            frame.pack_forget()
            frame.master = self.notebook
            max_index = self.notebook.index("end")
            insert_index = idx if idx <= max_index else max_index
            self.notebook.insert(insert_index, frame, text=tab_text)
            del self.detached_tabs[tab_text]
            new_window.destroy()

        new_window.protocol("WM_DELETE_WINDOW", on_close)

    def _get_tab_index(self, frame: tk.Widget) -> Optional[int]:
        for i in range(self.notebook.index("end")):
            if self.notebook.nametowidget(self.notebook.tabs()[i]) == frame:
                return i
        return None

    def open_detached_window(self, tab_name: str) -> None:
        """Открыть отдельное окно с функционалом вкладки, не удаляя вкладку из основного окна."""
        new_window = tk.Toplevel(self)
        new_window.title(f"{tab_name} (отдельное окно)")
        new_window.geometry("900x700")

        frame = ttk.Frame(new_window)
        frame.pack(expand=True, fill='both')

        # Вызовем соответствующий метод создания интерфейса для вкладки
        create_func_map = {
            "Processes": self._create_process_tab,
            "Network Config": self._create_network_tab,
            "Wireless Status": self._create_wireless_tab,
            "Screen Resolution": self._create_screen_tab,
            "Terminal": self._create_terminal_tab,
            "Removable Drives": self._create_removable_tab,
            "File Manager": self._create_file_manager_tab,
        }

        create_func = create_func_map.get(tab_name)
        if create_func:
            create_func(frame)
        else:
            ttk.Label(frame, text=f"Функционал для вкладки '{tab_name}' не реализован").pack(padx=10, pady=10)

    # --- Создание вкладок ---

    def _create_process_tab(self, frame: tk.Widget) -> None:
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Processes", command=self.get_processes).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save Report", command=self.save_process_report).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Open Popup Window", command=self.open_popup_window).pack(side='left', padx=5)

        # Кнопка открытия отдельного окна
        ttk.Button(btn_frame, text="Открыть в отдельном окне", command=lambda: self.open_detached_window("Processes")).pack(side='left', padx=5)

        columns = ("pid", "name", "username", "start_time")
        self.process_table = ttk.Treeview(frame, columns=columns, show='headings')
        for col, text, width in zip(columns, ("PID", "Name", "User", "Start Time"), (80, 250, 150, 150)):
            self.process_table.heading(col, text=text)
            self.process_table.column(col, width=width, anchor='center' if col == "pid" else 'w')
        self.process_table.pack(expand=True, fill='both', padx=10, pady=10)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.process_table.yview)
        self.process_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

    def _create_network_tab(self, frame: tk.Widget) -> None:
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Network Config", command=self.get_network_config).pack(side='left', padx=5)
        self._add_detach_button(btn_frame, "Network Config", frame)

        self.network_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.network_text.pack(expand=True, fill='both', padx=10, pady=10)

    def _create_wireless_tab(self, frame: tk.Widget) -> None:
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Wireless Status", command=self.get_wireless_status).pack(side='left', padx=5)
        self._add_detach_button(btn_frame, "Wireless Status", frame)

        self.wireless_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.wireless_text.pack(expand=True, fill='both', padx=10, pady=10)

    def _create_screen_tab(self, frame: tk.Widget) -> None:
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Screen Resolution", command=self.get_screen_resolution).pack(side='left', padx=5)
        self._add_detach_button(btn_frame, "Screen Resolution", frame)

        self.screen_label = ttk.Label(frame, text="", font=("Arial", 14))
        self.screen_label.pack(pady=20)

    def _create_terminal_tab(self, frame: tk.Widget) -> None:
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Label(btn_frame, text="Enter Command:").pack(side='left', padx=5)
        self.command_entry = ttk.Entry(btn_frame, width=60)
        self.command_entry.pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Run Command", command=self.run_command).pack(side='left', padx=5)
        self._add_detach_button(btn_frame, "Terminal", frame)

        self.output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.output_text.pack(expand=True, fill='both', padx=10, pady=10)

    def _create_removable_tab(self, frame: tk.Widget) -> None:
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5, fill='x')

        ttk.Button(btn_frame, text="Get Removable Drives", command=self.get_removable_drives).pack(side='left', padx=5)
        self._add_detach_button(btn_frame, "Removable Drives", frame)

        self.removable_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        self.removable_text.pack(expand=True, fill='both', padx=10, pady=10)

    def _create_file_manager_tab(self, frame: tk.Widget) -> None:
        self.file_tree = ttk.Treeview(frame)
        self.file_tree.pack(expand=True, fill='both', padx=10, pady=10)

        # Добавим вертикальный скроллбар
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # Корневая директория (домашняя папка пользователя)
        self.root_path = os.path.abspath(os.path.expanduser("~"))

        # Заполнение дерева
        def insert_node(parent, path):
            try:
                for p in sorted(os.listdir(path)):
                    abspath = os.path.join(path, p)
                    isdir = os.path.isdir(abspath)
                    node = self.file_tree.insert(parent, 'end', text=p, open=False)
                    if isdir:
                        # Добавим пустой дочерний элемент, чтобы показать стрелку раскрытия
                        self.file_tree.insert(node, 'end')
            except PermissionError:
                pass  # Игнорируем папки без доступа

        def on_open(event):
            node = self.file_tree.focus()
            path = self._get_full_path(node)
            # Очистить дочерние элементы
            self.file_tree.delete(*self.file_tree.get_children(node))
            insert_node(node, path)

        self.file_tree.bind('<<TreeviewOpen>>', on_open)

        # Вспомогательный метод для получения полного пути из узла
        def get_full_path(node):
            parts = []
            while node:
                parts.insert(0, self.file_tree.item(node, 'text'))
                node = self.file_tree.parent(node)
            return os.path.join(self.root_path, *parts)

        self._get_full_path = get_full_path

        # Заполнить корневой узел
        insert_node('', self.root_path)

        # --- Drag and Drop ---

        self._dragging_item = None

        def on_button_press(event):
            item = self.file_tree.identify_row(event.y)
            if item:
                self._dragging_item = item

        def on_button_release(event):
            if not self._dragging_item:
                return
            target_item = self.file_tree.identify_row(event.y)
            if not target_item or target_item == self._dragging_item:
                self._dragging_item = None
                return

            src_path = self._get_full_path(self._dragging_item)
            dst_path = self._get_full_path(target_item)

            # Если цель - папка, переместить внутрь
            if os.path.isdir(dst_path):
                dst_path = os.path.join(dst_path, os.path.basename(src_path))
            else:
                # Если цель - файл, переместить в папку родителя цели
                dst_path = os.path.join(os.path.dirname(dst_path), os.path.basename(src_path))

            # Отправляем запрос на сервер для перемещения
            data = {'src': src_path, 'dst': dst_path}
            response = self.send_request('move_item', data=data)

            if isinstance(response, dict) and 'error' in response:
                messagebox.showerror("Ошибка перемещения", response['error'])
            else:
                messagebox.showinfo("Перемещение", response)
                # Обновляем дерево: удаляем src и обновляем dst
                parent_src = self.file_tree.parent(self._dragging_item)
                self.file_tree.delete(self._dragging_item)
                # Обновляем целевой узел, если открыт
                if self.file_tree.item(target_item, 'open'):
                    self.file_tree.delete(*self.file_tree.get_children(target_item))
                    insert_node(target_item, self._get_full_path(target_item))

            self._dragging_item = None

        self.file_tree.bind('<ButtonPress-1>', on_button_press)
        self.file_tree.bind('<ButtonRelease-1>', on_button_release)

    # --- Методы для запросов и обновления UI ---

    def send_request(self, command: str, data: Optional[Any] = None) -> Union[Dict, List, str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(self.server_address)
                request_data = {'command': command}
                if data is not None:
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

    def get_processes(self) -> None:
        response = self.send_request('get_processes')
        if 'error' in response:
            self._show_error(self.process_table, response['error'])
            return
        self.process_table.delete(*self.process_table.get_children())
        for proc in response:
            pid = proc.get('pid', '')
            name = proc.get('name', '')
            user = proc.get('username', '')
            start_time = proc.get('create_time', '')
            self.process_table.insert('', 'end', values=(pid, name, user, start_time))

    def save_process_report(self) -> None:
        filename = "process_report.txt"
        response = self.send_request('save_process_report', data=filename)
        messagebox.showinfo("Сохранение отчета", response)

    def open_popup_window(self) -> None:
        p = multiprocessing.Process(target=run_popup_window)
        p.daemon = True
        p.start()

    def get_network_config(self) -> None:
        response = self.send_request('get_network_config')
        self.network_text.delete(1.0, tk.END)
        if 'error' in response:
            self.network_text.insert(tk.END, f"Error: {response['error']}")
            return
        self.network_text.insert(tk.END, response)

    def get_wireless_status(self) -> None:
        response = self.send_request('get_wireless_status')
        self.wireless_text.delete(1.0, tk.END)
        if 'error' in response:
            self.wireless_text.insert(tk.END, f"Error: {response['error']}")
            return
        pretty = pprint.pformat(response, indent=2, width=80)
        self.wireless_text.insert(tk.END, pretty)

    def get_screen_resolution(self) -> None:
        response = self.send_request('get_screen_resolution')
        if 'error' in response:
            self.screen_label.config(text=f"Error: {response['error']}")
            return
        self.screen_label.config(text=f"Screen resolution: {response[0]} x {response[1]}")

    def run_command(self) -> None:
        command = self.command_entry.get()
        response = self.send_request('linux_terminal', data=command)
        self.output_text.delete(1.0, tk.END)
        if isinstance(response, dict) and 'error' in response:
            self.output_text.insert(tk.END, f"Error: {response['error']}")
        else:
            self.output_text.insert(tk.END, response)

    def get_removable_drives(self) -> None:
        response = self.send_request('get_removable_drives')
        self.removable_text.delete(1.0, tk.END)
        if 'error' in response:
            self.removable_text.insert(tk.END, f"Error: {response['error']}")
            return
        if not response:
            self.removable_text.insert(tk.END, "Съемные носители не найдены.")
            return
        for drive in response:
            self.removable_text.insert(
                tk.END,
                f"Device: {drive['device']}\n"
                f"Mountpoint: {drive['mountpoint']}\n"
                f"Fstype: {drive['fstype']}\n"
                f"Opts: {drive['opts']}\n\n"
            )

    def _show_error(self, widget: Union[ttk.Treeview, tk.Text], message: str) -> None:
        if isinstance(widget, ttk.Treeview):
            widget.delete(*widget.get_children())
            widget.insert('', 'end', values=(message,))
        else:
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, message)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = App()
    app.mainloop()
