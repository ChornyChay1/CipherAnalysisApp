import os
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cipher import (
    CaesarCipher, CaesarCipherMod,
    DESCipher, DESCipherMod,
    RSACipher, RSACipherMod,
    CaesarBruteForce,CaesarCipherModBruteForce,
   
)
import sys
import psutil   
from functools import wraps

RUSSIAN_KEYWORDS = [
    "привет", "здравствуйте", "как", "дела", "шифр", "работа", "пример", "слово"
]

# Описание алгоритмов
ALGO_DESCRIPTIONS = {
    "Цезарь": "Простой шифр сдвига, где каждая буква сдвигается на фиксированное число позиций в алфавите.",
    "Цезарь (мод)": "Модифицированный шифр Цезаря с динамическим сдвигом на основе ключевого слова.",
    "DES": "Упрощенный DES-подобный шифр, использующий XOR с фиксированным ключом.",
    "DES (мод)": "Модифицированный DES с циклическим сдвигом ключа при шифровании.",
    "RSA": "Упрощенная реализация RSA с небольшими простыми числами (только для демонстрации).",
    "RSA (мод)": "RSA с двойным шифрованием разными ключами для усиления защиты."
}

# Описание параметров для каждого алгоритма
ALGO_PARAMS = {
    "Цезарь": {"shift": (int, "Сдвиг", 3)},
    "Цезарь (мод)": {"key": (str, "Ключ (латиница)", "key")},
    "DES": {"key": (str, "Ключ (8 байт, hex)", "38627974656b6579")},  # это "8bytekey"
    "DES (мод)": {"key": (str, "Ключ (8 байт, hex)", "38627974656b6579")},
    "RSA": {},
    "RSA (мод)": {},
}


 






class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифратор")
        self.root.geometry("900x700")
        self.prev_analysis_text = ""
        self.algorithms = {
            "Цезарь": CaesarCipher,
            "Цезарь (мод)": CaesarCipherMod,
            "DES": DESCipher,
            "DES (мод)": DESCipherMod,
            "RSA": RSACipher,
            "RSA (мод)": RSACipherMod,
        }

        self.bruteforcers = {
            "Цезарь": CaesarBruteForce(),
            "Цезарь (мод)": CaesarCipherModBruteForce()
        }

        self.param_vars = {}
        self.setup_menu()
        self.setup_ui()
        self.update_params_ui()

    def setup_menu(self):
        menu_bar = tk.Menu(self.root)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Загрузить из файла", command=self.load_from_file)
        file_menu.add_command(label="Сохранить результат", command=self.save_to_file)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)
        menu_bar.add_cascade(label="Файл", menu=file_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="О программе", command=lambda: messagebox.showinfo("О программе", "Шифратор 3000 v5.0"))
        menu_bar.add_cascade(label="Справка", menu=help_menu)

        self.root.config(menu=menu_bar)

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Алгоритм и описание
        algo_frame = ttk.Frame(main_frame)
        algo_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        ttk.Label(algo_frame, text="Алгоритм:").grid(row=0, column=0, sticky="w")
        self.algo_var = tk.StringVar(value="Цезарь")
        algo_box = ttk.Combobox(algo_frame, textvariable=self.algo_var, 
                               values=list(self.algorithms.keys()), state="readonly")
        algo_box.grid(row=0, column=1, sticky="ew", pady=5)
        algo_box.bind("<<ComboboxSelected>>", lambda e: self.update_params_ui())
        
        self.algo_desc_label = ttk.Label(algo_frame, text=ALGO_DESCRIPTIONS["Цезарь"], 
                                       wraplength=600, foreground="gray")
        self.algo_desc_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=5)

        # Параметры шифра
        self.params_frame = ttk.Frame(main_frame)
        self.params_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)

        # Вкладки ввода и результата
        notebook = ttk.Notebook(main_frame)
        self.text_input = tk.Text(notebook, wrap="word", undo=True)
        self.result_output = tk.Text(notebook, wrap="word", state="disabled")
        notebook.add(self.text_input, text="Ввод текста / байтов")
        notebook.add(self.result_output, text="Результат")
        notebook.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=5)

        # Кнопки копирования
        copy_frame = ttk.Frame(main_frame)
        copy_frame.grid(row=3, column=0, columnspan=2, sticky="e")
        ttk.Button(copy_frame, text="📋 Копировать ввод", command=self.copy_input).grid(row=0, column=0, padx=5)
        ttk.Button(copy_frame, text="📋 Копировать результат", command=self.copy_result).grid(row=0, column=1, padx=5)

        # Кнопки действий
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Зашифровать", command=self.encrypt).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Расшифровать", command=self.decrypt).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Brute-Force", command=self.brute_force).grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="Очистить всё", command=self.clear_all).grid(row=0, column=3, padx=5)

        # Метрики анализа
        self.analysis_label = ttk.Label(main_frame, text="Анализ: —")
        self.analysis_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=5)

        self.prev_analysis_label = ttk.Label(main_frame, text="Предыдущий анализ: —", foreground="gray")
        self.prev_analysis_label.grid(row=6, column=0, columnspan=2, sticky="w", pady=5)

        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

    def update_params_ui(self):
        # Очистить предыдущие параметры
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        self.param_vars.clear()

        algo = self.algo_var.get()
        self.algo_desc_label.config(text=ALGO_DESCRIPTIONS.get(algo, ""))
        params = ALGO_PARAMS.get(algo, {})

        if not params:
            ttk.Label(self.params_frame, text="Параметры не требуются").pack(anchor="w")
            return

        for i, (param_name, (ptype, desc, default)) in enumerate(params.items()):
            ttk.Label(self.params_frame, text=f"{desc}:").grid(row=i, column=0, sticky="w")
            if ptype == int:
                var = tk.IntVar(value=default)
                entry = ttk.Entry(self.params_frame, textvariable=var)
            elif ptype == str:
                var = tk.StringVar(value=default)
                entry = ttk.Entry(self.params_frame, textvariable=var)
            else:
                var = tk.StringVar(value=str(default))
                entry = ttk.Entry(self.params_frame, textvariable=var)
            entry.grid(row=i, column=1, sticky="ew", padx=5, pady=2)
            self.param_vars[param_name] = var

        self.params_frame.columnconfigure(1, weight=1)

    def get_cipher(self):
        algo_name = self.algo_var.get()
        cls = self.algorithms.get(algo_name)
        if cls is None:
            return None

        params = ALGO_PARAMS.get(algo_name, {})

        kwargs = {}
        for param_name, (ptype, desc, default) in params.items():
            var = self.param_vars.get(param_name)
            if var is not None:
                val = var.get()
                if ptype == int:
                    try:
                        val = int(val)
                    except ValueError:
                        messagebox.showerror("Ошибка", f"Параметр '{desc}' должен быть числом.")
                        return None
                elif ptype == str:
                    val = str(val)
                    if "hex" in desc.lower():
                        try:
                            val = bytes.fromhex(val)
                        except ValueError:
                            messagebox.showerror("Ошибка", f"Параметр '{desc}' должен быть в hex формате.")
                            return None
                kwargs[param_name] = val

        try:
            return cls(**kwargs)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать шифр:\n{e}")
            return None

    def measure_analysis(self, text, action, cipher):
        self.prev_analysis_text = self.analysis_label.cget("text")

        process = psutil.Process()
        start_mem = process.memory_info().rss
        start_time = time.time()
        
        try:
            result = action(text)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании/дешифровании:\n{e}")
            return ""
            
        end_time = time.time()
        end_mem = process.memory_info().rss

        info = (
            f"Анализ:\n"
            f"  Алгоритм: {cipher.__class__.__name__}\n"
            f"  Символов: {len(text)}\n"
            f"  Память: ~{end_mem - start_mem} байт\n"
            f"  Время: {end_time - start_time:.5f} сек"
        )
        self.analysis_label.config(text=info)
        self.prev_analysis_label.config(text=f"Предыдущий анализ:\n{self.prev_analysis_text}")
        return result

    def brute_force(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Пусто", "Введите текст для взлома")
            return

        algo = self.algo_var.get()
    
        # Проверяем, разрешен ли brute force для этого алгоритма
        if algo not in ["Цезарь", "Цезарь (мод)"]:
            messagebox.showwarning(
                "Стойкий шифр", 
                f"Brute-force для {algo} займет непрактично много времени (годы или десятилетия).\n"
                "Рекомендуется использовать другие методы криптоанализа."
            )
            return

        bruteforcer = self.bruteforcers.get(algo)
        if bruteforcer is None:
            messagebox.showerror("Ошибка", f"Brute-Force не реализован для алгоритма '{algo}'")
            return

        try:
            dict_res = bruteforcer.crack(text)
            results = dict_res["results"] 
            metrics = dict_res["metrics"] 
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Неверный формат ввода: {str(e)}")
            return
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при брутфорсе:\n{str(e)}")
            return

        # Формируем отчет
        report = [
            f"Результат взлома ({algo}):",
            f"Время выполнения: {metrics['time']:.2f} сек", 
            f"Использовано памяти: {metrics['memory']} байт",
            ""
        ]

        self.analysis_label.config(
            text=f"Анализ взлома ({algo}):\n" 
                 f"Время: {metrics['time']:.2f} сек\n" 
                 f"Память: {metrics['memory']} байт"
        )
    
        self.show_result("\n".join(report))

    def encrypt(self):
        text = self.text_input.get("1.0", tk.END).strip()
        cipher = self.get_cipher()
        if cipher:
            result = self.measure_analysis(text, cipher.encrypt, cipher)
            self.show_result(result)

    def decrypt(self):
        text = self.text_input.get("1.0", tk.END).strip()
        cipher = self.get_cipher()
        if cipher:
            result = self.measure_analysis(text, cipher.decrypt, cipher)
            self.show_result(result)

    def show_result(self, text):
        self.result_output.config(state="normal")
        self.result_output.delete("1.0", tk.END)
        self.result_output.insert("1.0", text)
        self.result_output.config(state="disabled")

    def save_to_file(self):
        text = self.result_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Пусто", "Нет текста для сохранения.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Бинарные файлы", "*.bin"), ("Все файлы", "*.*")]
        )
        if not file_path:
            return

        try:
            if file_path.endswith(".bin"):
                with open(file_path, "wb") as f:
                    f.write(text.encode("latin1"))
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(text)
            messagebox.showinfo("Успех", "Файл успешно сохранён!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def load_from_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                data = f.read()
            content = data.decode("latin1")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить файл:\n{e}")
            return

        self.text_input.delete("1.0", tk.END)
        self.text_input.insert("1.0", content)

    def clear_all(self):
        self.text_input.delete("1.0", tk.END)
        self.result_output.config(state="normal")
        self.result_output.delete("1.0", tk.END)
        self.result_output.config(state="disabled")
        self.analysis_label.config(text="Анализ: —")
        self.prev_analysis_label.config(text="Предыдущий анализ: —")

    def copy_input(self):
        text = self.text_input.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Скопировано", "Текст скопирован в буфер обмена.")

    def copy_result(self):
        text = self.result_output.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Скопировано", "Результат скопирован в буфер обмена.")


if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()