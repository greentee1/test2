import tkinter as tk
from tkinter import messagebox, scrolledtext
import binascii
from encrypt import SAFEREncrypt
from decrypt import SAFERDecrypt

def encrypt():
    """Шифрование текста"""
    try:
        # Получаем данные
        text = text_entry.get("1.0", tk.END).strip()
        key = key_entry.get().strip()

        if not text or not key:
            messagebox.showerror("Ошибка", "Введите текст и ключ")
            return
        if len(key) != 8:
            messagebox.showerror("Ошибка", "Введите ключ из 8 символов")
            return

        # Шифруем
        cipher = SAFEREncrypt()
        encrypted = cipher.encrypt(text, key)

        result_text.config(state='normal')
        result_text.delete('1.0', tk.END)
        result_text.insert('1.0', "ENCRYPTED:\n\n")
        result_text.insert('end', f"Key: {key}\n")
        result_text.insert('end', f"Text: {text}\n\n")
        result_text.insert('end', "Ciphertext (hex):\n")
        result_text.insert('end', encrypted)
        result_text.config(state='disabled')

        # Копируем в поле ввода для дешифрования
        text_entry.delete("1.0", tk.END)
        text_entry.insert("1.0", encrypted)

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt():
    """Дешифрование текста"""
    try:
        # Получаем данные
        ciphertext = text_entry.get("1.0", tk.END).strip()
        key = key_entry.get().strip()

        if not ciphertext or not key:
            messagebox.showerror("Ошибка", "Введите шифртекст и ключ")
            return
        if len(key) != 8:
            messagebox.showerror("Ошибка", "Введите ключ из 8 символов")
            return

        # Дешифруем
        cipher = SAFERDecrypt()
        decrypted = cipher.decrypt(ciphertext, key)

        result_text.config(state='normal')
        result_text.delete('1.0', tk.END)
        result_text.insert('1.0', "Расшифровано:\n\n")
        result_text.insert('end', f"Ключ: {key}\n")
        result_text.insert('end', f"Шифр: {ciphertext[:50]}...\n\n")
        result_text.insert('end', "Расшифрованный текст:\n")
        result_text.insert('end', decrypted)
        result_text.config(state='disabled')

        # Копируем в поле ввода
        text_entry.delete("1.0", tk.END)
        text_entry.insert("1.0", decrypted)

    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def clear():
    """Очистка всех полей"""
    text_entry.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)
    result_text.config(state='normal')
    result_text.delete('1.0', tk.END)
    result_text.config(state='disabled')

    # Вставить пример
    text_entry.insert("1.0", "Hello World! This is a test.")
    key_entry.insert(0, "secret12")

def copy_result():
    """Копирование результата в буфер"""
    result = result_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)

root = tk.Tk()
root.title("SAFER SK-64 Encryption")
root.geometry("600x500")


title_label = tk.Label(root, text="SAFER SK-64",
                       font=("Arial", 14, "bold"))
title_label.pack(pady=10)

# Поле для текста
tk.Label(root, text="Введите сообщение на английском:").pack()
text_entry = scrolledtext.ScrolledText(root, height=5, width=70)
text_entry.pack(padx=20, pady=(0, 10))

# Поле для ключа
tk.Label(root, text="Введите ключ (8 английских символов):").pack()
key_entry = tk.Entry(root, width=50)
key_entry.pack(pady=(0, 10))