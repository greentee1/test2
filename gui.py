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
