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