import binascii

class SAFERDecrypt:
    
    def __init__(self, rounds=8):
        self.rounds = min(max(rounds, 6), 10)
        self.logtab = [0] * 256
        self.exptab = [0] * 257
        self._init_tables()


    def _init_tables(self):

        self.exptab[0] = 1
        for i in range(1, 256):
            val = (45 * self.exptab[i - 1]) % 257
            if val == 256:
                val = 0
            self.exptab[i] = val
            self.logtab[val] = i

        self.logtab[1] = 0
        self.logtab[0] = 128
        self.exptab[128] = 0
        self.exptab[256] = 0

    def rotate_left(self, b, n):
        return ((b << n) | (b >> (8 - n))) & 0xFF
    
    def mat1_inv(self, a, b):
        x = (a - b) & 0xFF
        y = (b - x) & 0xFF
        return x, y
    
    def key_schedule(self, key):
        """Генерация 17 раундовых ключей"""
        if len(key) != 8:
            raise ValueError(f"Ключ должен быть 8 байт, получено {len(key)}")

        k = list(key)
        parity = 0
        for b in k:
            parity ^= b
        k.append(parity)

        subkeys = []
        for r in range(2 * self.rounds + 1):
            subkey = []
            for j in range(8):
                idx = (9 * r + j) % 256
                subkey.append((k[j] + self.exptab[idx]) & 0xFF)
            subkeys.append(subkey)
            k = [self.rotate_left(x, 3) for x in k]

        return subkeys
    
    def decrypt_block(self, block, key):
        """Дешифрование одного 8-байтного блока"""
        if len(block) != 8:
            raise ValueError(f"Блок должен быть 8 байт, получено {len(block)}")
        if len(key) != 8:
            raise ValueError(f"Ключ должен быть 8 байт, получено {len(key)}")

        a = list(block)
        k = self.key_schedule(key)

        # Обратное финальное преобразование
        for i in range(8):
            if i % 2 == 0:
                a[i] = (a[i] - k[2 * self.rounds][i]) & 0xFF
            else:
                a[i] = a[i] ^ k[2 * self.rounds][i]

        # 8 раундов в обратном порядке
        for r in range(self.rounds, 0, -1):
            # Обратное смешивание с ключами
            for i in range(8):
                if i % 2 == 0:
                    a[i] = a[i] ^ k[2 * r][i]
                else:
                    a[i] = (a[i] - k[2 * r][i]) & 0xFF

            for i in range(8):
                if i % 2 == 0:
                    a[i] = (a[i] - k[2 * r - 1][i]) & 0xFF
                else:
                    a[i] = a[i] ^ k[2 * r - 1][i]

            # Обратная перестановка
            a = [a[0], a[4], a[5], a[1], a[2], a[6], a[7], a[3]]

            # Обратный PHT
            a[0], a[1] = self.mat1_inv(a[0], a[1])
            a[2], a[3] = self.mat1_inv(a[2], a[3])
            a[4], a[5] = self.mat1_inv(a[4], a[5])
            a[6], a[7] = self.mat1_inv(a[6], a[7])

            # Обратный S-box
            for i in range(8):
                if i % 2 == 0:
                    a[i] = self.logtab[a[i]]
                else:
                    a[i] = self.exptab[a[i]]

        # Обратное начальное преобразование
        for i in range(8):
            if i % 2 == 0:
                a[i] = (a[i] - k[0][i]) & 0xFF
            else:
                a[i] = a[i] ^ k[0][i]

        return bytes(a)

    def unpad_message(self, padded_bytes):
    
        if not padded_bytes:
            return b''

        padding = padded_bytes[-1]
        if 0 <= padding <= 7:
            return padded_bytes[:-padding]
        return padded_bytes.rstrip(b'\x00')
    
    def decrypt(self, ciphertext_hex, key):
        # Проверка и подготовка ключа
        if len(key) < 8:
            key = key.ljust(8, 'A')
        elif len(key) > 8:
            key = key[:8]

        # Проверка ASCII ключа
        try:
            key_bytes = key.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError("Ключ должен содержать только английские буквы")

        # Конвертация hex в байты
        ciphertext = binascii.unhexlify(ciphertext_hex)

        # Проверка длины
        if len(ciphertext) % 8 != 0:
            raise ValueError(f"Длина шифртекста должна быть кратна 8, получено {len(ciphertext)}")

        # Дешифрование блоков
        result = b''
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            decrypted = self.decrypt_block(block, key_bytes)
            result += decrypted

        # Удаление дополнения
        original = self.unpad_message(result)

        # Декодирование
        try:
            return original.decode('ascii')
        except UnicodeDecodeError:
            # Если не ASCII, возвращаем hex
            return binascii.hexlify(original).decode()