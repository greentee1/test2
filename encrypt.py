import binascii

class SAFEREncrypt:
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

        def mat1(self, a, b):
            y = (a + b) & 0xFF
            x = (y + a) & 0xFF
            return x, y

        def key_schedule(self, key):
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

        def encrypt_block(self, block, key):
            if len(block) != 8:
                raise ValueError(f"Блок должен быть 8 байт, получено {len(block)}")
            if len(key) != 8:
                raise ValueError(f"Ключ должен быть 8 байт, получено {len(key)}")

            a = list(block)
            k = self.key_schedule(key)
        
        for i in range(8):
            if i % 2 == 0:
                a[i] = (a[i] + k[0][i]) & 0xFF
            else:
                a[i] = a[i] ^ k[0][i]

        
        for r in range(1, self.rounds + 1):
            for i in range(8):
                if i % 2 == 0:
                    a[i] = self.exptab[a[i]]
                else:
                    a[i] = self.logtab[a[i]]

            
            a[0], a[1] = self.mat1(a[0], a[1])
            a[2], a[3] = self.mat1(a[2], a[3])
            a[4], a[5] = self.mat1(a[4], a[5])
            a[6], a[7] = self.mat1(a[6], a[7])
            a = [a[0], a[3], a[4], a[7], a[1], a[2], a[5], a[6]]

            for i in range(8):
                if i % 2 == 0:
                    a[i] = (a[i] + k[2 * r - 1][i]) & 0xFF
                else:
                    a[i] = a[i] ^ k[2 * r - 1][i]

            for i in range(8):
                if i % 2 == 0:
                    a[i] = a[i] ^ k[2 * r][i]
                else:
                    a[i] = (a[i] + k[2 * r][i]) & 0xFF
