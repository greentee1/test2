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