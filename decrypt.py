import binascii

class SAFERDecrypt:
    
    def __init__(self, rounds=8):
        self.rounds = min(max(rounds, 6), 10)
        self.logtab = [0] * 256
        self.exptab = [0] * 257
        self._init_tables()