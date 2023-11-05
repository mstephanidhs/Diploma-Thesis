class DecryptionError(Exception):
    def __init__(self, message="Decryption failed. Invalid data format."):
        self.message = message
        super().__init__(self.message)