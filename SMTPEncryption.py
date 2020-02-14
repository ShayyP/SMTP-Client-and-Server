class NWSEncryption:
    def __init__(self):
        self._enabled = False
        self._method = None
        self._alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
                         "!£$%^&*()-+={}[]:;@'<,>.?/\\#\n\t\" "
        self._caesar_key = None
        self._vigenere_key = None

    def toggle_enable(self) -> bool:
        """Toggles whether encryption is to be used"""
        self._enabled = not self._enabled
        return self._enabled

    def get_enabled(self) -> bool:
        """Get method for enabled private variable"""
        return self._enabled

    def set_caesar_key(self, key):
        """Sets caesar key to defined integer"""
        try:
            self._caesar_key = int(key)
        except TypeError:
            self._caesar_key = 0
            return
        else:
            return self._caesar_key

    def set_vigenere_key(self, key):
        """Sets vigenere key to defined string"""
        try:
            self._vigenere_key = str(key)
        except TypeError:
            self._vigenere_key = 'Derby'
            return
        else:
            return self._caesar_key

    def set_method(self, method):
        """Specifies encryption method to be used"""
        if method.lower() == 'caesar':
            self._method = 'caesar'
        elif method.lower() == 'vigenere':
            self._method = 'vigenere'
        else:
            self._method = None

    def encrypt(self, message) -> str:
        """Encrypts message using specified method"""
        if self._enabled:
            if self._method == 'caesar':
                return self._caesarcipherencrypt(message)
            elif self._method == 'vigenere':
                return self._vigeneresquareencrypt(message)
        return message

    def decrypt(self, message) -> str:
        """Decrypts message using specified method"""
        if self._enabled:
            if self._method == 'caesar':
                return self._caesarcipherdecrypt(message)
            elif self._method == 'vigenere':
                return self._vigeneresquaredecrypt(message)
        return message

    def _caesarcipherencrypt(self, message) -> str:
        """Encrypts message using caesar cipher"""
        try:
            message = str(message)
        except TypeError:
            return ''
        else:
            output = ''
            for letter in message:
                letter_num = self._alphabet.index(letter)
                output += self._alphabet[((letter_num + self._caesar_key) % len(self._alphabet))]

            return output

    def _vigeneresquareencrypt(self, message) -> str:
        """Encrypts message using vigenere cipher"""
        try:
            message = str(message)
        except TypeError:
            return ''
        else:
            output = ''
            pos = 0
            for letter in message:
                letter_num = self._alphabet.index(letter)
                key_num = self._alphabet.index(self._vigenere_key[pos]) + 1
                output += self._alphabet[((letter_num + key_num) % len(self._alphabet))]
                pos += 1
                if pos == len(self._vigenere_key):
                    pos = 0

            return output

    def _caesarcipherdecrypt(self, message) -> str:
        """Decrypts message using caesar cipher"""
        try:
            message = str(message)
        except TypeError:
            return ''
        else:
            output = ''
            for letter in message:
                letter_num = self._alphabet.index(letter)
                output += self._alphabet[((letter_num - self._caesar_key) % len(self._alphabet))]

            return output

    def _vigeneresquaredecrypt(self, message) -> str:
        """Decrypts message using vigenere cipher"""
        try:
            message = str(message)
        except TypeError:
            return ''
        else:
            output = ''
            pos = 0
            for letter in message:
                letter_num = self._alphabet.index(letter)
                key_num = self._alphabet.index(self._vigenere_key[pos]) + 1
                output += self._alphabet[((letter_num - key_num) % len(self._alphabet))]
                pos += 1
                if pos == len(self._vigenere_key):
                    pos = 0

            return output
