import selectors
import queue
import traceback
import SMTPEncryption
from threading import Thread
import random
import hashlib


class Module(Thread):
    def __init__(self, sock, addr):
        Thread.__init__(self)
        # public:
        self.current_state = 'START'

        # private:
        self._selector = selectors.DefaultSelector()
        self._sock = sock
        self._addr = addr
        self._incoming_buffer = queue.Queue()
        self._outgoing_buffer = queue.Queue()
        self._selector.register(self._sock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=None)
        self._next_state = None
        self._previous_state = None
        self._encryption = SMTPEncryption.NWSEncryption()
        # Variables used in Diffie Hellman key exchange
        self._dh_private_x = random.randint(10000, 100000)
        self._dh_public_g = random.randint(10000, 100000)
        self._dh_public_n = None
        self._gy_mod_n = None
        self._gx_mod_n = None
        self._shared_key = None
        # RFC821 standard return codes + 2 custom ones used for Diffie Hellman
        self._expected_return_codes = ['211', '214', '220', '221', '250', '251', '354', '421', '450', '451', '452',
                                       '500', '501', '502', '503', '504', '510', '530', '550', '551', '552', '553',
                                       '554', 'DH1', 'DH2']

    def modify_encryption(self, enabled, method, key):
        """Updates encryption, defining whether it is enabled and then setting the method and key"""
        if self._encryption.get_enabled() != enabled:
            self._encryption.toggle_enable()
        self._encryption.set_method(method)
        if method == 'caesar':
            self._encryption.set_caesar_key(key)
        elif method == 'vigenere':
            self._encryption.set_vigenere_key(key)
        else:
            raise SyntaxError('Invalid Method Provided')

    def run(self):
        """Creates thread"""
        try:
            while 1:
                events = self._selector.select(timeout=1)
                for key, mask in events:
                    try:
                        if mask & selectors.EVENT_READ:
                            self._read()
                        if mask & selectors.EVENT_WRITE:
                            pass
                        if not self._outgoing_buffer.empty():
                            self._write()
                    except Exception:
                        print('main: error: exception for', f"{self._addr}:\n{traceback.format_exc()}")
                        self._sock.close()

                if not self._selector.get_map():
                    break

        finally:
            self._selector.close()

    def _read(self):
        """Reads data from the incoming buffer"""
        try:
            data = self._sock.recv(4096)
        except BlockingIOError:
            pass
        else:
            if data:
                self._incoming_buffer.put(self._encryption.decrypt(data.decode('utf-8')))
            else:
                raise RuntimeError('Peer closed.')
        self._process_response()

    def _write(self):
        """Writes data to the outgoing buffer"""
        try:
            message = self._outgoing_buffer.get_nowait()
        except ():
            message = None

        if message:
            print('sending', repr(message), 'to', self._addr)
        try:
            self._sock.send(message)
        except BlockingIOError:
            pass

    def create_message(self, content: str, encrypt=True):
        """Encrypts and encodes data before writing it"""
        if encrypt:
            encrypted = self._encryption.encrypt(content)
        else:
            encrypted = content
        encoded = encrypted.encode('utf-8')
        self._outgoing_buffer.put(encoded)

    def start_diffie_hellman(self):
        """Begins Diffie Hellman key exchange"""
        self._next_state = 'NEGOTIATE'
        self._update_state_machine()
        self.create_message('DHK1' + str(self._dh_public_g), False)

    def diffie_hellman_done(self):
        """Verifies if the Diffie Hellman key exchange is been completed or not"""
        return self._shared_key is not None

    def _process_response(self):
        """Splits message into header and body"""
        message = self._incoming_buffer.get()
        header_length = 3
        if len(message) >= header_length:
            self._module_processor(message[0:header_length], message[header_length:])

    def _update_state_machine(self):
        """Updates the state machine by shifting states back"""
        self._previous_state = self.current_state
        self.current_state = self._next_state
        self._next_state = None

    def _module_processor(self, command, message):
        """Processes incoming messages based on their command"""
        # Outputs server response
        if command in self._expected_return_codes:
            print('Server response: ' + command + message)
        else:
            print('Unknown command received: ' + command)
            self.create_message('500 Unknown command')
        # Diffie Hellman key exchange
        if command == 'DH1':
            self._dh_public_n = int(message)
            self._gx_mod_n = self._dh_public_g ** self._dh_private_x % self._dh_public_n
            self.create_message('DHK2' + str(self._gx_mod_n), False)
        elif command == 'DH2':
            self._gy_mod_n = int(message)
            self._shared_key = self._gy_mod_n ** self._dh_private_x % self._dh_public_n
            # Hashing the key to make it longer
            self.modify_encryption(True, 'vigenere', hashlib.sha256(str(self._shared_key).encode()).hexdigest())
            self.create_message('250 OK', False)
        # 221 signifies connection termination
        elif command == '221':
            self._next_state = 'TERMINATE'
            self._update_state_machine()
            self.close()

    def close(self):
        """Closes connection to the server and terminates the thread"""
        print('closing connection to', self._addr)
        try:
            self._selector.unregister(self._sock)
        except Exception as e:
            print('error: selector.unregister() exception for', f"{self._addr}: {repr(e)}")

            try:
                self._sock.close()
            except OSError as e:
                print('error: socket.close() exception for', f"{self._addr}: {repr(e)}")

        finally:
            self._sock = None
