import socket
import selectors
import SMTPClientLib
import time


class NWSThreadedClient:
    def __init__(self, host="127.0.0.1", port=12345):
        if __debug__:
            print("NWSThreadedClient.__init__", host, port)

        # Network components
        self._host = host
        self._port = port
        self._listening_socket = None
        self._selector = selectors.DefaultSelector()

        self._module = None

    def start_connection(self, host, port):
        """Connects to the server"""
        addr = (host, port)
        print("starting connection to", addr)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(addr)

        self._module = SMTPClientLib.Module(sock, addr)
        self._module.start()

    def run(self):
        """Runs the client"""
        self.start_connection(self._host, self._port)

        # Uses Diffie Hellman key exchange to agree key to be used
        self._module.start_diffie_hellman()
        while not self._module.diffie_hellman_done():
            pass
        time.sleep(0.2)

        # Runs test case to demonstrate key features of my program
        if input('Run test case? (Y/N): ').upper() == 'Y':
            messages = [
                # Sends HELO command followed by the domain
                'HELO [127.0.0.1]',
                # Requests general HELP message from the server
                'HELP',
                # Requests specific HELP message from the server
                'HELP MAKE',
                # Creates account 'BestUsername56' with password: 'Password123'
                'MAKE BestUsername56 Password123',
                # Logs into account 'BestUsername56' with password: 'Password123'
                'LOGI BestUsername56 Password123',
                # Creates mailbox 'bestemail@gmail.com' with password: '123Password'
                'MBOX bestemail@gmail.com 123Password',
                # Links mailbox 'bestemail@gmail.com' to logged in account, passing in the password for the mailbox
                'LINK bestemail@gmail.com 123Password',
                # Searches for mailboxes owned by 'Shay'
                'VRFY Shay',
                # Specifies MAIL sender as 'bestemail@gmail.com'
                'MAIL FROM:<bestemail@gmail.com>',
                # Specifies recipients as
                # 'bestemail@gmail.com', 'shayp2000@gmail.com' and 's.pearson5@unimail.derby.ac.uk'
                'RCPT TO:<bestemail@gmail.com>',
                'RCPT TO:<shayp2000@gmail.com>',
                'RCPT TO:<s.pearson5@unimail.derby.ac.uk>',
                # Begins data stream
                'DATA',
                # Sends lines of data
                'Hello Shay,',
                'Please reply at your earliest convenience.',
                'Thanks,',
                'Bob',
                # Ends data stream
                '.',
                # Sends NOOP command
                'NOOP',
                # Access will be denied as 'BestUsername56' is not linked to 'shayp2000@gmail.com'
                'VIEW shayp2000@gmail.com',
                # Resets sender, recipients and data and logs user out
                'RSET',
                # Sends HELO command followed by the domain
                'HELO [127.0.0.1]',
                # Logs into account 'ShayP2000' with password: 'SuperSecurePassword7'
                # ShayP2000 has access to 'shayp2000@gmail.com' and 's.pearson5@unimail.derby.ac.uk'
                'LOGI ShayP2000 SuperSecurePassword7',
                # Gets mailing list 'Work'
                'EXPN Work',
                # Gets all emails sent to 'shayp2000@gmail.com'
                # Date or date range can be specified for VIEW and DLTE command too
                'VIEW shayp2000@gmail.com',
                # Deletes all emails sent to 'shayp2000@gmail.com'
                'DLTE shayp2000@gmail.com',
                # Gets all emails sent to 'shayp2000@gmail.com' (will return none as they have just been deleted)
                'VIEW shayp2000@gmail.com',
                # Gets all emails sent to 's.pearson5@unimail.derby.ac.uk' (the email here was not deleted)
                'VIEW s.pearson5@unimail.derby.ac.uk',
                # Requests for connection to be terminated
                'QUIT',
            ]

            # Sends all messages in list with 1 second gap between them
            for message in messages:
                print('\nCreating message: ' + message + '\n')
                self._module.create_message(message)
                time.sleep(1)

        # Creates messages taking user input until the connection is terminated
        while self._module.current_state != "TERMINATE":
            user_action = input("Enter a string: ")
            self._module.create_message(user_action)
            time.sleep(0.2)


if __name__ == "__main__":
    client = NWSThreadedClient()
    client.run()
