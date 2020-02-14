import selectors
import queue
import traceback
import SMTPEncryption
from threading import Thread
import random
import re
import string
import datetime
import hashlib
import xml.etree.ElementTree as ElemTree
from xml.dom import minidom
import os


class Module(Thread):
    def __init__(self, sock, addr):
        Thread.__init__(self)

        # public:
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.current_state = 'START'

        # private:
        self._encryption = SMTPEncryption.NWSEncryption()
        self._selector = selectors.DefaultSelector()
        self._sock = sock
        self._addr = addr
        self._domain = '[' + str(self._addr).split('\'')[1] + ']'
        self._user_file_name = 'MailFiles\\UserInfo.txt'
        self._incoming_buffer = queue.Queue()
        self._outgoing_buffer = queue.Queue()
        self._expected_commands = ['HELO', 'MAKE', 'LOGI', 'MBOX', 'LINK', 'MAIL', 'RCPT', 'DATA', 'RSET',
                                   'VIEW', 'DLTE', 'VRFY', 'EXPN', 'HELP' 'NOOP', 'QUIT']
        self._months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC']
        self._next_state = None
        self._previous_state = None
        self._selector.register(self._sock, events, data=None)
        # Variables used in Diffie Hellman
        self._dh_private_y = random.randint(1000, 10000)
        self._dh_public_g = None
        self._dh_public_n = random.randint(1000, 10000)
        self._gy_mod_n = None
        self._gx_mod_n = None
        self._shared_key = None
        # User info
        self._current_user = None
        self._client_domain = None
        # Mail info
        self._sender = None
        self._recipients = None
        self._data = None
        # Audit log file
        self._audit_file = 'MailFiles\\AuditLog.xml'
        self._write_to_audit_log('Connection accepted')

    def _write_to_audit_log(self, content):
        """Writes given content to audit log in XML format"""
        auditlog = ElemTree.Element('auditlog')
        logs = ElemTree.SubElement(auditlog, 'logs')

        # Rewrites existing logs
        parse_file = minidom.parse(self._audit_file)
        existing_logs = parse_file.getElementsByTagName('log')
        for log in existing_logs:
            new_log = ElemTree.SubElement(logs, 'log')
            new_log.set('date', log.attributes['date'].value)
            new_log.set('time', log.attributes['time'].value)
            new_log.set('content', log.attributes['content'].value)
            new_log.set('client_address', log.attributes['client_address'].value)
            new_log.set('user', log.attributes['user'].value)

        # Adds new log to the file
        new_log = ElemTree.SubElement(logs, 'log')
        new_log.set('date', datetime.datetime.now().strftime('%x'))
        new_log.set('time', datetime.datetime.now().strftime('%X'))
        new_log.set('content', content)
        new_log.set('client_address', str(self._addr).replace('\'', ''))
        if self._current_user is not None:
            new_log.set('user', self._current_user)
        else:
            new_log.set('user', '')

        # Converts element tree to string
        data = ElemTree.tostring(auditlog)
        # Writes string to XML file
        file = open(self._audit_file, 'w')
        file.write(str(data)[2:][:-1])
        file.close()

    def modify_encryption(self, enabled, method, key):
        """Changes encryption method and key"""
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
            while True:
                events = self._selector.select(timeout=None)
                for key, mask in events:
                    try:
                        if mask & selectors.EVENT_READ:
                            self._read()
                        if mask & selectors.EVENT_WRITE and not self._outgoing_buffer.empty():
                            self._write()
                    except Exception:
                        print(
                            "main: error: exception for",
                            f"{self._addr}:\n{traceback.format_exc()}",
                        )
                        self._sock.close()
                if not self._selector.get_map():
                    break
        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
        finally:
            self._selector.close()

    def _read(self):
        """Reads data from the incoming buffer"""
        try:
            data = self._sock.recv(4096)
        except BlockingIOError:
            print('blocked')
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

            if self.current_state == "TERMINATE":
                self.close()

    def _create_message(self, content):
        """Encrypts and encodes message before adding it to the buffer"""
        encrypted = self._encryption.encrypt(content)
        nwencoded = encrypted.encode('utf-8')
        self._outgoing_buffer.put(nwencoded)

    def _process_response(self):
        """Splits message into header and body"""
        message = self._incoming_buffer.get()
        header_length = 4
        # If in DATA state then ignore minimum message length
        if len(message) >= header_length or self.current_state == 'DATA':
            self._module_processor(message[0:header_length], message[header_length:])
        else:
            self._write_to_audit_log('Unknown command received')
            self._create_message('500 Unknown command')

    @staticmethod
    def _validate_input(inp, regex_string, exact=False) -> bool:
        """Checks if given input is valid using regex"""
        if not exact:
            if re.search(regex_string, inp) is None:
                return False
            return True
        else:
            # Gets exact matches only using multiline flag for bigger, more complex strings
            matches = re.finditer(regex_string, inp, re.MULTILINE)
            for i in matches:
                match = str(i).split('match=')[1].replace('\'', '').replace('>', '')
                if match == inp:
                    return True
            return False

    @staticmethod
    def _get_domain_regex():
        """Returns regex string for valid domain (converted from BNF in RFC documentation)"""
        # <a> ::= any one of the 52 alphabetic characters A through Z in upper case and a through z in lower case
        a = r'[a-zA-Z]'
        # <d> ::= any one of the ten digits 0 through 9
        d = r'[0-9]'
        # <let-dig> ::= <a> | <d>
        let_dig = a + r'|' + d
        # <let-dig-hyp> ::= <a> | <d> | "-"
        let_dig_hyp = a + r'|' + d + r'|-'
        # <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
        ldh_str = r'(' + let_dig_hyp + r')+'
        # <name> ::= <a> <ldh-str> <let-dig>
        name = r'(' + a + ldh_str + r'(' + let_dig + r'))'
        # <number> ::= <d> | <d> <number>
        number = d + r'+'
        # <snum> ::= one, two, or three digits representing a decimal integer value in the range 0 through 255
        snum = r'(1[0-9][0-9]|2[0-4][0-9]|25[0-5]|[0-9][0-9]|[0-9])'
        # <dotnum> ::= <snum> "." <snum> "." <snum> "." <snum>
        dotnum = r'(' + snum + r'\.){3}' + snum
        # <element> ::= <name> | "#" <number> | "[" <dotnum> "]"
        element = name + r'|#' + number + r'|\[' + dotnum + r'\]'
        # <domain> ::=  <element> | <element> "." <domain>
        final = element + r'(\.' + element + r')*'
        return final

    def _get_email_regex(self):
        """Returns regex string for valid domain (converted from BNF in RFC documentation)"""
        # <x> ::= any one of the 128 ASCII characters (no exceptions)
        x = r'[' + chr(0) + r'-' + chr(127) + r']'
        # <c> ::= any one of the 128 ASCII characters, but not any <special> or <SP>
        c = r'((?![<>\(\)\[\]\\\.,;:@"\0\a\b\t\n\v\f\r\e])' + x + r')'
        # <q> ::= any one of the 128 ASCII characters except <CR>, <LF>, quote ("), or backslash (\)
        q = r'((?![\r\n"\\])' + x + r')'
        # <char> ::= <c> | "\" <x>
        char = c + r'|(\\' + x + r')'
        # <string> ::= <char> | <char> <string>
        strng = r'(' + char + r')+'
        # <dot-string> ::= <string> | <string> "." <dot-string>
        dot_string = r'(' + strng + r')(\.' + strng + r')*'
        # <qtext> ::=  "\" <x> | "\" <x> <qtext> | <q> | <q> <qtext>
        qtext = r'((\\(' + x + r'))+|(' + q + r')+|(\\(' + x + r')(' + q + r'))+|((' + q + r')\\(' + x + r'))+)+'
        # <quoted-string> ::=  """ <qtext> """
        quoted_string = r'^\"\"\"(' + qtext + r')\"\"\"$'
        # <local-part> ::= <dot-string> | <quoted-string>
        # local_part = r'(' + dot_string + r')|(' + quoted_string + r')'
        # local_part caused errors in python but works fine in regex debugger
        # Because of this I have had to use a simpler, less effective regex string
        # Left code in above anyway to show my attempt
        local_part = r'(((([a-zA-Z0-9])|(\\.))+)(\.(([a-zA-Z0-9])|(\\.))+)*)|(\"\"\"(([a-zA-Z0-9])|(\\.))+\"\"\")'
        # <mailbox> ::= <local-part> "@" <domain>
        domain = self._get_domain_regex()
        final = r'(' + local_part + r')@(' + domain + r')(\.' + local_part + r')*'
        return final

    def _validate_domain(self, domain):
        """Checks if domain given is valid using regex"""
        return self._validate_input(domain, self._get_domain_regex(), True)

    def _validate_email(self, email):
        """Checks if email given is valid using regex"""
        return self._validate_input(email, self._get_email_regex(), True)

    def _create_account(self, username, password) -> str:
        """Creates an account if username does not exist. User password is salted and hashed"""
        user_info = open(self._user_file_name, 'r')
        all_info = user_info.readlines()
        # Checks if username already exists in text file
        if len(all_info) > 0:
            for line in all_info:
                other_username = line.split(' ')[0]
                if other_username == username:
                    return '550 Username already exists'

        # Checks if username is valid (using local part of domain from RFC standard)
        if not self._validate_input(username, r'(((([a-zA-Z0-9])|(\\.))+)(\.(([a-zA-Z0-9])|(\\.))+)*)|'
                                              r'(\"\"\"(([a-zA-Z0-9])|(\\.))+\"\"\")', True):
            user_info.close()
            return '553 Invalid username'
        else:
            user_info.close()
            user_info = open(self._user_file_name, 'a')
            # Generates salt string
            salt = ''
            for i in range(40):
                salt += random.choice(string.ascii_letters)

            # Salts and hashes password before writing them to a text file
            salted_password_hash = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
            user_info.write(username + ' ' + salted_password_hash + ' ' + str(salt) + '\n')
            user_info.close()
            # Makes mailing list file for user
            mailing_list = open('MailFiles\\MailingLists\\' + username + '.txt', 'w')
            mailing_list.close()
            return '250 OK'

    def _login(self, username, password) -> str:
        """Checks if username and password match existing user in text file"""
        user_info = open(self._user_file_name, 'r')
        all_info = user_info.readlines()
        for line in all_info:
            line_parts = line.split(' ')
            salt = line_parts[2].replace('\n', '')
            if line_parts[0] == username:
                # Gets salt then applies it to the password and hashes it.
                # If the result matches the one in the file then the password is correct
                salted_password_hash = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
                if salted_password_hash == line_parts[1]:
                    user_info.close()
                    return '250 OK'
                else:
                    user_info.close()
                    return '550 Password incorrect'
        # If no username matches then the user does not exist
        user_info.close()
        return '550 User not found'

    @staticmethod
    def _mailbox_exists(email) -> bool:
        """Checks if mailbox exists"""
        return os.path.exists('MailFiles\\Mailboxes\\' + email)

    def _access_to_mailbox(self, email) -> bool:
        """Checks if current user has access to mailbox"""
        users_file = open('MailFiles\\Mailboxes\\' + email + '\\users.txt', 'r')
        # Compares username to usernames in the file
        for user in users_file.readlines():
            if self._current_user == user.replace('\n', ''):
                users_file.close()
                return True
        users_file.close()
        return False

    def _create_mailbox(self, email, password) -> str:
        """Creates a new mailbox if it does not exist. User data is salted and hashed"""
        if self._validate_email(email):
            if not self._mailbox_exists(email):
                # If email is valid and does not already exist, a new directory is created for this mailbox
                # This directory contains 4 files:
                #                  - salt (stores the salt string for the password hash)
                #                  - password (stores the salted and hashed password)
                #                  - users (stores the usernames of users who can access this mailbox)
                #                  - emails (stores all emails sent to this mailbox)
                os.makedirs('MailFiles\\Mailboxes\\'+email)
                # Generates salt string
                salt = ''
                for i in range(40):
                    salt += random.choice(string.ascii_letters)
                # Stores salt
                salt_file = open('MailFiles\\Mailboxes\\'+email+'\\salt.txt', 'w')
                salt_file.write(salt)
                salt_file.close()
                salted_password_hash = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
                # Stores salted and hashed password
                password_file = open('MailFiles\\Mailboxes\\' + email + '\\password.txt', 'w')
                password_file.write(salted_password_hash)
                password_file.close()
                # Creates empty users and emails files
                users_file = open('MailFiles\\Mailboxes\\' + email + '\\users.txt', 'w')
                users_file.close()
                emails_file = open('MailFiles\\Mailboxes\\' + email + '\\emails.txt', 'w')
                emails_file.close()
            else:
                return '550 mailbox already exists'
        else:
            return '553 Invalid email'
        return '250 OK'

    def _link_mailbox(self, email, password) -> str:
        """Links mailbox to current user"""
        if self._mailbox_exists(email):
            # Gets salt from file
            salt_file = open('MailFiles\\Mailboxes\\' + email + '\\salt.txt', 'r')
            salt = salt_file.readline()
            salt_file.close()
            salted_password_hash = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
            password_file = open('MailFiles\\Mailboxes\\' + email + '\\password.txt', 'r')
            # Compares salted password hash to one in password file for authentication
            if salted_password_hash == password_file.readline():
                password_file.close()
                users_file = open('MailFiles\\Mailboxes\\' + email + '\\users.txt', 'r')
                already_linked = False
                for line in users_file.readlines():
                    if self._current_user in line:
                        already_linked = True
                users_file.close()
                # If username hash not already in the file it is added
                if not already_linked:
                    users_file = open('MailFiles\\Mailboxes\\' + email + '\\users.txt', 'a')
                    users_file.write(self._current_user + '\n')
                    users_file.close()
                return '250 OK'
            else:
                password_file.close()
                return '550 Password incorrect'
        else:
            return '550 Mailbox not found'

    @staticmethod
    def _get_mailbox(username):
        """Returns mailbox of specified user"""
        # Checks all mailboxes to see if user is linked
        # If it is linked, it is added to the list that is returned
        linked_mailboxes = []
        for subdir, dirs, files in os.walk('MailFiles\\Mailboxes'):
            for file in files:
                if 'users.txt' in file:
                    user_file = open(os.path.join(subdir, file), 'r')
                    for line in user_file.readlines():
                        if username in line:
                            linked_mailboxes.append([line.replace('\n', ''), subdir.split('\\')[2]])
                    user_file.close()
        if linked_mailboxes:
            return linked_mailboxes
        else:
            return 'User ambiguous'

    def _get_mailing_list(self, mailing_list):
        """Returns mailing list if it exists"""
        mailing_lists = open('MailFiles\\MailingLists\\' + self._current_user + '.txt', 'r')
        for line in mailing_lists.readlines():
            if line.split(':')[0] == mailing_list:
                mailing_lists.close()
                return line.split(':')[1]
        mailing_lists.close()
        return False

    def _update_state_machine(self):
        """Updates the state machine by shifting states back"""
        self._previous_state = self.current_state
        self.current_state = self._next_state
        self._next_state = None

    def _save_email_to_file(self):
        """Writes email to text file"""
        timestamp = datetime.datetime.now()
        for recip in self._recipients:
            if os.path.exists('MailFiles\\Mailboxes\\' + recip):
                file = open('MailFiles\\Mailboxes\\' + recip + '\\emails.txt', 'a')
                # Writes sender, recipients, data and a time stamp to the file
                file.write('Sender: ' + self._sender)
                file.write('\nRecipients: ')
                for recipient in self._recipients:
                    file.write('<' + recipient + '>')
                file.write('\nData: ')
                for line in self._data:
                    file.write('\n' + line)
                file.write('\nSent: ' + timestamp.strftime('%x') + ' ' + timestamp.strftime('%X'))
                file.write('\n-\n')
                file.close()

    def _get_dates_from_message(self, message):
        """Extracts one or two dates from message if they exist"""
        date1 = None
        date2 = None
        msg_parts = message.split(' ')
        if len(msg_parts) >= 4:
            year = msg_parts[3]
            month = str(self._months.index(msg_parts[2]) + 1)
            if int(month) < 10:
                month = '0' + month
            day = msg_parts[1]
            if int(day) < 10:
                day = '0' + day
            date1 = month + '/' + day + '/' + year
        if len(msg_parts) == 7:
            year = msg_parts[6]
            month = str(self._months.index(msg_parts[5]) + 1)
            if int(month) < 10:
                month = '0' + month
            day = msg_parts[4]
            if int(day) < 10:
                day = '0' + day
            date2 = month + '/' + day + '/' + year
        return date1, date2

    def _retrieve_emails(self, message, get_all=False):
        """Gets all emails sent to specified email address given no arguments.
        One date or date range can also be specified"""
        date1, date2 = self._get_dates_from_message(message)

        emails_file = open('MailFiles\\Mailboxes\\' + message.split(' ')[0] + '\\emails.txt', 'r')
        current_email = ''
        all_emails = []
        date_sent = None
        for line in emails_file.readlines():
            current_email += line
            # -\n marks the end of each email
            if line == '-\n':
                if get_all:
                    all_emails.append(current_email)
                # _DELETED_ flag specifies that this email has been deleted and should not be returned
                elif '_DELETED_' not in current_email:
                    # If no dates provided, return all (that aren't deleted)
                    if date1 is None and date2 is None:
                        all_emails.append(current_email)
                    # If 1 date provided, return all sent on that date (that aren't deleted)
                    elif date2 is None:
                        if date1 == date_sent:
                            all_emails.append(current_email)
                    # If 2 date provided, return all sent between these dates (that aren't deleted)
                    else:
                        if date1 <= date_sent <= date2:
                            all_emails.append(current_email)
                current_email = ''
            # Extracts date sent from email
            elif 'Sent: ' in line:
                date_sent = line.split(' ')[1]
        emails_file.close()
        return all_emails

    def _delete_email(self, message) -> int:
        """Deletes all emails sent to specified email address given no arguments.
        One date or date range can also be specified"""
        date1, date2 = self._get_dates_from_message(message)

        emails_deleted = 0
        all_emails = self._retrieve_emails(message, True)
        index = 0
        date_sent = None
        for email in all_emails:
            # Splits email into lines
            for line in email.split('\n'):
                # Extracts date sent from email
                if 'Sent: ' in line:
                    date_sent = line.split(' ')[1]
            if '_DELETED_' not in email:
                # Used _DELETED_ to mark deleted emails rather than actually deleting them
                # This allows for deleted emails to be recovered in the future
                if date1 is None and date2 is None:
                    all_emails[index] = '_DELETED_\n' + email
                    emails_deleted += 1
                elif date2 is None:
                    if date1 == date_sent:
                        all_emails[index] = '_DELETED_\n' + email
                        emails_deleted += 1
                else:
                    if date1 <= date_sent <= date2:
                        all_emails[index] = '_DELETED_\n' + email
                        emails_deleted += 1
            index += 1

        # Writes all emails back to file
        emails = open('MailFiles\\Mailboxes\\' + message.split(' ')[0] + '\\emails.txt', 'w')
        for email in all_emails:
            emails.write(email)
        emails.close()
        return emails_deleted

    def _module_processor(self, command, message):
        """Carries out commands specified by the client"""
        # If expecting data, do not treat messages as commands, instead just add data that is sent
        if self.current_state == 'DATA':
            # Unreachable return codes:
            transaction_failed, error, insufficient_storage = False, False, False
            if transaction_failed:
                self._create_message('554 Transaction failed')
            elif error:
                self._create_message('451 Local error in processing')
            elif insufficient_storage:
                self._create_message('452 Insufficient system storage')
            # -
            else:
                data = command + message
                # Saves data to file when data stream is terminated with a '.'
                if data == '.':
                    self._save_email_to_file()
                    self._next_state = 'OTHER_STATE'
                    self._update_state_machine()
                    self._create_message('250 OK')
                else:
                    # Ensures data doesn't go over specified maximum
                    if len(data) <= 1000:
                        self._data.append(data)
                    else:
                        self._create_message('552 Too much mail data')

        else:
            # Ensures command line isn't too long
            if len(command + message) <= 512:
                # Strips left space and control characters from the message
                # Saves message with space for use in input validation
                message = message.replace('\r', '')
                message = message.replace('\n', '')
                original_message = message
                message = message.lstrip()

                # Checks for all commands and carries out their functions
                # Ignores command case as specified in RFC docs
                if command.upper() == 'HELO':
                    if self.current_state == 'NEGOTIATE':
                        if message != '':
                            if self._validate_domain(message):
                                if self.current_state == 'TERMINATE':
                                    self._create_message('421 ' + self._addr +
                                                         ' Service not available, closing transmission channel')
                                else:
                                    # Unreachable return code:
                                    param_not_implemented = False
                                    if param_not_implemented:
                                        self._create_message('504 Command parameter not implemented')
                                    # -
                                    else:
                                        # Moves to next state
                                        self._next_state = 'LOGIN'
                                        self._update_state_machine()
                                        self._client_domain = message
                                        self._create_message('250 OK ' + self._domain)
                            else:
                                self._create_message('501 Domain invalid')
                        else:
                            self._create_message('501 Syntax error')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'MAKE':
                    if self.current_state == 'LOGIN':
                        if self._validate_input(original_message, r'(^ \S+ \S+$)'):
                            # Gets username and password from message, checks username is not too long
                            # before attempting to create account
                            username = message.split(' ')[0]
                            if len(username) <= 64:
                                password = message.split(' ')[1]
                                result = self._create_account(username, password)
                                self._create_message(result)
                            else:
                                self._create_message('501 Username too long')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'LOGI':
                    if self.current_state == 'LOGIN':
                        if self._validate_input(original_message, r'(^ \S+ \S+$)'):
                            # Gets username and password from message, attempts login
                            username = message.split(' ')[0]
                            password = message.split(' ')[1]
                            result = self._login(username, password)
                            if result == '250 OK':
                                self._current_user = username
                                self._next_state = 'OTHER_STATE'
                                self._update_state_machine()
                            self._create_message(result)
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'MBOX':
                    if self.current_state == 'OTHER_STATE':
                        if self._validate_input(original_message, r'(^ \S+ \S+$)'):
                            # Gets email and password from message, attempts to create a new mailbox
                            email = message.split(' ')[0]
                            password = message.split(' ')[1]
                            result = self._create_mailbox(email, password)
                            self._create_message(result)
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'LINK':
                    if self.current_state == 'OTHER_STATE':
                        if self._validate_input(original_message, r'(^ \S+ \S+$)'):
                            # Gets email and password from message, attempts to link account to mailbox
                            email = message.split(' ')[0]
                            password = message.split(' ')[1]
                            result = self._link_mailbox(email, password)
                            self._create_message(result)
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'MAIL':
                    if self.current_state == 'OTHER_STATE':
                        if self._validate_input(original_message, r'(^ F|fR|rO|oM|m:<\S+>$)'):
                            # Unreachable return codes:
                            error, insufficient_storage,  exceeded_storage = False, False, False
                            if error:
                                self._create_message('451 Local error in processing')
                            elif insufficient_storage:
                                self._create_message('452 Insufficient system storage')
                            elif exceeded_storage:
                                self._create_message('552 Exceeded storage allocation')
                            # -
                            else:
                                # Gets email, validates it and checks if the user has access to it
                                # If so the sender is set to the mailbox specified
                                email = message.split('<')[1].split('>')[0]
                                if self._validate_email(email):
                                    if self._access_to_mailbox(email):
                                        self._next_state = 'MAIL'
                                        self._update_state_machine()
                                        self._sender = email
                                        self._recipients = []
                                        self._create_message('250 OK')
                                    else:
                                        self._create_message('550 No access to mailbox')
                                else:
                                    self._create_message('553 Email address invalid')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'RCPT':
                    if self.current_state == 'MAIL' or self.current_state == 'RCPT':
                        if self._validate_input(original_message, r'(^ T|tO|o:<\S+>$)'):
                            # Unreachable return codes:
                            not_local_but_found, not_local, unavailable, error, insufficient_storage = \
                                False, False, False, False, False
                            if not_local_but_found:
                                self._create_message('251 User not local; will forward to <forward-path>')
                            elif not_local:
                                self._create_message('551 User not local; please try <forward-path>')
                            elif unavailable:
                                self._create_message('450 Mailbox unavailable')
                            elif error:
                                self._create_message('451 Local error in processing')
                            elif insufficient_storage:
                                self._create_message('452 Insufficient system storage')
                            # -
                            else:
                                # Gets email, validates it and checks it exists
                                # Also checks if recipient list is not a cap of 100
                                # Recipient is then added to the list
                                if '<' in message:
                                    email = message.split('<')[1].split('>')[0]
                                else:
                                    email = message.split(':')[1]

                                if self._validate_email(email):
                                    if self._mailbox_exists(email):
                                        if len(self._recipients) < 100:
                                            self._next_state = 'RCPT'
                                            self._update_state_machine()
                                            self._recipients.append(email)
                                            self._create_message('250 OK')
                                        else:
                                            self._create_message('552 Too many recipients')
                                    else:
                                        self._create_message('550 No such user here')
                                else:
                                    self._create_message('553 Email address invalid')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'DATA':
                    if self.current_state == 'RCPT':
                        if original_message == '':
                            # Unreachable return codes:
                            error, transaction_failed = False, False
                            if error:
                                self._create_message('451 Local error in processing')
                            elif transaction_failed:
                                self._create_message('554 Transaction failed')
                            # -
                            else:
                                # Changes state to expect data stream
                                self._next_state = 'DATA'
                                self._update_state_machine()
                                self._data = []
                                self._create_message('354 Start mail input; end with <CRLF>.<CRLF>')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'RSET':
                    if self.current_state in ['LOGIN', 'OTHER_STATE', 'MAIL', 'RCPT']:
                        if original_message == '':
                            # Unreachable return code:
                            param_not_implemented = False
                            if param_not_implemented:
                                self._create_message('504 Command parameter not implemented')
                            # -
                            else:
                                # Resets sender, recipients and data. Logs user out
                                self._next_state = 'NEGOTIATE'
                                self._update_state_machine()
                                self._sender = None
                                self._current_user = None
                                self._recipients = None
                                self._data = None
                                self._create_message('250 OK')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'VIEW':
                    if self.current_state == 'OTHER_STATE':
                        if self._validate_input(original_message,
                                                r'(^ \S+( ([1-9]|1[0-9]|2[0-9]|3[0-1]) '
                                                r'(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)'
                                                r' [0-9][0-9]){0,2}$)'):
                            if self._mailbox_exists(message.split(' ')[0]):
                                if self._access_to_mailbox(message.split(' ')[0]):
                                    # Gets emails from mailbox if the user has access to it
                                    output = self._retrieve_emails(message)
                                    if not output:
                                        self._create_message('450 No emails found')
                                    else:
                                        for email in output:
                                            self._create_message('250:\n' + str(email))
                                else:
                                    self._create_message('550 No access to mailbox')
                            else:
                                self._create_message('550 Mailbox not found')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'DLTE':
                    if self.current_state == 'OTHER_STATE':
                        if self._validate_input(original_message,
                                                r'(^ \S+( ([1-9]|1[0-9]|2[0-9]|3[0-1]) '
                                                r'(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)'
                                                r' [0-9][0-9]){0,2}$)'):
                            if self._mailbox_exists(message.split(' ')[0]):
                                if self._access_to_mailbox(message.split(' ')[0]):
                                    # Deletes emails from mailbox if the user has access to it
                                    outcome = self._delete_email(message)
                                    if outcome == 0:
                                        self._create_message('450 No emails found')
                                    elif outcome == 1:
                                        self._create_message('250 ' + str(outcome) + ' email deleted')
                                    else:
                                        self._create_message('250 ' + str(outcome) + ' emails deleted')
                                else:
                                    self._create_message('550 No access to mailbox')
                            else:
                                self._create_message('550 Mailbox not found')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == "VRFY":
                    if self.current_state in ['OTHER_STATE', 'MAIL', 'RCPT']:
                        if self._validate_input(original_message, r'(^ \S+$)'):
                            # Unreachable return codes:
                            not_local_but_found, not_local, not_implemented, param_not_implemented = \
                                False, False, False, False
                            if not_local_but_found:
                                self._create_message('251 User not local; will forward to <forward-path>')
                            elif not_local:
                                self._create_message('551 User not local; please try <forward-path>')
                            elif not_implemented:
                                self._create_message('502 Command not implemented')
                            elif param_not_implemented:
                                self._create_message('504 Command parameter not implemented')
                            # -
                            else:
                                # Attempts to get mailbox(es) linked to username
                                output = self._get_mailbox(message)
                                if output == 'User ambiguous':
                                    self._create_message('553 User ambiguous')
                                elif output:
                                    for mailbox in output:
                                        username, email = mailbox
                                        self._create_message('250 ' + username + ' <' + email + '>')
                                else:
                                    self._create_message('550 Mailbox not found')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == "EXPN":
                    if self.current_state in ['OTHER_STATE', 'MAIL', 'RCPT']:
                        if self._validate_input(original_message, r'(^ .+$)'):
                            # Unreachable return codes:
                            not_implemented, param_not_implemented = False, False
                            if not_implemented:
                                self._create_message('502 Command not implemented')
                            elif param_not_implemented:
                                self._create_message('504 Command parameter not implemented')
                            # -
                            # Gets mailing list if it exists
                            output = self._get_mailing_list(message)
                            if output:
                                for email in output.split(','):
                                    self._create_message('250 ' + email)
                            else:
                                self._create_message('550 Not found')
                        else:
                            self._create_message('501 Syntax error')
                    elif self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        self._create_message('503 Bad sequence of commands')

                elif command.upper() == 'HELP':
                    if self._validate_input(original_message, r'(^( \S+)?$)'):
                        # Unreachable return codes:
                        system_status, not_implemented = False, False
                        if system_status:
                            self._create_message('211 System status or system help reply')
                        elif not_implemented:
                            self._create_message('502 Command not implemented')
                        # -
                        if self.current_state == 'TERMINATE':
                            self._create_message('421 ' + self._addr +
                                                 ' Service not available, closing transmission channel')
                        else:
                            # Gets general HELP message if no parameter given
                            if message == '':
                                self._create_message('214 Here are the accepted commands for this server:\n'
                                                     '\tHELO <SP> <domain> <CRLF>\n'
                                                     '\tMAKE <SP> <string> <SP> <string> <CRLF>\n'
                                                     '\tLOGI <SP> <string> <SP> <string> <CRLF>\n'
                                                     '\tMBOX <SP> <mailbox> <SP> <string> <CRLF>\n'
                                                     '\tLINK <SP> <mailbox> <SP> <string> <CRLF>\n'
                                                     '\tMAIL <SP> FROM:<reverse-path> <CRLF>\n'
                                                     '\tRCPT <SP> TO:<forward-path> <CRLF>\n'
                                                     '\tDATA <CRLF>\n'
                                                     '\tRSET <CRLF>\n'
                                                     '\tVIEW <SP> <mailbox> [<SP> <date>] [<SP> <date>]<CRLF>\n'
                                                     '\tDLTE <SP> <mailbox> [<SP> <date>] [<SP> <date>]<CRLF>\n'
                                                     '\tVRFY <SP> <string> <CRLF>\n'
                                                     '\tEXPN <SP> <string> <CRLF>\n'
                                                     '\tHELP [<SP> <string>] <CRLF>\n'
                                                     '\tNOOP <CRLF>\n'
                                                     '\tQUIT <CRLF>\n')
                            # Gives specific HELP messages if correct parameters given
                            elif message.upper() == 'HELO':
                                self._create_message('214 HELO <SP> <domain> <CRLF>\n'
                                                     'Asks the host to identify itself\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250 <domain>\n'
                                                     '\tE: 500, 501, 504, 421\n')
                            elif message.upper() == 'MAKE':
                                self._create_message('214 MAKE <SP> <string> <SP> <string> <CRLF>\n'
                                                     'Create a new account where first string is the username '
                                                     'and second string is the password\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 550, 553, 421\n')
                            elif message.upper() == 'LOGI':
                                self._create_message('214 LOGI <SP> <string> <SP> <string> <CRLF>\n'
                                                     'Login to an existing account where first string is the username '
                                                     'and second string is the password\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 550, 421\n')
                            elif message.upper() == 'MBOX':
                                self._create_message('214 MBOX <SP> <mailbox> <SP> <string> <CRLF>\n'
                                                     'Create a new mailbox where first string is the email '
                                                     'and second string is the password (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 550, 553, 421\n')
                            elif message.upper() == 'LINK':
                                self._create_message('214 LINK <SP> <mailbox> <SP> <string> <CRLF>\n'
                                                     'Link account to a mailbox where first string is the email '
                                                     'and second string is the password\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 550, 421\n')
                            elif message.upper() == 'MAIL':
                                self._create_message('214 MAIL <SP> FROM:<reverse-path> <CRLF>\n'
                                                     'Specifies mail sender (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tF: 552, 451, 452\n'
                                                     '\tE: 500, 501, 503, 550, 553, 421\n')
                            elif message.upper() == 'RCPT':
                                self._create_message('214 RCPT <SP> TO:<forward-path> <CRLF>\n'
                                                     'Specifies mail recipients (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250, 251\n'
                                                     '\tF: 550, 551, 552, 553, 450, 451, 452\n'
                                                     '\tE: 500, 501, 503, 421\n')
                            elif message.upper() == 'DATA':
                                self._create_message('214 DATA <CRLF>\n'
                                                     'Signals start of data stream (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tI: 354 -> data -> S: 250\n'
                                                     '\t                  F: 552, 554, 451, 452\n'
                                                     '\tF: 451, 554 \n'
                                                     '\tE: 500, 501, 503, 421\n')
                            elif message.upper() == 'RSET':
                                self._create_message('214 RSET <CRLF>\n'
                                                     'Reset mail sender, recipients and data (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 504, 421\n')
                            elif message.upper() == 'VIEW':
                                self._create_message('214 VIEW <SP> <mailbox> [<SP> <date>] [<SP> <date>]<CRLF>\n'
                                                     'Retrieve all emails sent to specified mailbox given no arguments.'
                                                     ' One date or date range can also be specified (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 550, 450, 421\n')
                            elif message.upper() == 'DLTE':
                                self._create_message('214 DLTE <SP> <mailbox> [<SP> <date>] [<SP> <date>]<CRLF>\n'
                                                     'Deletes all emails to specified mailbox given no arguments. '
                                                     'One date or date range can also be specified (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 501, 503, 550, 450, 421\n')
                            elif message.upper() == 'VRFY':
                                self._create_message('214 VRFY <SP> <string> <CRLF>\n'
                                                     'Gets mailbox for given user (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250, 251\n'
                                                     '\tF: 550, 551, 553\n'
                                                     '\tE: 500, 501, 502, 503, 504, 421\n')
                            elif message.upper() == 'EXPN':
                                self._create_message('214 EXPN <SP> <string> <CRLF>\n'
                                                     'Gets specified mailing list (requires login)\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tF: 550\n'
                                                     '\tE: 500, 501, 502, 503, 504, 421\n')
                            elif message.upper() == 'HELP':
                                self._create_message('214 HELP [<SP> <string>] <CRLF>\n'
                                                     'Gives general help or specific help message given a string\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 211, 214\n'
                                                     '\tE: 500, 501, 502, 504, 421\n')
                            elif message.upper() == 'NOOP':
                                self._create_message('214 NOOP <CRLF>\n'
                                                     'Requests a 250 OK response\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 250\n'
                                                     '\tE: 500, 421\n')
                            elif message.upper() == 'QUIT':
                                self._create_message('214 QUIT <CRLF>\n'
                                                     'Terminates the connection\n'
                                                     'Possible outputs:\n'
                                                     '\tS: 221\n'
                                                     '\tE: 500\n')
                            # RFC821 commands that aren't needed in my program
                            elif message.upper() in ['SEND', 'SOML', 'SAML', 'TURN']:
                                self._create_message('504 Command parameter not implemented')
                            else:
                                self._create_message('501 Syntax error')
                    else:
                        self._create_message('501 Syntax error')

                elif command.upper() == 'NOOP':
                    if self.current_state == 'TERMINATE':
                        self._create_message('421 ' + self._addr +
                                             ' Service not available, closing transmission channel')
                    else:
                        if original_message == '':
                            self._create_message('250 OK')
                        else:
                            self._create_message('500 Syntax error')

                elif command.upper() == 'QUIT':
                    if original_message == '':
                        self._next_state = "TERMINATE"
                        self._update_state_machine()
                        self._create_message('221 ' + self._domain + ' Service closing')
                        self.close()
                    else:
                        self._create_message('500 Syntax error')

                # RFC821 commands that aren't needed in my program
                elif command.upper() in ['SEND', 'SOML', 'SAML', 'TURN']:
                    self._create_message('502 Command not implemented')

                # Commands used in Diffie Hellman key exchange
                elif command == 'DHK1':
                    self._next_state = 'NEGOTIATE'
                    self._update_state_machine()
                    self._dh_public_g = int(message)
                    self._create_message('DH1' + str(self._dh_public_n))

                elif command == 'DHK2':
                    self._gx_mod_n = int(message)
                    self._gy_mod_n = self._dh_public_g ** self._dh_private_y % self._dh_public_n
                    self._shared_key = self._gx_mod_n ** self._dh_private_y % self._dh_public_n
                    self._create_message('DH2' + str(self._gy_mod_n))

                elif command == '250 ':
                    if self.current_state == 'NEGOTIATE':
                        try:
                            # Used hash of key to make it longer
                            self.modify_encryption(True, 'vigenere',
                                                   hashlib.sha256(str(self._shared_key).encode()).hexdigest())
                            self._create_message('220 SMTP Service ready')
                        except TypeError:
                            self._create_message('421 ' + self._addr +
                                                 ' Service not available, closing transmission channel')

                elif command == '500 ':
                    print('Command unrecognised by client')
                else:
                    self._write_to_audit_log('Unknown command received')
                    self._create_message('500 Unknown command')

                if command.upper() in self._expected_commands:
                    self._write_to_audit_log('Command: ' + command)
            else:
                self._create_message('500 Command line too long')

    def close(self):
        """Closes connection to client and terminates thread"""
        if self._outgoing_buffer.qsize() > 0:
            return False
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
