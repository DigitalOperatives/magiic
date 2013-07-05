#!/usr/bin/env python

import sys
import re
import os.path
import getpass
import imaplib
import email
from email.Iterators import typed_subpart_iterator
import email.utils
import argparse
import datetime
def _tryimport(module_name, import_command = None, module_url = None):
    if import_command == None:
        import_command = "import " + module_name
    try:
        exec(import_command) in globals()
    except ImportError:
        sys.stderr.write("Error loading module " + module_name + "!\nPlease make sure you have it installed.\n")
        if module_url != None:
            sys.stderr.write("For instructions on doing so, please visit " + module_url + "\n")
        sys.stderr.write("\n")
        exit(1)
_imports = {
    'gnupg' : {'url' : 'https://code.google.com/p/python-gnupg/'},
    'whoosh.index' : {'url' : 'https://pypi.python.org/pypi/Whoosh/', 'cmd' : 'from whoosh.index import create_in, open_dir'},
    'whoosh.fields' : {'url' : 'https://pypi.python.org/pypi/Whoosh/', 'cmd' : 'from whoosh.fields import *'},
    'whoosh.qparser' : {'url' : 'https://pypi.python.org/pypi/Whoosh/', 'cmd' : 'from whoosh.qparser import QueryParser, MultifieldParser'},    
}
for module_name, vals in _imports.iteritems():
    import_command = None
    if 'cmd' in vals:
        import_command = vals['cmd']
    module_url = None
    if 'url' in vals:
        module_url = vals['url']
    _tryimport(module_name, import_command = import_command, module_url = module_url)

def get_charset(message, default="ascii"):
    """Get the message charset"""

    if message.get_content_charset():
        return message.get_content_charset()

    if message.get_charset():
        return message.get_charset()

    return default

def get_body(message):
    """Get the body of the email message"""

    if message.is_multipart():
        #get the plain text version only
        text_parts = [part
                      for part in typed_subpart_iterator(message,
                                                         'text',
                                                         'plain')]
        text_parts += [part
                      for part in typed_subpart_iterator(message,
                                                         'application',
                                                         'pgp-encrypted')]
        body = []
        for part in text_parts:
            charset = get_charset(part, get_charset(message))
            body.append(unicode(part.get_payload(decode=True),
                                charset,
                                "replace"))

        return u"\n".join(body).strip()

    else: # if it is not multipart, the payload will be a string
          # representing the message body
        body = unicode(message.get_payload(decode=True),
                       get_charset(message),
                       "replace")
        return body.strip()

class Index:
    def __init__(self, gpg_user, index_dir = None):
        if index_dir == None:
            index_dir = os.path.join(os.path.expanduser("~"), ".magiic")
        self.index_dir = index_dir
        self.gpg = gnupg.GPG()
        self.gpg_user = gpg_user
        self._passphrase = getpass.getpass("GPG Password for " + gpg_user + ": ")
        if not os.path.exists(index_dir):
            os.makedirs(index_dir)
            schema = Schema(subject=TEXT(stored=True), date=DATETIME(stored=True), sender=TEXT(stored=True), idx=ID(stored=True), body=TEXT(stored=True))
            self.index = create_in(index_dir, schema)
        else:
            for f in map(lambda x : os.path.join(index_dir, x), os.listdir(index_dir)):
                if f.endswith(".enc"):
                    with open(f, 'rb') as ef:
                        self.gpg.decrypt_file(ef, passphrase=self._passphrase, output=f[:-4])
            self.index = open_dir(index_dir)
    def save(self):
        sys.stderr.write("\nRe-Encrypting the Index...")
        self.index.optimize()
        for f in map(lambda x : os.path.join(self.index_dir, x), os.listdir(self.index_dir)):
            if not f.endswith(".enc"):
                with open(f, 'rb') as ef:
                    self.gpg.encrypt_file(ef, recipients=[self.gpg_user], output=f + ".enc")
        sys.stderr.write("\n")
    def __enter__(self):
        return self
    def __exit__(self, type, value, traceback):
        for f in map(lambda x : os.path.join(self.index_dir, x), os.listdir(self.index_dir)):
            if not f.endswith(".enc"):
                os.unlink(f)
    def get_by_id(self, idx, searcher = None):
        if searcher == None:
            with self.searcher() as s:
                return self.get_by_id(idx, s)
        else:
            query = QueryParser("idx", self.index.schema).parse(unicode(idx))
            results = searcher.search(query)
            if len(results) == 0:
                return None
            else:
                return dict(results[0])
    def searcher(self):
        return self.index.searcher()
    def __getitem__(self, idx):
        return self.get_by_id(idx)
    def query(self, string):
        with self.searcher() as s:
            query = MultifieldParser(["body","subject","sender"], self.index.schema).parse(unicode(string))
            return map(lambda x : (unicode(x['sender']), x['date'], unicode(x['subject']), unicode(x['body'])), s.search(query))
    def __iadd__(self, email):
        self.add(email)
        return self
    def decrypt(self, text):
        d = self.gpg.decrypt(text.group(0), passphrase=self._passphrase)
        if not d.ok:
            return text
            #raise Exception("Decryption Error!")
        return d.data
    def add(self, email_msg, writer = None):
        if writer == None:
            writer = self.index.writer()
            r = self.add(email_msg, writer)
            if r:
                writer.commit()
            else:
                writer.cancel()
            return r
        else:
            b = get_body(email_msg)
            try:
                b = re.sub(r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----", self.decrypt, b, flags=re.DOTALL)
            except Exception:
                return False
            date = None
            date_str = email_msg['date']
            if date_str:
                date_tuple=email.utils.parsedate_tz(date_str)
                if date_tuple:
                    date=datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
            writer.add_document(subject = unicode(email_msg['Subject']), date = date, sender = unicode(email_msg['From']), idx = unicode(email_msg['Message-ID']), body = b)
            return True

class Monitor:
    def __init__(self, screen, results, queries):
        self.screen = screen
        self.height, self.width = self.screen.getmaxyx()
        #self.screen.nodelay(1)
        self.results = results
        self.offset = 0
        self.idx = 0
        self.viewing = None
        self.view_offset = 0
        self.queries = set(queries)

    def get_name(self, from_name):
        from_name = re.sub(r"<[^>]*>", "", from_name)
        from_name = from_name.strip()
        if from_name[0] == '"' or from_name[0] == "'":
            from_name = from_name[1:]
        if from_name[-1] == '"' or from_name[-1] == "'":
            from_name = from_name[:-1]
        return from_name

    def redraw(self):
        self.screen.clear()
        if self.viewing:
            for i in range(min(len(self.viewing),self.height)):
                line = self.viewing[i + self.view_offset]
                try:
                    self.screen.addstr(i, 0, line)
                except Exception:
                    pass
                for q in self.queries:
                    for m in re.finditer(q, line, re.IGNORECASE):
                        try:
                            self.screen.addstr(i, m.start(), q, curses.A_BOLD)
                        except Exception:
                            pass
        else:
            for i in range(min(len(self.results),self.height)):
                date = ""
                d = self.results[i+self.offset][1]
                if d:
                    date = d.strftime("%h %d, %Y")
                s = "%-12s %-20s %s" % (date, self.get_name(self.results[i+self.offset][0]), self.results[i+self.offset][2])
                if i == self.idx:
                    self.screen.addstr(i,0,s,curses.A_STANDOUT)
                else:
                    self.screen.addstr(i,0,s)
        self.screen.refresh()

    def main(self):
        curses.use_default_colors()
        self.redraw()
        while 1:
            key = self.screen.getch()
            if key == 27 or key == ord('q') or key == curses.KEY_EXIT or (self.viewing and key == ord('i')):
                if self.viewing:
                    self.viewing = None
                else:
                    break
            elif key == curses.KEY_PPAGE:
                if self.viewing:
                    self.view_offset -= self.height
                else:
                    self.idx -= self.height
            elif key == curses.KEY_NPAGE or (self.viewing and key == ord(' ')):
                if self.viewing:
                    self.view_offset += self.height
                else:
                    self.idx += self.height
            elif key == curses.KEY_DOWN or key == ord('j'):
                if self.viewing:
                    self.view_offset += 1
                else:
                    self.idx += 1
            elif key == curses.KEY_UP or key == ord('k'):
                if self.viewing:
                    self.view_offset -= 1
                else:
                    self.idx -= 1
            if self.idx < 0:
                self.idx = 0
            if self.idx < self.offset:
                self.offset = self.idx
            if self.idx - self.offset >= self.height or self.idx >= len(self.results):
                self.idx = min(self.height - 1, len(self.results) - 1)
            if self.idx >= self.offset + self.height:
                self.offset = self.idx - self.height + 1
            if self.viewing and self.view_offset > len(self.viewing) - self.height:
                self.view_offset = len(self.viewing) - self.height
            if self.view_offset < 0:
                self.view_offset = 0
            if key == curses.KEY_ENTER or key == curses.KEY_OPEN or key == ord(' ') or key == ord('\n') or key == ord('\r') or key == ord('o'):
                if not self.viewing:
                    self.viewing = self.results[self.idx][3].split("\n")
                    self.view_offset = 0
            self.redraw()

results = None
def show_results(stdscr):
    global results
    global args
    mon = Monitor(stdscr, results, args.QUERY)
    mon.main()

if __name__ == "__main__":
    muttrc = os.path.join(os.path.expanduser("~"), ".muttrc")
    mutt_imap_user = None
    mutt_imap_server = None
    mutt_gpg_email = None
    if os.path.exists(muttrc):
        with open(muttrc, 'r') as rc:
            for line in rc:
                m = re.match(r'\s*set\s+spoolfile\s*=\s*"imaps://([^@]+)@([^/]+)/"', line)
                if m:
                    mutt_imap_user = m.group(1)
                    mutt_imap_server = m.group(2)
                else:
                    m = re.match(r'\s*my_hdr\s+[Ff][Rr][Oo][Mm]:.*?\b([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+)\b', line)
                    if m:
                        mutt_gpg_email = m.group(1)

    argparser = argparse.ArgumentParser(description='Magiic Allows for GPG Indexing of IMAP on the Command-line.')
    argparser.add_argument('QUERY', nargs='*', help='the string(s) to query.  If none are provided, Magiic will sync its index with the E-mails in your inbox.')
    if mutt_imap_user:
        argparser.add_argument('--user', '-u', type=str, default=mutt_imap_user, help="IMAP username", required=False)
    else:
        argparser.add_argument('--user', '-u', type=str, help="IMAP username", required=True)
    if mutt_gpg_email:
        argparser.add_argument('--email', '-e', type=str, default=mutt_gpg_email, help="E-Mail address associated with your GPG private key", required=False)
    else:
        argparser.add_argument('--email', '-e', type=str, help="E-Mail address associated with your GPG private key", required=True)
    if mutt_imap_server:
        argparser.add_argument('--server', '-s', type=str, default=mutt_imap_server, help="IMAP server hostname", required=False)
    else:
        argparser.add_argument('--server', '-s', type=str, help="IMAP server address", required=True)

    args = argparser.parse_args()

    with Index(args.email) as index:
        if len(args.QUERY) > 0:
            results = [email for query in args.QUERY for email in index.query(query)]
            if len(results) == 0:
                sys.stderr.write("No results.\n")
                exit(0)
            import curses
            try:
                curses.wrapper(show_results)
            except KeyboardInterrupt:
                pass
            exit(0)
        imap = imaplib.IMAP4_SSL(args.server)
        imap.login(args.user, getpass.getpass("IMAP Password for " + args.user + ": "))
        try:
            imap.select('INBOX', True)
            typ, data = imap.search(None, 'ALL')
            emails = data[0].split()
            d = str(len(str(len(emails))))
            f = "\r" + " "*100 + "\r%" + d + "d/%" + d + "d %8s %s"
            updated = False
            with index.searcher() as s:
                for i, num in enumerate(emails):
                    typ, data = imap.fetch(num, '(BODY.PEEK[HEADER.FIELDS (Message-ID)])')
                    msg = email.message_from_string(data[0][1])
                    doc = index.get_by_id(msg['Message-ID'])
                    if doc == None:
                        sys.stderr.write(f % (i+1, len(emails), "Adding", msg['Message-ID']))
                        sys.stderr.flush()
                        # Fetch the whole E-Mail
                        typ, data = imap.fetch(num, '(RFC822)')
                        msg = email.message_from_string(data[0][1])
                        writer = index.index.writer()
                        if index.add(msg, writer):
                            updated = True
                            writer.commit(merge = False)
                        else:
                            writer.cancel()
                            sys.stderr.write("\r" + " "*100 + "\rError decrypting E-Mail:\n\t" + str(msg['Message-ID']) + " (IMAP ID: " + str(num) + ")\n\tFrom: " + str(msg['From']) + "\n\tDate: " + str(msg['date']) + "\n\tSubject: " + str(msg['Subject']))
                            sys.stderr.flush()
                    else:
                        sys.stderr.write(f % (i+1, len(emails), "Skipping", msg['Message-ID']))
                        sys.stderr.flush()
                    if i % 100 == 0 and i > 0 and updated:
                        sys.stderr.write("\r" + " "*100 + "\rOptimizing the index...")
                        sys.stderr.flush()
                        index.index.optimize()
                        updated = False
        except KeyboardInterrupt:
            pass
        finally:
            index.save()
            imap.close()
            imap.logout()
