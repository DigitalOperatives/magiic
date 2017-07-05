#!/usr/bin/env python

## Magiic Allows for GPG Indexing of IMAP on the Command-line (MAGIIC)
##
##     Version:	1.0
##        Date:	2013-07-12
##      Author:	Evan A. Sultanik, Ph.D.
##   Copyright:	2013, Digital Operatives, LLC
##
## This software is licensed under a version of the Creative Commons
## BY-NC-SA 3.0 license modified to be more applicable for software
## licensing.  In general:
## 
##   * you are permitted to modify the software in any way;
##
##   * you are permitted to redistribute the software as long as you
##     retain the same license and attributions; and
##
##   * you can use the software in any non-commercial way.
##
## For specific details on the license, please see the LICENSE file
## included with this software.
## 
## For information on commercial licensing, please contact
## info _ at _ digitaloperatives.com
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
## WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
## ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
## (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
## LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
## ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
## (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
## SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
        sys.stderr.write("[!] Error loading module " + module_name + "!\nPlease make sure you have it installed.\n")
        if module_url != None:
            sys.stderr.write("[!] For instructions on doing so, please visit " + module_url + "\n")
        sys.stderr.write("\n")
        exit(1)

_imports = {
    'gnupg' : {'url' : 'https://code.google.com/p/python-gnupg/'},
    'whoosh.index' : {'url' : 'https://pypi.python.org/pypi/Whoosh/', 'cmd' : 'from whoosh.index import create_in, open_dir'},
    'whoosh.fields' : {'url' : 'https://pypi.python.org/pypi/Whoosh/', 'cmd' : 'from whoosh.fields import *'},
    'whoosh.qparser' : {'url' : 'https://pypi.python.org/pypi/Whoosh/', 'cmd' : 'from whoosh.qparser import QueryParser, MultifieldParser'},    
}

# Import modules dynamically
for module_name, vals in _imports.iteritems():
    import_command = None
    if 'cmd' in vals:
        import_command = vals['cmd']
    module_url = None
    if 'url' in vals:
        module_url = vals['url']
    _tryimport(module_name, import_command = import_command, module_url = module_url)

# Get secret keys
gpg = gnupg.GPG(homedir='~/.gnupg')
secret_keys = gpg.list_keys(secret=True)
default_gpg_id = None
if len(secret_keys) == 0:
    sys.stderr.write("[!] No GPG private keys could be found, exiting\n")
    exit(1)
elif len(secret_keys) == 1:
    default_gpg_id = str(secret_keys[0]['keyid'])
gpg_secret_key_map = {}
email_part_pattern = re.compile('.*<([^>]+)>')
for key in secret_keys:
    keyidstr = str(key['keyid'])
    gpg_secret_key_map[key['keyid']] = keyidstr
    gpg_secret_key_map[key['keyid'][-8:]] = keyidstr
    gpg_secret_key_map[key['fingerprint'][-8:]] = keyidstr
    for uid in key['uids']:
        gpg_secret_key_map[uid] = keyidstr
        if email_part_pattern.match(uid):
            gpg_secret_key_map[email_part_pattern.match(uid).group(1)] = keyidstr

def get_charset(message, default="ascii"):
    """Get the message charset"""

    if message.get_content_charset():
        return message.get_content_charset()

    if message.get_charset():
        return message.get_charset()

    return default

def get_body(message):
    if message.is_multipart():
        text_parts = [part for part in typed_subpart_iterator(message, 'text', 'plain')]
        text_parts += [part for part in typed_subpart_iterator(message, 'application', 'pgp-encrypted')]
        text_parts += [part for part in typed_subpart_iterator(message, 'application', 'octet-stream')]
        body = []
        for part in text_parts:
            charset = get_charset(part, get_charset(message))
            payload = part.get_payload(decode=True)
            body.append(unicode(payload, charset, "replace"))
        return u"\n".join(body).strip()
    else:
        body = unicode(message.get_payload(decode=True), get_charset(message), "replace")
        return body.strip()

class Index:
    def __init__(self, gpg_user, index_dir = None, index_suffix = "INBOX"):
        if index_dir == None:
            suffix = index_suffix
            if suffix is None or suffix == "INBOX":
                suffix = ""
            else:
                suffix = "-" + suffix
            index_dir = os.path.join(os.path.expanduser("~"), ".magiic" + suffix)
        self.index_dir = index_dir
        self.gpg = gpg
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
        sys.stderr.write("\n[+] Re-Encrypting the Index...")
        try:
            self.index.optimize()
            for f in map(lambda x : os.path.join(self.index_dir, x), os.listdir(self.index_dir)):
                if not f.endswith(".enc"):
                    with open(f, 'rb') as ef:
                        unencrypted_data = ef.read()
                        self.gpg.encrypt(unencrypted_data, self.gpg_user, output=(f+".enc"))
                    os.remove(f)
            sys.stderr.write(" done\n")
        except Exception as e:
            sys.stdout.write("[!] Exception: "+str(e) + "\n")
            sys.stdout.flush()
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
                            self.screen.addstr(i, m.start(), q, curses.A_BOLD|self.A_RED_FG)
                        except Exception:
                            pass
        else:
            for i in range(min(len(self.results),self.height)):
                date = ""
                d = self.results[i+self.offset][1]
                if d:
                    date = d.strftime("%F %T")
                date_width = 19
                name_width = 25
                screen_width = self.screen.getmaxyx()[1]
                subject_width = screen_width - date_width - name_width - 4
                dws = str(date_width)
                nws = str(name_width)
                sws = str(subject_width)
                s = ("%-"+dws+"s  %-"+nws+"."+nws+"s  %-"+sws+"."+sws+"s") % (date, self.get_name(self.results[i+self.offset][0]), self.results[i+self.offset][2])
                if i == self.idx:
                    self.screen.addstr(i,0,s,curses.A_STANDOUT)
                else:
                    self.screen.addstr(i,0,s)
        self.screen.refresh()

    def main(self):
        curses.use_default_colors()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, -1)
        self.A_RED_FG = curses.color_pair(1)
        self.redraw()
        page_back_keys    = [curses.KEY_PPAGE, ord('b'), ord(curses.ascii.ctrl('b'))]
        page_forward_keys = [curses.KEY_NPAGE, ord('f'), ord(curses.ascii.ctrl('f')), curses.ascii.SP]
        down_keys         = [curses.KEY_DOWN,  ord('j')]
        up_keys           = [curses.KEY_UP,    ord('k')]
        open_keys         = [curses.KEY_ENTER, curses.KEY_OPEN, ord(' '), ord('\n'), ord('\r'), ord('o')]
        exit_keys         = [curses.ascii.ESC, curses.KEY_EXIT, ord('q'), ord('i')]
        while 1:
            key = self.screen.getch()
            if key in exit_keys:
                if self.viewing:
                    self.viewing = None
                else:
                    break
            elif key in page_back_keys:
                if self.viewing:
                    self.view_offset -= self.height
                else:
                    self.idx -= self.height
            elif key in page_forward_keys:
                if self.viewing:
                    self.view_offset += self.height
                else:
                    self.idx += self.height
            elif key in down_keys:
                if self.viewing:
                    self.view_offset += 1
                else:
                    self.idx += 1
            elif key in up_keys:
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
            if key in open_keys:
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
    # Preprocess .muttrc if it exists
    muttrc = os.path.join(os.path.expanduser("~"), ".muttrc")
    mutt_imap_user = None
    mutt_imap_server = None
    if os.path.exists(muttrc):
        with open(muttrc, 'r') as rc:
            for line in rc:
                m = re.match(r'\s*set\s+spoolfile\s*=\s*"imaps://([^@]+)@([^/]+)/"', line)
                if m:
                    mutt_imap_user = m.group(1)
                    mutt_imap_server = m.group(2)

    # Parse arguments
    argparser = argparse.ArgumentParser(description='Magiic Allows for GPG Indexing of IMAP on the Command-line.')
    argparser.add_argument('QUERY', nargs='*', help='the string(s) to query.  If none are provided, Magiic will sync its index with the E-mails in your inbox, provided it has the information necessary (user, email, server).')
    if default_gpg_id is None:
        argparser.add_argument('--gpg-id', '-g', type=str,
            help="E-Mail address associated with your GPG private key, or the key ID itself",
            required=True)
    argparser.add_argument('--user', '-u', type=str,
        default=mutt_imap_user if mutt_imap_user else None,
        help="IMAP username"+("" if mutt_imap_user is None else " (default: %s)" % mutt_imap_user),
        required=False)
    argparser.add_argument('--server', '-s', type=str,
        default=mutt_imap_server if mutt_imap_server else None,
        help="IMAP server hostname"+("" if mutt_imap_server is None else " (default: %s)" % mutt_imap_server),
        required=False)
    argparser.add_argument('--mailbox', '-m', type=str, help="The mailbox to index and/or search from (default is INBOX)", required=False, default="INBOX")
    argparser.add_argument('--full', '-f', action='store_true', help="Perform a full import.  Without this option, the import stops when it reaches a message that it has already indexed.")
    args = argparser.parse_args()

    # Enforce the two modes of operation: either query mode or indexing mode
    if len(args.QUERY) == 0 and (args.user is None or args.gpg_id is None or args.server is None):
        argparser.print_help()
        sys.exit(2)

    # Ensure we will encrypt the index to something it is possible to decrypt
    if default_gpg_id is not None:
        gpg_user = default_gpg_id
    else:
        if args.gpg_id not in gpg_secret_key_map:
            sys.stderr.write("[!] Unable to find private key for \"%s\", exiting.\n" % args.gpg_id)
            sys.stderr.flush()
            exit(1)
        gpg_user = gpg_secret_key_map[args.gpg_id]

    with Index(gpg_user, index_suffix=args.mailbox) as index:
        # If in querying mode:
        if len(args.QUERY) > 0:
            results = [email for query in args.QUERY for email in index.query(query)]
            if len(results) == 0:
                sys.stderr.write("[!] No results.\n")
                sys.stderr.flush()
                exit(0)
            import curses
            import curses.ascii
            try:
                curses.wrapper(show_results)
            except KeyboardInterrupt:
                pass
            exit(0)

        # Else, if in indexing mode:
        imap = imaplib.IMAP4_SSL(args.server)
        imap.login(args.user, getpass.getpass("IMAP Password for " + args.user + ": "))
        try:
            processed = 0
            imap.select(args.mailbox, True)
            typ, data = imap.search(None, 'ALL')
            emails = data[0].split()
            if not args.full:
                emails = list(reversed(emails))
            total_emails = len(emails)
            d = str(len(str(total_emails)))
            f = "\r" + " "*200 + "\r[.] %" + d + "d/%" + d + "d %8s %s"
            current_email = 1
            with index.searcher() as s:
                for i, num in enumerate(emails):
                    typ, data = imap.fetch(num, '(BODY.PEEK[HEADER.FIELDS (Message-ID)])')
                    msg = email.message_from_string(data[0][1])
                    doc = index.get_by_id(msg['Message-ID'])
                    if doc == None:
                        sys.stderr.write(f % (current_email, total_emails, "Adding", msg['Message-ID']))
                        sys.stderr.flush()
                        # Fetch the whole E-Mail
                        typ, data = imap.fetch(num, '(RFC822)')
                        msg = email.message_from_string(data[0][1])
                        writer = index.index.writer()
                        if index.add(msg, writer):
                            processed += 1
                            writer.commit(merge = False)
                        else:
                            writer.cancel()
                            sys.stderr.write("\r" + " "*200 + "\r[!] Error decrypting E-Mail:\n\t" + str(msg['Message-ID']) + "\n\tFrom: " + str(msg['From']) + "\n\tDate: " + str(msg['date']) + "\n\tSubject: " + str(msg['Subject']))
                            sys.stderr.flush()
                    elif not args.full:
                        # We reached a message that we have seen before, and we aren't doing a full import, so we are done!
                        sys.stderr.write(f % (current_email, total_emails, "[+] Finished quick import!", msg['Message-ID']))
                        sys.stderr.flush()
                        break
                    else:
                        sys.stderr.write(f % (current_email, total_emails, "Skipping", msg['Message-ID']))
                        sys.stderr.flush()
                    current_email += 1

                    if processed % 0x100 == 0 and processed > 0:
                        sys.stderr.write("\r" + " "*200 + "\r[+] Optimizing the index...")
                        sys.stderr.flush()
                        index.index.optimize()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            sys.stdout.write("[!] Exception: "+str(e) + "\n")
            sys.stdout.flush()
        finally:
            index.save()
            imap.close()
            imap.logout()

