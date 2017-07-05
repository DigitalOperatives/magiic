Magiic
======

**Magiic Allows for GPG Indexing of IMAP on the Command-line**

Magiic is a Python script that uses [GnuPG](https://www.gnupg.org/) for
encryption/decryption and [Whoosh](https://pypi.python.org/pypi/Whoosh/) for
full-text indexing. It acts as a standalone mail application, either connecting
directly to an IMAP server and creating a local index off of the contents, or
recursively indexing a local directory for all mbox files. It has a simple
[ncurses](https://www.gnu.org/software/ncurses/) interface so all interaction
can take place on the command line.  We are releasing the code using a version
of the Creative Commons BY-NC-SA 3.0 license that has been modified slightly to
be more applicable for software licensing. It is free for non-commercial use.

For more information, including Magiic's motivations and use-cases, see
[our blog post](http://digitaloperatives.com/2013/08/23/defending-your-emails-from-surveillance-conveniently/).
