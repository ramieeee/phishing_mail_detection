Procmail will be reading the subject in the header of the email and redirect into spam mailbox.

Procmail works after Pymilter processes the email.

`vim /home/project/.procmailrc`: make `.procmailrc`  file and put codes below

```
MAILDIR=$HOME/mail
LOGFILE=$MAILDIR/procmaillog
#VERBOSE=yes

:0 H
# reads subject in the header to check "[PHISHING]"
* ^Subject:\[PHISHING]
$MAILDIR/Spam
```

