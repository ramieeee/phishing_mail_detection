```
yum -y install sendmail-cf dovecot
```

```
vim /etc/mail/sendmail.cf

# project.com server
85 Cwproject.com
264 O DaemonPortOptions=Port=smtp, Name=MTA

# test.com server
85 Cwtest.com
264 O DaemonPortOptions=Port=smtp, Name=MTA
```

```
# RELAY add mail sending func
vim /etc/mail/access

# project.com, test.com server
project.com     RELAY
test.com        RELAY
192.168.100     RELAY

# apply the conf on both servers
makemap hash /etc/mail/access < /etc/mail/access
```

```
# on both servers
vim /etc/dovecot/conf.d/10-ssl.conf
8: ssl = yes
```

```
vim /etc/dovecot/conf.d/10-mail.conf

# remove comment
25 mail_location = mbox:~/mail:INBOX=/var/mail/%u
121 mail_access_groups = mail
166 lock_method = fcntl
```

```
systemctl restart sendmail
systemctl enable sendmail
```

