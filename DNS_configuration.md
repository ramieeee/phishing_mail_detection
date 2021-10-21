Name server is built to enable project & test server to communicate through

- [mail.project.com](http://mail.project.com/)( victim) = 192.168.100.146
- [mail.test.com](http://mail.test.com/)(phishing mail sender) = 192.168.100.140
- DNS = 192.168.100.143



## words in short

- **MTA(Mail Transport Agent)**

a space where E-mail is processed after receiving it from MUA

- **MDA(Mail Delivery Agent)**

MUA -> MTA -> MDA -> MUA

saves Email before sending it to MUA.

- **MUA(Mail User Agent)**

Clients can read and send emails with this program

Client Program like Outlook Express and Thunder Bird

- **SMTP(Simple Mail Transfer Protocol)**

SMTP is TCP/IP protocol used to send/receive emails.

Port: 25, 465(SSL), 587(TLS)

- **POP3/IMAP**

Email receiving protocol



# DNS configuration

```
yum -y install bind bind-chroot
```

```
vim /etc/hosts

# project.com server
192.168.100.146 mail.project.com

# test.com server
192.168.100.140 mail.test.com
```

```
vim /etc/sysconfig/network

# project.com server
HOSTNAME=192.168.100.146

# test.com server
HOSTNAME=192.168.100.140
```

```
# name server (192.168.100.143)
vim /etc/named.conf

options {

# with which IP and port of mine will I listen to
listen-on port 53 { any; };

# with which IP and port of mine will I listen to(IPv6)
listen-on-v6 port 53 { none; };

# from which IP will I allow query
allow-query { any; };
};

dnssec-validation no;

# zone configure
zone "project.com" IN {
        type master;
        file "project.com.db";
        allow-update { none; };
};

zone "test.com" IN {
        type master;
        file "test.com.db";
        allow-update { none; };
};
```

```
# project.com server
vi /var/named/project.com.db

$TTL    3H
@       SOA     @       root.   ( 2  1D  1H  1W  1H )
        IN      NS      @
        IN      A       192.168.100.142
        IN      MX      10      mail.project.com.

mail    IN      A       192.168.100.142

# test.com server
vi /var/named/test.com.db

$TTL    3H
@       SOA     @       root.   ( 2  1D  1H  1W  1H )
        IN      NS      @
        IN      A       192.168.100.140
        IN      MX      10      mail.test.com.

mail    IN      A       192.168.100.140

# check if conf is ok
named-checkconf
named-checkzone project.com project.com.db
named-checkzone test.com test.com.db
```

```
# name server service start
systemctl restart named
systemctl enable named

# take out the firewall
systemctl stop firewalld
systemctl disable firewalld
```

```
# at project.com, test.com
nmcli con mod ens33 ipv4.dns 192.168.100.143
systemctl restart NetworkManager
reboot
```
