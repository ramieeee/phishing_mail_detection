Pymilter is an opensource, milter controlled by Python.

Pymilter should run as a demon.

```
# download pymilter

wget https://files.pythonhosted.org/packages/ca/b0/0e314563fc802cd7f8f98c858acf5def0ba85acc5fb2cef6db83d1b70431/pymilter-1.0.4.tar.gz
tar xvf pymilter-1.0.4.tar.gz
cd pymilter-1.0.4/

# install to compile setup.py
yum install gcc
yum install python-devel
yum install sendmail-devel

python setup.py install
```

```
# add two lines in sendmail.cf

vim /etc/mail/sendmail.cf

O InputMailFilters=pythonfilter
Xpythonfilter,        S=local:/home/[USER NAME]/pythonsock
```

```
systemctl restart sendmail
```

```
# disable selinux

vim /etc/selinux/config

SELINUX=disabled

# and reboot OS
```

