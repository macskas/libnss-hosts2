# libnss-hosts2
Just a basic secondary hosts lookup. Can be helpful in docker where /etc/hosts cannot be renamed(safely modified).

### install
- optional: configure secondary hosts file path in Makefile (FILE_HOSTS=/etc/hosts2), default: /etc/hosts2
- `# make && make install`
- locate the line starting with _hosts:_ in `/etc/nsswitch.conf`, add "hosts2" after files

### uninstall
- remove hosts2 from `/etc/nsswitch.conf`
- `# make uninstall`

### test
```console
user@host:~/libnss-hosts2$ make
gcc -D FILE_HOSTS=\"/etc/hosts2\" -shared -fPIC -o libnss_hosts2.so.2 -Wl,-soname,libnss_hosts2.so.2 libnss_hosts2.c

user@host:~/libnss-hosts2$ sudo su
root@host:~/libnss-hosts2# make install
cp libnss_hosts2.so.2 /lib/x86_64-linux-gnu/libnss_hosts2.so.2
# after the install add it in the /etc/nsswitch.conf
# look for the line, starting with hosts: just add it after the files or at the end of the line

root@host:~/libnss-hosts2# editor /etc/nsswitch.conf

root@host:~/libnss-hosts2# #just an example:
root@host:~/libnss-hosts2# cat /etc/nsswitch.conf|grep hosts2
hosts:          files hosts2 mdns4_minimal [NOTFOUND=return] dns myhostname

root@host:~/libnss-hosts2# echo 1.2.3.4 test.asdf >> /etc/hosts2
user@host:~/libnss-hosts2$ perl -MSocket -e 'my $x = gethostbyname("test.asdf"); printf("test: %s\n", defined($x) ? inet_ntoa($x) : "-");'
test: 1.2.3.4
user@host:~/libnss-hosts2$ perl -MSocket -e 'my $x = gethostbyaddr(inet_aton("1.2.3.4"), AF_INET); printf("test: %s\n", defined($x) ? $x : "-");'
test: test.asdf
user@host:~/libnss-hosts2$ 
```