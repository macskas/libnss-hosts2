CXX=gcc
DLL_NAME=libnss_hosts2
FILE_HOSTS=/etc/hosts2

all:
	$(CXX) -D FILE_HOSTS=\"$(FILE_HOSTS)\" -shared -fPIC -o $(DLL_NAME).so.2 -Wl,-soname,$(DLL_NAME).so.2 $(DLL_NAME).c

clean:
	rm -f $(DLL_NAME).so.2

install:
	cp $(DLL_NAME).so.2 /lib/x86_64-linux-gnu/$(DLL_NAME).so.2
	@echo '#' after the install add it in the /etc/nsswitch.conf
	@echo '#' look for the line, starting with 'hosts:' just add it after the files or at the end of the line

uninstall:
ifeq ($(shell grep -c hosts2 /etc/nsswitch.conf), 0)
	rm -f /lib/x86_64-linux-gnu/$(DLL_NAME).so.2
else
	@echo '#' remove hosts2 from /etc/nsswitch.conf manually, then run make uninstall again
endif
