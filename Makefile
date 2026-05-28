SVCNAME := $(shell . ./env_vars.sh && echo $$RESTIT_SVCNAME)

all: main bundle

main:
	gcc -c inifind.c -o inifind.o -O3
	gcc -c sha512.c -o sha512.o -O3
	gcc -c encrypt.c -o encrypt.o -O3
	gcc -c entropy.c -o entropy.o -O3
	gcc -c tcpd.c -o tcpd.o -O3 -lpthread
	gcc -c ymlparse.c -o ymlparse.o -O3
	gcc main.c -o restit -lpthread -O3 sha512.o encrypt.o entropy.o inifind.o tcpd.o ymlparse.o
bundle:
	mkdir -p ~/bin 2>/dev/null
	RESTIT_SVCNAME=$(SVCNAME) ./restit -b main.yml
	chmod +x ./build_scripts/genpkg.sh
	./build_scripts/genpkg.sh
	./build_scripts/genrpm.sh
clean:
	./build_scripts/cleanup.sh
