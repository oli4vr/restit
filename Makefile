all:
	gcc -c inifind.c -o inifind.o -O3
	gcc -c sha512.c -o sha512.o -O3
	gcc -c encrypt.c -o encrypt.o -O3
	gcc -c entropy.c -o entropy.o -O3
	gcc -c tcpd.c -o tcpd.o -O3 -lpthread
	gcc main.c -o restit -lpthread -O3 sha512.o encrypt.o entropy.o inifind.o tcpd.o
bundle:
	mkdir -p ~/bin 2>/dev/null
	./restit -b main.csv
	chmod +x ./genpkg.sh
	./genpkg.sh
	./genrpm.sh
clean:
	rm -rf *.o restit restit.*.sh 2>/dev/null
	rm -rf bin .restit 2>/dev/null
	rm -rf *.deb *.rpm
