LDLIBS=-lpcap

all: tcp-block

main.o: mac.h ip.h ethhdr.h iphdr.h tcphdr.h main.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

tcp-block: main.o ethhdr.o iphdr.o tcphdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
