make: sniff.c
	gcc -o sniff sniff.c -lpcap -I/usr/include/pcap
