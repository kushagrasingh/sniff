sniff is a tool built in C based on libpcap library. libpcap is a C library providing APIs for capturing packets directly form datalink layer of Unix derived operating systems.
sniff is a packet capture tool that captures all real time inbound and outbound packets on a specified network interface and port.

To run sniff, run make command in terminal.
Then run,

sudo ./sniff -i wlan0 tcp port 80

to sniff on wireless and capture all TCP packets on port 80.
