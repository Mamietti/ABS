# ABS

Non-intrusive access monitoring scenario using attribute based signatures.

##Requirements

* **Python 3.6** (verified to work) or possibly newer (untested) with the included base libraries
* Libraries **charm-crypto**, **netfilterqueue** and **scapy** and their respective requirements

##Usage

1. Run `$ sudo iptables -A OUTPUT -p tcp -j NFQUEUE` to send packets to the NFQUEUE handler.
2. Start the server process via `$ sudo python3.6 ABSSentinel.py` which gives you the port number (host is the IP of the machine running it).
3. Start the client process as `$ sudo python3.6 ABSClient.py serverhost serverport networkalias` where:
* `serverhost` and `serverport` are self-explanatory.
* `networkalias` is the IP address representing the client in the packets sent to/from the client. This is for enabling NAT support.
4. When finished, stop the processes via Ctrl-C and run `$ sudo iptables -D OUTPUT -p tcp -j NFQUEUE` to stop the packet handler
