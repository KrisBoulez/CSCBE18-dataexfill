# CSCBE18-dataexfill
This repository contains all information related to a challenge in the [CSCBE 18](https://www.cybersecuritychallenge.be/) qualifiers. 
The challenge was based on data exfiltration using blockchain and consisted of three subchallenges
* Blockshark
* BlocksharkNado
* BlocksharkNado vs Blocksharcopus

For the challenge a network capture file was provided [data_exfil.pcap](https://github.com/KrisBoulez/CSCBE18-dataexfill/blob/master/data_exfil.pcap).

A writeup of the challenge was published on the NVISO blog (**XXX add URL XXX**)

The following files are provided:

**datai\_exfil.pcap**: network capture used for the challenges

**bt\_encrypt.go**: encrypts the message contained in secret.txt. Expects to have the 3123xy.json files in a data subfolder. Two files are provided, downloaded the other address blocks from blockchain.info.

**webserver.go**: the webserver that participants could use to check the working of the protocol. Also expects to have the 3123xy.json files in a data subfolder (see above). The address\_response\_footer file contains the footer for address responses.

**anal\_blockfile.pl** and **anal\_reqs.pl**: perl scripts used during the analysis that is described in the writeup.

## Important !!!
The webserver is **not** intended to be run directly accessible from a hostile environment (read The Internet). Although care was taken to only accept very specific URL's and perform basic santity checking, this was my first decent-sized Go program I've written. During the CSCBE18 challenge it was set up behind an NGINX reverse proxy, which implemented basic filtering and rate limiting.

Kris Boulez - kris [dot] boulez [at] gmail [dot] com



