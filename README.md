# arpspoof.py - An ARP poisoning tool
arpspoof.py is a small tool I wrote because I was annoyed with  my ARP spoofing workflow. Also, I wanted to brush up my scapy knowledge.

## Dependencies
You will need scapy and Python 2, nothing else.

## Usage

```
$ python2 arpspoof.py -h
usage: arpspoof.py [-h] [-i INTERFACE] -t TARGETS -g GATEWAY

Do ARP poisoning between a gatway and several targets

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        interface to send from
  -t TARGETS, --targets TARGETS
                        comma-separated list of IP addresses
  -g GATEWAY, --gateway GATEWAY
                        IP address of the gateway
```

As you can see from the output above, the typical usage scenario is that you want to intercept data between one gateway and one or more targets. The -t and -g parameters are required, the -i parameter might be useful if you have multiple connected interfaces.

```
$ sudo python2 arpspoof.py -t 192.168.1.234 -g 192.168.1.1
Using interface wifi0 (60:67:20:42:fb:de)
arpspoof#
```

After starting, you will find yourself at a command prompt. At this time, the ARP poisoning is already going on in the background.

```
arpspoof# help
add <IP>: add IP address to target list
del <IP>: remove IP address from target list
list: print all current targets
exit: stop poisoning and exit
arpsoof#
```

Typing help will bring up a list of commands.

- add/del will modify the list of targets. At the moment, I haven't found the need to change the gateway, so this is not possible right now
- list will list all current targets and the gateway
- exit will exit, who would have thought...

```
arpspoof# list
Current targets:
Gateway: 192.168.1.1 (00:00:00:00:00:01)
192.168.1.234 (00:00:00:00:00:02)
arpspoof# exit
Stopping the attack, restoring ARP cache
ARP 192.168.1.1 is at 00:00:00:00:00:01
ARP 192.168.1.234 is at 00:00:00:00:00:02
ARP 192.168.1.1 is at 00:00:00:00:00:01
ARP 192.168.1.234 is at 00:00:00:00:00:02
ARP 192.168.1.1 is at 00:00:00:00:00:01
ARP 192.168.1.234 is at 00:00:00:00:00:02
Restored ARP caches
$
```

After receiving the exit command, arpspoof.py will restore the ARP caches of the gateway and the targets by sending three correct ARP responses.

## TODO
- implement a command to change the gateway
- find a less ugly way of implementing the command prompt logic