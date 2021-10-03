import socket
from struct import *

""""This File contains the packet sniffing Methods using the socket module"""

class Pysniff:
    """Class where i kept all the methods"""

    def __init__(self):
        self.msg = ""


    def eth_addr(self, raw_mac):
        """This method formats the MAC ADDRESS and i can call it in both of the other methods"""
        strMAC = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(raw_mac[0]), ord(raw_mac[1]), ord(raw_mac[2]), ord(raw_mac[3]),
                                                    ord(raw_mac[4]), ord(raw_mac[5]))
        return strMAC

    @property
    def deviceFinder(self):
        """This is the method i use in the first GUI in order to display the diffrent connections
        avalible to the device you are currently using"""
        Line = ""
        cap = True
        while True: # To grab the packets as we can never be sure of the timing of packets on the networks
            try:
                s            = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                packet       = s.recvfrom(65565)
                # packet string from tuple
                packet       = packet[0]
                # parse ethernet header
                eth_length   = 14
                eth_header   = packet[:eth_length]
                eth          = unpack('!6s6sH', eth_header)
                eth_protocol = socket.ntohs(eth[2])
                Mac          = self.eth_addr(str(packet[0:6]))

                #IP Protocol number = 8
                if eth_protocol == 8:
                    # take the first 20 characters for the ip header
                    ip_header = packet[eth_length:20 + eth_length]
                    # Unpacking
                    iph       = unpack('!BBHHHBBH4s4s', ip_header)
                    d_addr    = socket.inet_ntoa(iph[9])
                    Line      = "Mac: " + str(Mac) + "          IP: " + str(d_addr)
                    if ""    != Line: #To ensure empty strings arent being passed through
                        break
                    else:
                        pass
            except: #Try & except in order to keep going through the while loop
                pass
        return Line



    def Get_Packets(self, mac):
        """ Method used in the GUI screen for displaying all the packets information """
        # try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

         # To grab the packets as we can never be sure of the timing of packets on the networks
        while True:
            packet       = s.recvfrom(65565)
            # packet string from tuple
            packet       = packet[0]
            # parse ethernet header
            eth_length   = 14
            eth_header   = packet[:eth_length]
            eth          = unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])
            check        = self.isitRight_Packet(str(self.eth_addr(str(packet[0:6]))), mac)
            if check:
                PACKET   = ('Destination MAC : ' + self.eth_addr(str(packet[0:6])) + ' Source MAC : '
                          + self.eth_addr(str(packet[6:12])) + ' Protocol : ' + str(
                            eth_protocol) + '\n')
                self.Androgen_Protocol(eth_protocol, packet, eth_length)
                PACKET   = str(PACKET + self.msg)
                self.msg = "" #Clear out the instance variable
                return PACKET
                break
            else:
                pass


    def isitRight_Packet(self, recv_mac, mac):
        """This is just used inorder to filter out the packets so we only get the ones we wanted"""
        a = False
        if recv_mac == mac:
            a = True
        return a

    def Androgen_Protocol(self, eth_protocol, packet, eth_length):
        """Just goes through the diffrent protocols in order to properly display them """
        if eth_protocol == 8:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header   = packet[eth_length:20 + eth_length]
            # now unpack them 🙂
            iph         = unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            version     = version_ihl >> 4
            ihl         = version_ihl & 0xF
            iph_length  = ihl * 4
            ttl         = iph[5]
            protocol    = iph[6]
            s_addr      = socket.inet_ntoa(iph[8])
            d_addr      = socket.inet_ntoa(iph[9])
            self.msg    = ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(
                ttl) + ' Protocol : ' + str(
                protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr) + "\n")


            # TCP protocol
            if protocol == 6:
                t               = iph_length + eth_length
                tcp_header      = packet[t:t + 20]
                tcph            = unpack('!HHLLBBHHH', tcp_header)
                source_port     = tcph[0]
                dest_port       = tcph[1]
                sequence        = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved   = tcph[4]
                tcph_length     = doff_reserved >> 4
                self.msg        = (self.msg + 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(
                    dest_port) + ' Sequence Number : ' + str(
                    sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(
                    tcph_length) + '\n')
                h_size          = eth_length + iph_length + tcph_length * 4
                # get data from the packet
                data            = str(packet[h_size:])
                self.msg        = self.msg + ('TCP Data : ' + data) + "\n"


                # ICMP Packets
            elif protocol == 1:
                u            = iph_length + eth_length
                icmph_length = 4
                icmp_header  = packet[u:u + 4]
                icmph        = unpack('!BBH', icmp_header)

                icmp_type    = icmph[0]
                code         = icmph[1]
                checksum     = icmph[2]

                self.msg     = (self.msg + 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(
                    checksum) + '\n')
                h_size       = eth_length + iph_length + icmph_length
                data         = str(packet[h_size:])
                self.msg     = (self.msg + ('ICMP Data : ' + data) + "\n")


                # UDP packets
            elif protocol == 17:
                u           = iph_length + eth_length
                udph_length = 8
                udp_header  = packet[u:u + 8]
                udph        = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port   = udph[1]
                length      = udph[2]
                checksum    = udph[3]

                self.msg    = (self.msg + 'Source Port : ' + str(source_port) +
                       ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
                            length) + ' Checksum : ' + str(checksum) + '\n')

                h_size      = eth_length + iph_length + udph_length
                data        = str(packet[h_size:])
                self.msg    = (self.msg + ('UDP Data : ' + data) + '\n')


                # some other IP packet like IGMP
            else:
                self.msg   = (self.msg + 'Protocol other than TCP/UDP/ICMP' + '\n')

