import random
import scapy.all as scapy

# ----- Helper functions ----- #


def generate_pkt_id():
    """
    gererate a random number between 1 & 0xfe
    :return: random number generated
    """
    n = random.randint(1, 0xfe)
    return n


def print_send_info(proto):
    """
    # prints sending info
    :param proto:
    """
    print('Sending {} packet:'.format(proto))

# ----- class definition ----- #


class PacketSender:
    """
    class representing the Secret Packet Sender
    """

    def __init__(self, dest_ip):

        self.pkt_id = generate_pkt_id()
        self.dest_ip = dest_ip

    def _create_ip_packet_(self, char, offset):
        """
        creates raw IP packet with default values
        sets the identification field in packet
        sets DO NOT FRAGMENT flag
        sets FRAGMENTATION OFFSET value

        :param char: character to be sent in identification field
        :param offset: fragmentation offset value
        :return:
        """
        try:
            pkt = scapy.IP(dst=self.dest_ip)
            msg = ord(char)
            iden = self.pkt_id | (msg << 8)
            # print hex(id) , hex((msg << 8))
            pkt.id = iden
            # print hex(pkt.id)
            # set DO NOT FRAGMENT flag
            pkt.flags = 0b010
            # print pkt.flags
            pkt.frag = offset
        except Exception as e:
            print(e)
        return pkt

    def _send_packet_(self, packet):
        """
        Send the packet on interface
        :param packet: packet to be sent
        :return:
        """
        try:
            # show packet details
            packet.show()
            # try to send the packet
            scapy.send(packet)
        except Exception as e:
            print(e)

    def send_tcp_packets(self, message):
        """
        Sends n number of TCP SYN packets to port 80
        where n is the length of message
        :param message: text message to be sent
        :return:
        """
        # generate new packet id
        self.pkt_id = generate_pkt_id()
        # send 1 packet for each char in message
        for i in range(0, len(message)):
            pkt = self._create_ip_packet_(message[i], i) / scapy.TCP()
            print_send_info('IPv4/TCP')
            self._send_packet_(pkt)

        # send last packet with message length
        pkt = self._create_ip_packet_('\0', len(message)) / scapy.TCP()
        # put the last bit high of frag offset
        pkt.frag = pkt.frag | (1 << 12)
        # print hex(pkt.frag)
        print_send_info('IPv4/TCP')
        self._send_packet_(pkt)

    def send_icmp_packets(self, message):
        """
        Send the message text encoded in tcp packet
        :param message: text message to be sent
        :return:
        """
        self.pkt_id = generate_pkt_id()
        # send n number of packets
        for i in range(0, len(message)):
            pkt = self._create_ip_packet_(message[i], i) / scapy.ICMP(id=id, seq=i + 1)
            print_send_info('IPv4/ICMP')
            self._send_packet_(pkt)

        # send last packet with message length
        pkt = self._create_ip_packet_('\0', len(message)) / scapy.ICMP(id=id, seq=len(message) + 1)
        # put the last bit high of frag offset
        pkt.frag = pkt.frag | (1 << 12)
        # print hex(pkt.frag)
        print_send_info('IPv4/ICMP')
        self._send_packet_(pkt)
