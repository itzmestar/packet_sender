import packet_sender


def main():
    ps = packet_sender.PacketSender('192.168.1.101')
    ps.send_tcp_packets('hey')


if __name__ == '__main__':
    main()
