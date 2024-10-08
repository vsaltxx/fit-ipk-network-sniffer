from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp

# Создание NDP-пакета
ndp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IPv6(dst="ff02::1:ff00:2") / ICMPv6ND_NA(tgt="fe80::1") / ICMPv6NDOptDstLLAddr(lladdr="00:11:22:33:44:55")

# Отправка NDP-пакета
sendp(ndp_packet, iface="eth0")
