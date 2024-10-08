from scapy.all import Ether, IPv6, ICMPv6MLReport, sendp

# Создаем MLDv2 Report пакет
mld_packet = Ether() / IPv6(dst="ff02::16") / ICMPv6MLReport()

# Отправляем MLD пакет
sendp(mld_packet, iface="eth0")
