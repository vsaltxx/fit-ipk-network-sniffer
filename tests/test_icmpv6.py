from scapy.all import IPv6, ICMPv6EchoRequest, send

# Создаем ICMPv6 Echo Request пакет
icmpv6_packet = IPv6(dst="fe80::215:5dff:fefb:e262") / ICMPv6EchoRequest()

# Отправляем ICMPv6 Echo Request пакет
send(icmpv6_packet, iface="eth0")
