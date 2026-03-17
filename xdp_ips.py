#!/usr/bin/python3
from bcc import BPF
import time
import socket
import struct

# ==========================================
# 1. LE MUSCLE : CODE EN C (INJECTION NOYAU)
# ==========================================
bpf_code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>

BPF_HASH(drop_cnt, u32, u32);

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Couche Ethernet
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Couche IP
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    // 3. Couche TCP & Détection de Scan
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)(ip + 1);
        if ((void*)(tcp + 1) > data_end)
            return XDP_PASS;

        // On traque le flag SYN (sans ACK) : La signature du scan Nmap furtif
        if (tcp->syn && !tcp->ack) {
            u32 src_ip = ip->saddr;
            u32 *val, zero = 0;
            
            val = drop_cnt.lookup_or_try_init(&src_ip, &zero);
            if (val) {
                lock_xadd(val, 1);
            }
            
            // On désintègre le scan !
            return XDP_DROP; 
        }
    }

    return XDP_PASS;
}
"""

# ==========================================
# 2. LE CERVEAU : CODE PYTHON
# ==========================================

INTERFACE = "eth0" # Vérifie bien que c'est toujours la bonne interface !

print(f"[*] Compilation de l'analyseur TCP en cours...")
b = BPF(text=bpf_code)

fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp(dev=INTERFACE, fn=fn, flags=0)

print(f"[+] Anti-Port-Scan activé sur l'interface {INTERFACE} !")
print(f"[*] En attente de scans furtifs... (Ctrl+C pour quitter)\n")

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("<L", ip_int))

try:
    drop_cnt = b.get_table("drop_cnt")
    while True:
        time.sleep(2)
        for k, v in drop_cnt.items():
            ip_attaquant = int_to_ip(k.value)
            print(f"🚨 [ALERTE XDP] Scan TCP SYN bloqué depuis {ip_attaquant} : {v.value} tentatives pulvérisées !")
        drop_cnt.clear()

except KeyboardInterrupt:
    print("\n[*] Désactivation du bouclier et nettoyage...")
    b.remove_xdp(INTERFACE, 0)
    print("[+] Déconnecté proprement.")
