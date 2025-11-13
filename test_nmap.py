#!/usr/bin/env python3
import nmap

# Test 1: Escaneo simple
print("="*60)
print("TEST 1: Escaneo de puertos en localhost")
print("="*60)

nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-443', arguments='-sT')

print(f"Comando ejecutado: {nm.command_line()}")
print(f"Hosts encontrados: {nm.all_hosts()}")

if '127.0.0.1' in nm.all_hosts():
    print(f"Protocolos: {nm['127.0.0.1'].all_protocols()}")
    if 'tcp' in nm['127.0.0.1']:
        print(f"Puertos TCP: {list(nm['127.0.0.1']['tcp'].keys())}")

# Test 2: Escaneo de tu red
print("\n" + "="*60)
print("TEST 2: Escaneo de 192.168.1.125")
print("="*60)

nm2 = nmap.PortScanner()
nm2.scan('192.168.1.125', arguments='-sT -p 22,80,443', sudo=True)

print(f"Comando ejecutado: {nm2.command_line()}")
print(f"Estado: {nm2['192.168.1.125'].state() if '192.168.1.125' in nm2.all_hosts() else 'No encontrado'}")

if '192.168.1.125' in nm2.all_hosts():
    print(f"Protocolos: {nm2['192.168.1.125'].all_protocols()}")
    if 'tcp' in nm2['192.168.1.125']:
        for port, data in nm2['192.168.1.125']['tcp'].items():
            print(f"  Puerto {port}: {data['state']} - {data['name']}")