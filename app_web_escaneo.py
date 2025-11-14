# app_web_escaneo.py
from flask import Flask, render_template_string, request, jsonify
import threading
import time
from datetime import datetime
import socket
import re
import os
import subprocess
import xml.etree.ElementTree as ET
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suprimir warnings de SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- 1. Definición de Clases ---

class Device:
    """Clase para representar un dispositivo en la red."""
    def __init__(self, ip, hostname="Desconocido"):
        self.ip = ip
        self.hostname = hostname
        self.mac = "N/A"
        self.vendor = "N/A"
        self.os = "N/A"
        self.os_class = "N/A"
        self.http_title = "N/A"
        self.ports = []
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.is_active = True
        self.inactive_count = 0

# --- 2. Funciones de Red ---

def get_hostname_from_ip(ip):
    """Intenta obtener el hostname real de una IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    
    try:
        hostname = socket.getfqdn(ip)
        if hostname and hostname != ip:
            return hostname
    except:
        pass
    
    return "Desconocido"

def get_local_network():
    """Obtiene la IP local y deriva una red base (ej., /24)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network_base = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        return network_base, local_ip
    except Exception:
        return "192.168.1.0/24", "127.0.0.1"

def get_local_mac():
    """Obtiene la MAC address de la interfaz de red principal."""
    try:
        # Intentar con netifaces (si está instalado)
        import netifaces
        gateways = netifaces.gateways()
        default_interface = gateways['default'][netifaces.AF_INET][1]
        
        addrs = netifaces.ifaddresses(default_interface)
        if netifaces.AF_LINK in addrs:
            mac = addrs[netifaces.AF_LINK][0]['addr']
            return mac.upper().replace('-', ':')
    except (ImportError, KeyError, IndexError):
        pass
    
    # Método alternativo con ip link (Linux)
    try:
        result = subprocess.run(
            ['ip', 'link', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Buscar la interfaz activa (excluyendo lo y docker)
        lines = result.stdout.split('\n')
        
        for i, line in enumerate(lines):
            # Detectar línea de interfaz
            if re.match(r'^\d+:', line):
                # Verificar si está UP y no es loopback ni docker
                if 'state UP' in line and 'lo:' not in line and 'docker' not in line:
                    # La siguiente línea debería tener la MAC
                    if i + 1 < len(lines):
                        next_line = lines[i + 1]
                        if 'link/ether' in next_line:
                            parts = next_line.split()
                            try:
                                mac_index = parts.index('link/ether') + 1
                                mac = parts[mac_index]
                                return mac.upper()
                            except (ValueError, IndexError):
                                pass
    except Exception:
        pass
    
    # Método alternativo con ifconfig (sistemas más antiguos)
    try:
        result = subprocess.run(
            ['ifconfig'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Buscar patrón de MAC
        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        matches = re.findall(mac_pattern, result.stdout)
        
        if matches:
            # Filtrar MACs válidas (no 00:00:00:00:00:00)
            for match in matches:
                mac = ''.join(match).replace('-', ':')
                if mac != '00:00:00:00:00:00':
                    return mac.upper()
    except:
        pass
    
    return None

def get_vendor_from_mac(mac):
    """Intenta obtener el fabricante desde la MAC usando una búsqueda simple."""
    if not mac or mac == 'N/A':
        return 'N/A'
    
    # Obtener los primeros 3 octetos (OUI) - primeros 6 caracteres hex
    oui = mac.replace(':', '').replace('-', '').upper()[:6]
    
    # Base de datos expandida de fabricantes comunes (OUI)
    vendors = {
        # Intel
        'D4D853': 'Intel Corporate',
        'F01898': 'Intel Corporate',
        '0050F2': 'Microsoft (Intel)',
        '6C2B59': 'Intel Corporate',
        '3497F6': 'Intel Corporate',
        '48F17F': 'Intel Corporate',
        '7085C2': 'Intel Corporate',
        
        # Apple
        '001EC2': 'Apple, Inc.',
        '3C0754': 'Apple, Inc.',
        '68A86D': 'Apple, Inc.',
        '001B63': 'Apple, Inc.',
        '0050E4': 'Apple, Inc.',
        '8C8590': 'Apple, Inc.',
        'F0DCE2': 'Apple, Inc.',
        'A43135': 'Apple, Inc.',
        '9027E4': 'Apple, Inc.',
        'B8E856': 'Apple, Inc.',
        
        # TP-Link
        '0024E8': 'TP-Link Technologies',
        '84C5A6': 'TP-Link Technologies',
        'C46E1F': 'TP-Link Technologies',
        'B0BE76': 'TP-Link Technologies',
        'C83A35': 'TP-Link Technologies',
        '1C3BF3': 'TP-Link Technologies',
        'D8EB97': 'TP-Link Technologies',
        
        # Realtek
        '00E04C': 'Realtek Semiconductor',
        '525400': 'Realtek Semiconductor',
        '0C5415': 'Realtek Semiconductor',
        '18FE34': 'Realtek Semiconductor',
        
        # Microsoft
        '00155D': 'Microsoft Corporation',
        '00125A': 'Microsoft Corporation',
        
        # Hon Hai / Foxconn
        '30AEA4': 'Hon Hai Precision',
        '00262D': 'Hon Hai Precision',
        
        # Samsung
        '0C9D92': 'Samsung Electronics',
        '84B541': 'Samsung Electronics',
        'C4576E': 'Samsung Electronics',
        
        # Xiaomi
        '34CE00': 'Xiaomi Communications',
        '786A89': 'Xiaomi Communications',
        
        # Huawei
        '7CE9D3': 'Huawei Technologies',
        '0025BC': 'Huawei Technologies',
        
        # Cisco
        '0011BB': 'Cisco Systems',
        '001CB0': 'Cisco Systems',
        
        # D-Link
        '001B11': 'D-Link Corporation',
        '0018E7': 'D-Link Corporation',
        
        # Netgear
        '002275': 'NETGEAR',
        '001E2A': 'NETGEAR',
        
        # Asus
        '1CB72C': 'ASUSTek Computer',
        '2C56DC': 'ASUSTek Computer',
        
        # Belkin
        '001150': 'Belkin International',
        '0030BD': 'Belkin International',
    }
    
    return vendors.get(oui, 'Unknown Vendor')

def get_http_title(ip, ports_list, timeout=3):
    """
    Intenta obtener el título de una página web HTTP/HTTPS.
    
    Args:
        ip: Dirección IP del dispositivo
        ports_list: Lista de puertos abiertos en formato ['80/http', '443/https']
        timeout: Tiempo máximo de espera en segundos
    
    Returns:
        str: Título de la página o 'N/A'
    """
    # Verificar si tiene puertos web abiertos
    has_http = False
    has_https = False
    http_port = 80
    https_port = 443
    
    for port_str in ports_list:
        try:
            port_num = int(port_str.split('/')[0])
            service = port_str.split('/')[1].lower() if '/' in port_str else ''
            
            if port_num == 80 or 'http' in service:
                has_http = True
                http_port = port_num
            elif port_num == 443 or 'https' in service or 'ssl' in service:
                has_https = True
                https_port = port_num
        except (ValueError, IndexError):
            continue
    
    if not has_http and not has_https:
        return 'N/A'
    
    # Intentar primero HTTPS, luego HTTP
    urls_to_try = []
    if has_https:
        urls_to_try.append(f"https://{ip}:{https_port}" if https_port != 443 else f"https://{ip}")
    if has_http:
        urls_to_try.append(f"http://{ip}:{http_port}" if http_port != 80 else f"http://{ip}")
    
    for url in urls_to_try:
        try:
            # Hacer petición HTTP con timeout corto
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,  # Ignorar certificados SSL inválidos
                allow_redirects=True,
                headers={'User-Agent': 'NetworkScanner/1.0'}
            )
            
            # Buscar el título en el HTML
            html = response.text
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            
            if title_match:
                title = title_match.group(1).strip()
                # Limpiar el título (eliminar saltos de línea, espacios extras)
                title = re.sub(r'\s+', ' ', title)
                # Truncar si es muy largo
                if len(title) > 60:
                    title = title[:57] + "..."
                return title if title else 'N/A'
            else:
                # Si no hay título pero la petición fue exitosa
                return f"HTTP {response.status_code}"
                
        except requests.exceptions.Timeout:
            continue  # Intentar siguiente URL
        except requests.exceptions.ConnectionError:
            continue  # Intentar siguiente URL
        except requests.exceptions.RequestException:
            continue  # Intentar siguiente URL
        except Exception:
            continue  # Intentar siguiente URL
    
    return 'N/A'

def scan_network(network_range, scan_type='quick'):
    """Escanea la red usando nmap directamente via subprocess."""
    devices_dict = {}
    
    # Obtener IP local para detección de MAC
    _, local_ip = get_local_network()
    local_mac_address = get_local_mac()
    
    # Construir comando nmap
    if scan_type == 'detailed':
        nmap_cmd = [
            'nmap', '-sS', '-O', '--osscan-guess', '--host-timeout', '300s',
            '-p', '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443',
            '-oX', '-',
            network_range
        ]
        add_log("🔍 Modo DETALLADO: Escaneo SYN + puertos + SO + Títulos HTTP...")
    elif scan_type == 'deep':
        nmap_cmd = [
            'nmap', '-sS', '-sV', '-O', '--osscan-guess', '--host-timeout', '600s',
            '--top-ports', '100',
            '-oX', '-',
            network_range
        ]
        add_log("🔬 Modo PROFUNDO: Escaneo completo + versiones + SO + Títulos HTTP...")
    else:
        nmap_cmd = ['nmap', '-sn', '-oX', '-', network_range]
        add_log("⚡ Modo RÁPIDO: Solo detección de hosts activos (sin títulos HTTP)...")
    
    add_log(f"🔧 Comando: {' '.join(nmap_cmd)}")
    
    try:
        # Ejecutar nmap
        result = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False
        )
        
        if result.returncode != 0 and result.returncode != 1:
            add_log(f"⚠️ nmap retornó código {result.returncode}")
            if result.stderr:
                stderr_lines = result.stderr.split('\n')[:3]
                for line in stderr_lines:
                    if line.strip():
                        add_log(f"⚠️ stderr: {line.strip()[:150]}")
        
        add_log(f"✅ Escaneo nmap completado")
        
        # Parsear XML de salida
        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError as e:
            add_log(f"❌ Error parseando XML: {str(e)[:100]}")
            return {}
        
        # Procesar hosts
        total_hosts = 0
        for host in root.findall('host'):
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue
            
            total_hosts += 1
            
            # IP
            addr_elem = host.find('address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
            ip = addr_elem.get('addr')
            
            add_log(f"🔍 Procesando {ip}...")
            
            # MAC y Vendor
            mac = 'N/A'
            vendor = 'N/A'
            mac_elem = host.find('address[@addrtype="mac"]')
            
            if mac_elem is not None:
                mac = mac_elem.get('addr', 'N/A')
                vendor = mac_elem.get('vendor', 'N/A')
                # Convertir MAC a mayúsculas para consistencia
                if mac != 'N/A':
                    mac = mac.upper()
                add_log(f"  🏷️  MAC: {mac} ({vendor})")
            else:
                # Si es nuestra IP local y no hay MAC, obtenerla manualmente
                if ip == local_ip and local_mac_address:
                    mac = local_mac_address
                    vendor = get_vendor_from_mac(mac)
                    add_log(f"  🏷️  MAC (local): {mac} ({vendor})")
                else:
                    add_log(f"  ⚠️  MAC no detectada para {ip}")
            
            # Hostname
            hostname = 'Desconocido'
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name', 'Desconocido')
            
            if hostname == 'Desconocido':
                hostname = get_hostname_from_ip(ip)
            add_log(f"  📛 Hostname: {hostname}")
            
            # OS Detection - MEJORADO CON SELECCIÓN INTELIGENTE
            os_name = 'N/A'
            os_class = 'N/A'
            os_elem = host.find('os')
            
            if os_elem is not None:
                # Intentar obtener TODOS los matches
                osmatch_list = os_elem.findall('osmatch')
                
                if osmatch_list:
                    # Filtrar y priorizar OS modernos
                    modern_matches = []
                    old_matches = []
                    
                    for match in osmatch_list:
                        name = match.get('name', '')
                        accuracy = int(match.get('accuracy', '0'))
                        
                        # Detectar si es un kernel antiguo
                        if '2.6' in name or '3.X' in name or '4.X' in name.lower():
                            old_matches.append((name, accuracy))
                        else:
                            modern_matches.append((name, accuracy))
                    
                    # Priorizar matches modernos con buena accuracy
                    if modern_matches:
                        # Ordenar por accuracy y tomar el mejor moderno
                        modern_matches.sort(key=lambda x: x[1], reverse=True)
                        os_name, accuracy = modern_matches[0]
                    elif old_matches:
                        # Si solo hay antiguos, tomar el mejor
                        old_matches.sort(key=lambda x: x[1], reverse=True)
                        os_name, accuracy = old_matches[0]
                    else:
                        # Fallback al mejor match original
                        best_match = max(osmatch_list, key=lambda x: int(x.get('accuracy', '0')))
                        os_name = best_match.get('name', 'N/A')
                        accuracy = int(best_match.get('accuracy', '0'))
                    
                    # Formatear salida según accuracy
                    if accuracy >= 85:
                        if len(os_name) > 60:
                            os_name = os_name[:57] + "..."
                        add_log(f"  💻 OS: {os_name} ({accuracy}% confianza)")
                    elif accuracy >= 70:
                        if len(os_name) > 50:
                            os_name = os_name[:47] + "..."
                        add_log(f"  💻 OS: {os_name} ({accuracy}% confianza)")
                    elif accuracy >= 50:
                        os_name = f"{os_name[:40]}..."
                        add_log(f"  💻 OS (moderada confianza): {os_name} ~{accuracy}%")
                    else:
                        add_log(f"  ⚠️  OS detectado pero baja confianza ({accuracy}%)")
                        # Si la confianza es muy baja, mejor mostrar el rango
                        if len(osmatch_list) > 1:
                            os_name = f"Linux 5.X-6.X (estimado)"
                        else:
                            os_name = 'N/A'
                
                # Obtener tipo de dispositivo
                osclass_list = os_elem.findall('osclass')
                if osclass_list:
                    # Tomar el osclass con mayor accuracy
                    best_class = max(osclass_list, key=lambda x: int(x.get('accuracy', '0')))
                    os_class = best_class.get('type', 'N/A')
                    
                    # Fallback a osfamily si type no está disponible
                    if os_class == 'N/A':
                        os_class = best_class.get('osfamily', 'N/A')
                    
                    if os_class != 'N/A':
                        add_log(f"  🔖 Tipo: {os_class}")
                
                # Si no hay tipo, intentar inferir desde el OS name
                if os_class == 'N/A' and os_name != 'N/A':
                    if 'linux' in os_name.lower():
                        os_class = 'Linux'
                        add_log(f"  🔖 Tipo inferido: {os_class}")
            
            # Puertos
            ports_list = []
            ports_elem = host.find('ports')
            
            if ports_elem is not None:
                all_ports = ports_elem.findall('port')
                add_log(f"  🔌 Analizando {len(all_ports)} puertos...")
                
                open_count = 0
                closed_count = 0
                filtered_count = 0
                
                for port_elem in all_ports:
                    state_elem = port_elem.find('state')
                    if state_elem is None:
                        continue
                    
                    state = state_elem.get('state', 'unknown')
                    port_num = port_elem.get('portid')
                    
                    if state == 'open':
                        open_count += 1
                        service_elem = port_elem.find('service')
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            
                            if scan_type == 'deep' and product:
                                port_str = f"{port_num}/{service_name}"
                                if product:
                                    port_str += f" ({product}"
                                    if version:
                                        port_str += f" {version}"
                                    port_str += ")"
                                ports_list.append(port_str)
                            else:
                                ports_list.append(f"{port_num}/{service_name}")
                        else:
                            ports_list.append(f"{port_num}/unknown")
                    elif state == 'closed':
                        closed_count += 1
                    elif state == 'filtered':
                        filtered_count += 1
                
                add_log(f"  ├─ Abiertos: {open_count}")
                add_log(f"  ├─ Cerrados: {closed_count}")
                add_log(f"  └─ Filtrados: {filtered_count}")
                
                if open_count > 0:
                    add_log(f"  ✅ {ip}: {len(ports_list)} puertos abiertos listados")
                    
                    if len(ports_list) > 0:
                        for port in ports_list[:5]:
                            add_log(f"    🟢 {port}")
                        if len(ports_list) > 5:
                            add_log(f"    ... y {len(ports_list)-5} más")
                else:
                    add_log(f"  ⚠️  {ip}: Sin puertos abiertos detectados")
            else:
                add_log(f"  ⚠️  No se escanearon puertos para {ip}")
            
            # Inferir tipo por puertos si no hay OS
            if os_class == 'N/A' and len(ports_list) > 0:
                port_numbers = []
                for p in ports_list:
                    try:
                        port_num = int(p.split('/')[0])
                        port_numbers.append(port_num)
                    except:
                        pass
                
                if 80 in port_numbers or 443 in port_numbers or 8080 in port_numbers or 8443 in port_numbers:
                    os_class = 'Web Server'
                    add_log(f"  🔍 Tipo inferido: {os_class}")
                elif 22 in port_numbers:
                    os_class = 'SSH Server'
                    add_log(f"  🔍 Tipo inferido: {os_class}")
                elif 3389 in port_numbers:
                    os_class = 'Windows (RDP)'
                    add_log(f"  🔍 Tipo inferido: {os_class}")
                elif 445 in port_numbers or 139 in port_numbers:
                    os_class = 'Windows/Samba'
                    add_log(f"  🔍 Tipo inferido: {os_class}")
                elif 3306 in port_numbers:
                    os_class = 'MySQL Server'
                    add_log(f"  🔍 Tipo inferido: {os_class}")
            
            # Obtener título HTTP (solo si hay puertos web y no es modo rápido)
            http_title = 'N/A'
            if scan_type != 'quick' and len(ports_list) > 0:
                add_log(f"  🌐 Intentando obtener título HTTP...")
                http_title = get_http_title(ip, ports_list, timeout=3)
                if http_title != 'N/A':
                    add_log(f"  ✅ Título HTTP: {http_title}")
                else:
                    add_log(f"  ⚠️  No se pudo obtener título HTTP")
            
            devices_dict[ip] = {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'os': os_name,
                'os_class': os_class,
                'http_title': http_title,
                'ports': ports_list
            }
            
            add_log(f"✅ {ip} procesado")
            add_log("─" * 50)
        
        if total_hosts == 0:
            add_log("⚠️ No se encontraron hosts activos")
        else:
            add_log(f"🎉 {total_hosts} dispositivos procesados exitosamente")
        
        return devices_dict
        
    except subprocess.TimeoutExpired:
        add_log("❌ Timeout: El escaneo tardó demasiado (>15min)")
        return {}
    except Exception as e:
        add_log(f"❌ Error inesperado: {str(e)[:200]}")
        import traceback
        add_log(f"💥 Traceback: {traceback.format_exc()[:300]}")
        return {}

# --- 3. Configuración de Flask ---

app = Flask(__name__)

known_devices = {}
scan_active = False
scan_in_progress = False 
scan_thread = None
network_range = get_local_network()[0] 
scan_interval = 30
scan_type = 'quick'
last_scan_time = None
logs = []

# --- 4. Rutas de la Aplicación Web ---

@app.route('/')
def index():
    global network_range, scan_interval, scan_active
    default_network, local_ip = get_local_network()
    return render_template_string(HTML_TEMPLATE, 
                                  network_range=network_range, 
                                  scan_interval=scan_interval,
                                  scan_active=scan_active,
                                  local_ip=local_ip)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    global scan_active, scan_thread, network_range, scan_interval, scan_type
    network_range = request.form.get('network_range', network_range)
    scan_type = request.form.get('scan_type', 'quick')
    
    try:
        scan_interval = int(request.form.get('scan_interval', scan_interval))
        if scan_type == 'quick' and not (5 <= scan_interval <= 600):
            return jsonify({'success': False, 'message': 'Intervalo entre 5 y 600 segundos.'})
        elif scan_type in ['detailed', 'deep'] and scan_interval < 60:
            return jsonify({'success': False, 'message': 'Para escaneos detallados/profundos use mínimo 60 segundos.'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Intervalo debe ser un número.'})

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", network_range):
        return jsonify({'success': False, 'message': 'Formato inválido. Use CIDR (ej. 192.168.1.0/24).'})

    mask = int(network_range.split('/')[-1])
    if not (16 <= mask <= 32): 
        return jsonify({'success': False, 'message': f'Máscara /{mask} no soportada. Use /16 a /32.'})

    if scan_type not in ['quick', 'detailed', 'deep']:
        return jsonify({'success': False, 'message': 'Tipo de escaneo inválido.'})

    if not scan_active:
        scan_active = True
        scan_thread = threading.Thread(target=scan_worker)
        scan_thread.daemon = True
        scan_thread.start()
        
        type_names = {'quick': 'RÁPIDO', 'detailed': 'DETALLADO', 'deep': 'PROFUNDO'}
        add_log(f"🚀 Iniciando escaneo {type_names.get(scan_type, scan_type)}")
        add_log(f"🌐 Red objetivo: {network_range}")
        add_log(f"⏱️  Intervalo: {scan_interval}s")
        return jsonify({'success': True, 'message': 'Escaneo iniciado.'})
    else:
        return jsonify({'success': False, 'message': 'El escaneo ya está activo.'})

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    global scan_active
    if scan_active:
        scan_active = False
        add_log("⏹️ Escaneo detenido por el usuario")
        return jsonify({'success': True, 'message': 'Escaneo detenido.'})
    else:
        return jsonify({'success': False, 'message': 'El escaneo no estaba activo.'})

@app.route('/get_devices')
def get_devices():
    global known_devices
    devices_list = []
    for ip, device in sorted(known_devices.items(), key=lambda x: (not x[1].is_active, x[0])):
        status = "ACTIVO" if device.is_active else "INACTIVO"
        devices_list.append({
            'ip': device.ip,
            'hostname': device.hostname,
            'mac': device.mac,
            'vendor': device.vendor,
            'os': device.os,
            'os_class': device.os_class,
            'http_title': device.http_title,
            'ports': device.ports,
            'status': status,
            'last_seen': device.last_seen.strftime('%H:%M:%S'),
            'first_seen': device.first_seen.strftime('%H:%M:%S')
        })
    return jsonify(devices_list)

@app.route('/get_logs')
def get_logs():
    global logs
    return jsonify(logs)

@app.route('/get_status')
def get_status():
    global scan_active, network_range, scan_interval, last_scan_time, scan_in_progress, scan_type
    net_size = calculate_network_size(network_range)
    return jsonify({
        'scan_active': scan_active,
        'scan_in_progress': scan_in_progress, 
        'network_range': network_range,
        'scan_interval': scan_interval,
        'scan_type': scan_type,
        'last_scan_time': last_scan_time.strftime('%H:%M:%S') if last_scan_time else 'Nunca',
        'network_size': f"~{net_size} hosts"
    })

# --- 5. Funciones del Hilo de Escaneo ---

def scan_worker():
    """
    Hilo de escaneo con lógica de 3 strikes
    """
    global known_devices, scan_active, network_range, last_scan_time, scan_in_progress, scan_type
    
    scan_number = 0
    
    while scan_active:
        scan_number += 1
        scan_start_time = time.time()
        
        try:
            scan_in_progress = True
            add_log("=" * 60)
            add_log(f"🔍 ESCANEO #{scan_number} - {network_range}")
            add_log("=" * 60)
            
            current_devices_dict = scan_network(network_range, scan_type)
            
            last_scan_time = datetime.now()
            current_ips = set(current_devices_dict.keys())
            
            add_log(f"📊 Resumen: {len(current_ips)} dispositivos activos detectados")

            # Actualizar dispositivos existentes
            devices_to_remove = []
            for ip in list(known_devices.keys()):
                if ip in current_ips:
                    # Dispositivo detectado -> Activo
                    if not known_devices[ip].is_active:
                        add_log(f"🔄 {ip} reconectado")
                    known_devices[ip].is_active = True
                    known_devices[ip].inactive_count = 0
                    known_devices[ip].last_seen = datetime.now()
                    
                    # Actualizar información
                    current_dev_data = current_devices_dict[ip]
                    
                    # Actualizar hostname
                    if current_dev_data['hostname'] != 'Desconocido':
                        known_devices[ip].hostname = current_dev_data['hostname']
                    
                    # Actualizar MAC/Vendor
                    if known_devices[ip].mac == 'N/A' and current_dev_data.get('mac', 'N/A') != 'N/A':
                        known_devices[ip].mac = current_dev_data['mac']
                        known_devices[ip].vendor = current_dev_data.get('vendor', 'N/A')
                    
                    # Actualizar OS
                    if current_dev_data.get('os', 'N/A') != 'N/A':
                        if known_devices[ip].os == 'N/A' or known_devices[ip].os == 'Analizando...':
                            known_devices[ip].os = current_dev_data['os']
                        elif current_dev_data['os'] != known_devices[ip].os and '~' not in known_devices[ip].os:
                            known_devices[ip].os = current_dev_data['os']
                        
                    # Actualizar tipo
                    if current_dev_data.get('os_class', 'N/A') != 'N/A':
                        if known_devices[ip].os_class == 'N/A' or known_devices[ip].os_class == 'Analizando...':
                            known_devices[ip].os_class = current_dev_data['os_class']

                    # Actualizar título HTTP
                    if current_dev_data.get('http_title', 'N/A') != 'N/A':
                        known_devices[ip].http_title = current_dev_data['http_title']

                    # Actualizar puertos
                    new_ports = current_dev_data.get('ports', [])
                    if new_ports:
                        old_count = len(known_devices[ip].ports) if known_devices[ip].ports else 0
                        known_devices[ip].ports = new_ports
                        add_log(f"📝 {ip}: Actualizados {len(new_ports)} puertos (antes: {old_count})")
                    
                else:
                    # Dispositivo NO detectado
                    known_devices[ip].inactive_count += 1
                    
                    if known_devices[ip].inactive_count == 1:
                        if known_devices[ip].is_active:
                            add_log(f"⚠️ {ip} no responde (1/3)")
                        known_devices[ip].is_active = False
                    elif known_devices[ip].inactive_count == 2:
                        add_log(f"⚠️ {ip} no responde (2/3)")
                    elif known_devices[ip].inactive_count >= 3:
                        add_log(f"🗑️ Eliminando {ip} (3 escaneos inactivo)")
                        devices_to_remove.append(ip)

            # Eliminar dispositivos con 3+ escaneos inactivos
            for ip in devices_to_remove:
                del known_devices[ip]

            # Agregar nuevos dispositivos
            for ip in current_ips:
                if ip not in known_devices:
                    dev_data = current_devices_dict[ip]
                    new_dev = Device(dev_data['ip'], dev_data['hostname'])
                    new_dev.mac = dev_data.get('mac', 'N/A')
                    new_dev.vendor = dev_data.get('vendor', 'N/A')
                    new_dev.os = dev_data.get('os', 'N/A')
                    new_dev.os_class = dev_data.get('os_class', 'N/A')
                    new_dev.http_title = dev_data.get('http_title', 'N/A')
                    
                    ports_data = dev_data.get('ports', [])
                    new_dev.ports = ports_data if ports_data else []
                    
                    known_devices[ip] = new_dev
                    
                    ports_info = f"{len(ports_data)} puertos" if ports_data else "sin puertos"
                    add_log(f"🆕 Nuevo: {ip} ({dev_data['hostname']}) - {ports_info}")

        except Exception as e:
            add_log(f"❌ Error en ciclo de escaneo: {str(e)[:200]}")
            import traceback
            add_log(f"💥 Traceback: {traceback.format_exc()[:500]}")
            
        finally:
            scan_in_progress = False
            scan_duration = time.time() - scan_start_time
            add_log(f"⏱️ Escaneo #{scan_number} completado en {scan_duration:.1f}s")
            add_log(f"📊 Dispositivos en memoria: {len(known_devices)}")

            # Espera inteligente
            wait_time = max(1.0, scan_interval - scan_duration)
            add_log(f"⏸️  Esperando {wait_time:.0f}s hasta el próximo escaneo...")
            
            wait_start = time.time()
            while time.time() - wait_start < wait_time:
                if not scan_active:
                    break
                time.sleep(0.5) 

    add_log("🛑 Hilo de escaneo finalizado")


def calculate_network_size(network_range):
    try:
        _, prefix_str = network_range.split('/')
        prefix_len = int(prefix_str)
        if 0 <= prefix_len <= 32:
            total_hosts = 2 ** (32 - prefix_len)
            return total_hosts
    except (ValueError, IndexError):
        pass
    return 0

def add_log(message):
    global logs
    entry = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'message': message
    }
    print(f"[{entry['timestamp']}] {entry['message']}")
    logs.append(entry)
    if len(logs) > 200:
        logs.pop(0)


# --- 6. Plantilla HTML ---

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Escáner de Red - Monitor de Dispositivos</title>
    <style>
:root {
  --color-primary: #2563eb;
  --color-primary-hover: #1d4ed8;
  --color-success: #10b981;
  --color-danger: #ef4444;
  --color-warning: #f59e0b;
  --color-background: #f8fafc;
  --color-surface: #ffffff;
  --color-border: #e2e8f0;
  --color-text-primary: #0f172a;
  --color-text-secondary: #64748b;
  --color-text-tertiary: #94a3b8;
  --radius-sm: 0.375rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
  --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-base: 200ms cubic-bezier(0.4, 0, 0.2, 1);
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 
               'Helvetica Neue', Arial, sans-serif;
  background-color: var(--color-background);
  color: var(--color-text-primary);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.container {
  max-width: 1600px;
  margin-inline: auto;
  padding-inline: clamp(1rem, 3vw, 2rem);
  padding-block: 1.5rem;
}

header {
  background-color: var(--color-surface);
  padding: 1.5rem;
  text-align: center;
  border-radius: var(--radius-lg);
  margin-block-end: 1.5rem;
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--color-border);
}

header h1 {
  font-size: clamp(1.5rem, 4vw, 2rem);
  font-weight: 700;
  letter-spacing: -0.025em;
  color: var(--color-text-primary);
  margin-block-end: 0.5rem;
}

header p {
  color: var(--color-text-secondary);
  font-size: 0.9375rem;
}

.status-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-block-end: 1.5rem;
}

.stat {
  background-color: var(--color-surface);
  padding: 1.25rem;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--color-border);
  transition: box-shadow var(--transition-base);
}

.stat:hover {
  box-shadow: var(--shadow-md);
}

.stat strong {
  display: block;
  color: var(--color-text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
  margin-block-end: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--color-text-primary);
  letter-spacing: -0.025em;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.main-grid {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 1.5rem;
  align-items: start;
}

.card {
  background-color: var(--color-surface);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--color-border);
}

.card h2 {
  font-size: 1.125rem;
  font-weight: 700;
  margin-block-end: 1.25rem;
  color: var(--color-text-primary);
  letter-spacing: -0.025em;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.form-group {
  margin-block-end: 1.25rem;
}

label {
  display: block;
  font-weight: 500;
  margin-block-end: 0.5rem;
  font-size: 0.875rem;
  color: var(--color-text-secondary);
}

input,
select {
  width: 100%;
  padding: 0.625rem 0.875rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  font-size: 0.9375rem;
  background-color: var(--color-surface);
  color: var(--color-text-primary);
  transition: all var(--transition-fast);
}

input:focus,
select:focus {
  outline: 2px solid var(--color-primary);
  outline-offset: 2px;
  border-color: transparent;
}

input:hover:not(:focus),
select:hover:not(:focus) {
  border-color: var(--color-text-tertiary);
}

button {
  width: 100%;
  padding: 0.75rem 1rem;
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  font-size: 0.9375rem;
  font-weight: 600;
  margin-block-end: 0.75rem;
  transition: all var(--transition-fast);
  font-family: inherit;
}

.btn-start {
  background-color: var(--color-primary);
  color: white;
  box-shadow: var(--shadow-sm);
}

.btn-start:hover:not(:disabled) {
  background-color: var(--color-primary-hover);
  box-shadow: var(--shadow-md);
  transform: translateY(-1px);
}

.btn-start:active:not(:disabled) {
  transform: translateY(0);
}

.btn-stop {
  background-color: var(--color-background);
  color: var(--color-text-secondary);
  border: 1px solid var(--color-border);
}

.btn-stop:hover:not(:disabled) {
  background-color: #f1f5f9;
  border-color: var(--color-text-tertiary);
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.table-container {
  max-height: 500px;
  overflow-y: auto;
  overflow-x: auto;
  border-radius: var(--radius-md);
  border: 1px solid var(--color-border);
}

.table-container::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

.table-container::-webkit-scrollbar-track {
  background: var(--color-background);
}

.table-container::-webkit-scrollbar-thumb {
  background: var(--color-border);
  border-radius: var(--radius-sm);
}

.table-container::-webkit-scrollbar-thumb:hover {
  background: var(--color-text-tertiary);
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

thead {
  position: sticky;
  top: 0;
  z-index: 10;
  background-color: var(--color-background);
}

th {
  background-color: var(--color-background);
  padding: 0.875rem 0.75rem;
  text-align: start;
  font-weight: 600;
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-block-end: 2px solid var(--color-border);
  white-space: nowrap;
}

/* COLUMNAS AVANZADAS - OCULTAS POR DEFECTO */
.col-os, .col-type, .col-ports, .col-http {
  display: none;
}

/* MODO DETALLADO - Mostrar OS, Tipo, Puertos y Título HTTP */
body[data-scan-type="detailed"] .col-os,
body[data-scan-type="detailed"] .col-type,
body[data-scan-type="detailed"] .col-ports,
body[data-scan-type="detailed"] .col-http {
  display: table-cell;
}

/* MODO PROFUNDO - Mostrar TODO */
body[data-scan-type="deep"] .col-os,
body[data-scan-type="deep"] .col-type,
body[data-scan-type="deep"] .col-ports,
body[data-scan-type="deep"] .col-http {
  display: table-cell;
}

td {
  padding: 0.875rem 0.75rem;
  border-block-end: 1px solid var(--color-border);
  vertical-align: middle;
}

tbody tr {
  transition: background-color var(--transition-fast);
}

tbody tr:hover {
  background-color: var(--color-background);
}

tbody tr:last-child td {
  border-block-end: none;
}

.badge {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.625rem;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.025em;
}

.badge-active {
  background-color: #dcfce7;
  color: #166534;
}

.badge-inactive {
  background-color: #f3f4f6;
  color: #6b7280;
}

.port-badge {
  display: inline-block;
  background-color: var(--color-background);
  padding: 0.125rem 0.5rem;
  border-radius: var(--radius-sm);
  font-size: 0.7rem;
  margin: 0.125rem;
  font-family: 'SF Mono', 'Monaco', 'Cascadia Code', 'Courier New', monospace;
  border: 1px solid var(--color-border);
  color: var(--color-text-secondary);
}

.indicator {
  width: 0.625rem;
  height: 0.625rem;
  border-radius: 50%;
  display: inline-block;
}

.indicator-active {
  background-color: var(--color-success);
  box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

.indicator-scanning {
  background-color: var(--color-warning);
  box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
  animation: pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

.indicator-inactive {
  background-color: var(--color-danger);
}

@keyframes pulse {
  0%, 100% { 
    opacity: 1; 
    transform: scale(1);
  }
  50% { 
    opacity: 0.7; 
    transform: scale(1.05);
  }
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.analyzing {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--color-warning);
}

.analyzing::before {
  content: "⏳";
  display: inline-block;
  animation: spin 2s linear infinite;
}

.logs {
  background-color: #0f172a;
  color: #e2e8f0;
  border-radius: var(--radius-md);
  padding: 1rem;
  block-size: 300px;
  overflow-y: auto;
  font-family: 'SF Mono', 'Monaco', 'Cascadia Code', 'Courier New', monospace;
  font-size: 0.8125rem;
  margin-block-start: 1.5rem;
  border: 1px solid #1e293b;
  line-height: 1.5;
}

.logs::-webkit-scrollbar {
  width: 8px;
}

.logs::-webkit-scrollbar-track {
  background: #1e293b;
  border-radius: var(--radius-sm);
}

.logs::-webkit-scrollbar-thumb {
  background: #334155;
  border-radius: var(--radius-sm);
}

.logs::-webkit-scrollbar-thumb:hover {
  background: #475569;
}

.log-entry {
  padding-block: 0.25rem;
  opacity: 0.95;
}

.log-time {
  color: var(--color-text-tertiary);
  margin-inline-end: 0.75rem;
}

.info-box {
  background-color: #eff6ff;
  border-inline-start: 3px solid var(--color-primary);
  padding: 1rem;
  margin-block-end: 1.25rem;
  border-radius: var(--radius-md);
  font-size: 0.875rem;
  color: #1e40af;
  line-height: 1.6;
}

.info-box strong {
  display: block;
  margin-block-end: 0.5rem;
  font-weight: 600;
}

.info-box code {
  background-color: #dbeafe;
  padding: 0.125rem 0.375rem;
  border-radius: var(--radius-sm);
  font-family: monospace;
  font-size: 0.8125rem;
}

.text-muted {
  color: var(--color-text-tertiary);
}

@media (width < 1024px) {
  .main-grid {
    grid-template-columns: 1fr;
  }
}

@media (width < 640px) {
  .container {
    padding-inline: 1rem;
  }
  
  .status-bar {
    grid-template-columns: 1fr;
  }
  
  .stat {
    padding: 1rem;
  }
  
  .card {
    padding: 1.25rem;
  }
  
  th, td {
    font-size: 0.75rem;
    padding: 0.625rem 0.5rem;
  }
  
  .table-container {
    max-height: 400px;
  }
  
  .logs {
    block-size: 200px;
  }
}

@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-background: #0f172a;
    --color-surface: #1e293b;
    --color-border: #334155;
    --color-text-primary: #f1f5f9;
    --color-text-secondary: #cbd5e1;
    --color-text-tertiary: #94a3b8;
  }
  
  .logs {
    background-color: #020617;
  }
  
  .info-box {
    background-color: #1e3a8a;
    color: #93c5fd;
  }
  
  .info-box code {
    background-color: #1e40af;
  }
  
  input, select {
    background-color: #1e293b;
    color: var(--color-text-primary);
  }
  
  thead {
    background-color: #1e293b;
  }
  
  th {
    background-color: #1e293b;
  }
}
    </style>
</head>
<body data-scan-type="quick">
    <div class="container">
        <header>
            <h1>🌐 Escáner de Red</h1>
            <p>Monitor completo con detección de MAC, SO y Títulos HTTP</p>
        </header>

        <div class="status-bar">
            <div class="stat">
                <strong>Red</strong>
                <div class="stat-value" id="currentNetwork">-</div>
            </div>
            <div class="stat">
                <strong>Tipo</strong>
                <div class="stat-value" id="currentType">-</div>
            </div>
            <div class="stat">
                <strong>Último</strong>
                <div class="stat-value" id="lastScanTime">-</div>
            </div>
            <div class="stat">
                <strong>Estado</strong>
                <div class="stat-value">
                    <span class="indicator" id="indicator"></span>
                    <span id="statusText">Detenido</span>
                </div>
            </div>
        </div>

        <div class="main-grid">
            <aside class="card">
                <h2>⚙️ Configuración</h2>
                
                <div class="info-box">
                    <strong>💡 Modos de Escaneo</strong>
                    <strong>⚡ Rápido:</strong> IPs, MACs, Hostnames<br>
                    <strong>🔍 Detallado:</strong> + Puertos + SO + Títulos HTTP<br>
                    <strong>🔬 Profundo:</strong> + Versiones de servicios + Títulos HTTP<br>
                    <br>
                </div>
                
                <div class="form-group">
                    <label for="network_range">Red (CIDR)</label>
                    <input type="text" id="network_range" value="{{ network_range }}" placeholder="192.168.1.0/24">
                </div>
                <div class="form-group">
                    <label for="scan_type">Tipo de Escaneo</label>
                    <select id="scan_type">
                        <option value="quick">⚡ Rápido </option>
                        <option value="detailed">🔍 Detallado </option>
                        <option value="deep">🔬 Profundo </option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="scan_interval">Intervalo (segundos)</label>
                    <input type="number" id="scan_interval" min="5" max="600" value="{{ scan_interval }}" step="5">
                </div>
                <button class="btn-start" id="startBtn" onclick="startScan()">▶️ Iniciar Escaneo</button>
                <button class="btn-stop" id="stopBtn" onclick="stopScan()" disabled>⏹️ Detener</button>
            </aside>

            <main class="card">
                <h2>🖥️ Dispositivos <span class="badge badge-active" id="deviceCount">0</span></h2>
                <div class="table-container">
                    <table id="devicesTable">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Hostname</th>
                                <th>MAC Address</th>
                                <th>Fabricante</th>
                                <th class="col-os">Sistema Operativo</th>
                                <th class="col-type">Tipo</th>
                                <th class="col-ports">Puertos</th>
                                <th class="col-http">Título HTTP</th>
                                <th>Estado</th>
                                <th>Última Vez</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td colspan="10" style="text-align: center; padding: 2rem; color: var(--color-text-tertiary);">
                                    Inicia un escaneo para ver dispositivos
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </main>
        </div>

        <div class="logs" id="logs">
            <div class="log-entry">
                <span class="log-time">[--:--:--]</span>
                Sistema iniciado. Los logs mostrarán información detallada del escaneo...
            </div>
        </div>
    </div>

    <script>
        let scanActive = {{ 'true' if scan_active else 'false' }};
        let currentScanType = 'quick';

        function updateTableColumns(scanType) {
            currentScanType = scanType;
            document.body.setAttribute('data-scan-type', scanType);
            console.log('Tipo de escaneo actualizado a:', scanType);
        }

        function updateStatus() {
            fetch('/get_status')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('currentNetwork').textContent = data.network_range;
                    document.getElementById('lastScanTime').textContent = data.last_scan_time;
                    
                    const typeMap = {
                        'quick': 'Rápido', 
                        'detailed': 'Detallado', 
                        'deep': 'Profundo'
                    };
                    document.getElementById('currentType').textContent = typeMap[data.scan_type] || data.scan_type;

                    if (data.scan_type !== currentScanType) {
                        updateTableColumns(data.scan_type);
                    }

                    const indicator = document.getElementById('indicator');
                    const statusText = document.getElementById('statusText');
                    const startBtn = document.getElementById('startBtn');
                    const stopBtn = document.getElementById('stopBtn');

                    if (data.scan_active) {
                        if (data.scan_in_progress) {
                            indicator.className = 'indicator indicator-scanning';
                            statusText.textContent = 'Escaneando';
                        } else {
                            indicator.className = 'indicator indicator-active';
                            statusText.textContent = 'Activo';
                        }
                        startBtn.disabled = true;
                        stopBtn.disabled = false;
                    } else {
                        indicator.className = 'indicator indicator-inactive';
                        statusText.textContent = 'Detenido';
                        startBtn.disabled = false;
                        stopBtn.disabled = true;
                    }
                    scanActive = data.scan_active;
                })
                .catch(err => console.error('Error al actualizar estado:', err));
        }

        function updateDevices() {
            if (!scanActive) return;

            fetch('/get_devices')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.querySelector('#devicesTable tbody');
                    tbody.innerHTML = '';
                    let activeCount = 0;
                    
                    if (data.length === 0) {
                        const colspan = currentScanType === 'quick' ? '6' : '10';
                        tbody.innerHTML = `
                            <tr>
                                <td colspan="${colspan}" style="text-align: center; padding: 2rem; color: var(--color-text-tertiary);">
                                    🔍 Esperando resultados del escaneo...<br>
                                    <small style="opacity: 0.7; margin-top: 0.5rem; display: block;">
                                    Revisa los logs abajo para ver el progreso
                                    </small>
                                </td>
                            </tr>
                        `;
                        document.getElementById('deviceCount').textContent = '0';
                        return;
                    }
                    
                    data.forEach(device => {
                        if (device.status === 'ACTIVO') activeCount++;
                        const row = tbody.insertRow();
                        
                        const badgeClass = device.status === 'ACTIVO' ? 'badge-active' : 'badge-inactive';
                        
                        let osDisplay = '<span class="text-muted">N/A</span>';
                        if (device.os === 'Analizando...') {
                            osDisplay = '<span class="analyzing">Analizando...</span>';
                        } else if (device.os !== 'N/A') {
                            osDisplay = device.os;
                        }
                        
                        let osClassDisplay = '<span class="text-muted">N/A</span>';
                        if (device.os_class === 'Analizando...') {
                            osClassDisplay = '<span class="analyzing">Analizando...</span>';
                        } else if (device.os_class !== 'N/A') {
                            osClassDisplay = device.os_class;
                        }
                        
                        let portsHtml = '<span class="text-muted">N/A</span>';
                        if (device.ports && device.ports.length > 0) {
                            if (device.ports[0] === 'Analizando...') {
                                portsHtml = '<span class="analyzing">Analizando...</span>';
                            } else {
                                portsHtml = device.ports.map(p => `<span class="port-badge">${p}</span>`).join(' ');
                            }
                        }
                        
                        const httpDisplay = device.http_title !== 'N/A' ? device.http_title : '<span class="text-muted">N/A</span>';
                        
                        row.innerHTML = `
                            <td><strong>${device.ip}</strong></td>
                            <td><strong>${device.hostname}</strong></td>
                            <td style="font-family: monospace; font-size: 0.85em;">${device.mac}</td>
                            <td><small class="text-muted">${device.vendor || 'N/A'}</small></td>
                            <td class="col-os">${osDisplay}</td>
                            <td class="col-type">${osClassDisplay}</td>
                            <td class="col-ports">${portsHtml}</td>
                            <td class="col-http"><small>${httpDisplay}</small></td>
                            <td><span class="badge ${badgeClass}">${device.status}</span></td>
                            <td>${device.last_seen}</td>
                        `;
                    });
                    
                    document.getElementById('deviceCount').textContent = activeCount;
                })
                .catch(err => console.error('Error al actualizar dispositivos:', err));
        }

        function updateLogs() {
            fetch('/get_logs')
                .then(r => r.json())
                .then(data => {
                    const logsDiv = document.getElementById('logs');
                    const shouldScroll = logsDiv.scrollTop + logsDiv.clientHeight >= logsDiv.scrollHeight - 30;
                    
                    logsDiv.innerHTML = '';
                    data.forEach(log => {
                        const entry = document.createElement('div');
                        entry.className = 'log-entry';
                        entry.innerHTML = `<span class="log-time">[${log.timestamp}]</span>${log.message}`;
                        logsDiv.appendChild(entry);
                    });
                    
                    if (shouldScroll) {
                        logsDiv.scrollTop = logsDiv.scrollHeight;
                    }
                })
                .catch(err => console.error('Error al actualizar logs:', err));
        }

        function startScan() {
            const network = document.getElementById('network_range').value;
            const interval = document.getElementById('scan_interval').value;
            const scanType = document.getElementById('scan_type').value;
            
            if (!network.trim()) {
                alert('⚠️ Por favor ingresa una red válida (ej: 192.168.1.0/24)');
                return;
            }
            
            fetch('/start_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `network_range=${encodeURIComponent(network)}&scan_interval=${encodeURIComponent(interval)}&scan_type=${encodeURIComponent(scanType)}`
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert('❌ Error: ' + data.message);
                } else {
                    updateTableColumns(scanType);
                }
            })
            .catch(err => {
                console.error('Error al iniciar escaneo:', err);
                alert('❌ Error de conexión al servidor');
            });
        }

        function stopScan() {
            fetch('/stop_scan', { method: 'POST' })
                .catch(err => console.error('Error al detener escaneo:', err));
        }

        setInterval(updateStatus, 2000);
        setInterval(() => { 
            if (scanActive) { 
                updateDevices(); 
                updateLogs(); 
            } 
        }, 3000);
        
        updateStatus();
        updateLogs();
        if (scanActive) updateDevices();
    </script>
</body>
</html>
'''


# --- 7. Punto de Entrada ---
if __name__ == '__main__':
    _, local_ip = get_local_network()
    local_mac = get_local_mac()
    
    print(f"\n{'='*60}")
    print(f"  🌐 ESCÁNER DE RED - VERSIÓN CON TÍTULOS HTTP")
    print(f"{'='*60}")
    
    if os.name != 'nt':
        print(f"\n⚠️  CRÍTICO - EJECUTA CON SUDO:")
        print(f"   sudo venv/bin/python3 app_web_escaneo.py")
        print(f"\n   Sin sudo: escaneo SYN (-sS) y OS detection (-O) NO funcionarán")
    
    print(f"\n📡 Información del sistema:")
    print(f"   IP Local:  {local_ip}")
    if local_mac:
        print(f"   MAC Local: {local_mac}")
        print(f"   Vendor:    {get_vendor_from_mac(local_mac)}")
    else:
        print(f"   MAC Local: ⚠️  No detectada")
    
    print(f"\n📡 URLs de acceso:")
    print(f"   Local:  http://127.0.0.1:5000")
    print(f"   Red:    http://{local_ip}:5000")
    print(f"\n💡 Funcionalidades implementadas:")
    print(f"   ✅ Detección automática de MAC local")
    print(f"   ✅ Base de datos expandida de fabricantes")
    print(f"   ✅ Selección inteligente de SO (prioriza versiones modernas)")
    print(f"   ✅ Inferencia de tipo de dispositivo mejorada")
    print(f"   ✅ NUEVO: Extracción de títulos HTTP/HTTPS")
    print(f"   ✅ NUEVO: Timeout de 3s para páginas web")
    print(f"   ✅ NUEVO: Soporte para certificados SSL autofirmados")
    print(f"\n💡 Presiona Ctrl+C para detener")
    print(f"{'='*60}\n")
    
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)