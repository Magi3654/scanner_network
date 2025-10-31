# app_web_escaneo.py
from flask import Flask, render_template_string, request, jsonify
import nmap
import threading
import time
from datetime import datetime
from collections import defaultdict
import socket
import re
import os

# --- 1. Definición de Clases ---

class Device:
    """Clase para representar un dispositivo en la red."""
    def __init__(self, ip, hostname="Desconocido"):
        self.ip = ip
        self.hostname = hostname
        self.mac = "N/A"
        self.vendor = "N/A"
        self.os = "N/A"
        self.os_class = "N/A" # --- MEJORA: Tipo de dispositivo (router, etc.)
        self.http_title = "N/A" # --- MEJORA: Título de página web
        self.ports = []
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.is_active = True

# --- 2. Funciones de Red ---

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

# --- MEJORA: Función de escaneo optimizada ---
def scan_network(network_range, scan_type='quick'):
    """Escanea la red usando nmap para dispositivos activos."""
    nm = nmap.PortScanner()
    devices_dict = {}
    
    if scan_type == 'detailed':
        # -O: Detección de OS
        # --top-ports 20: Escanea los 20 puertos más comunes
        # -PE: ARP discovery
        # Tiempos de espera más largos porque el escaneo de OS/puertos es lento
        scan_args = '-O --top-ports 20 -PE --host-timeout 10m --max-retries 1 --min-rate 500 --min-parallelism 32'
    elif scan_type == 'deep':
        # -O: Detección de OS
        # -sV: Detección de Versión de Servicio
        # --script http-title: Intenta obtener el título de la web
        # Tiempos aún más lentos, es un escaneo muy intrusivo
        scan_args = '-O -sV --top-ports 20 -PE --script http-title --host-timeout 15m --max-retries 1 --min-rate 300 --min-parallelism 16'
    else:
        # Escaneo rápido (solo ping)
        scan_args = '-sn -PE --host-timeout 5s --max-retries 1 --min-rate 1000 --min-parallelism 64'
    
    is_windows = (os.name == 'nt')

    try:
        if is_windows:
            nm.scan(hosts=network_range, arguments=scan_args)
        else:
            nm.scan(hosts=network_range, arguments=scan_args, sudo=True) 
    
    except nmap.nmap.PortScannerError as e:
        if not is_windows and 'sudo' in str(e):
            add_log(f"Error con sudo. Reintentando sin privilegios: {e}")
            try:
                 nm.scan(hosts=network_range, arguments=scan_args)
            except Exception as e_nosudo:
                 print(f"Error en el escaneo de nmap (sin sudo): {e_nosudo}")
                 add_log(f"ERROR en Nmap (sin sudo): {e_nosudo}")
                 return {}
        else:
            print(f"Error en el escaneo de nmap: {e}")
            add_log(f"ERROR en Nmap: {e}. ¿Está 'nmap' instalado y en el PATH del sistema?")
            return {}
    except Exception as e_general:
         print(f"Error general en el escaneo: {e_general}")
         add_log(f"ERROR: {e_general}. Asegúrate que Nmap esté instalado y en el PATH.")
         return {}

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            hostname = nm[host].hostname() or "Desconocido"
            
            # --- MEJORA: Obtener MAC y Vendor ---
            mac = nm[host]['addresses'].get('mac', 'N/A')
            vendor = "N/A"
            if mac != 'N/A' and 'vendor' in nm[host] and mac in nm[host]['vendor']:
                vendor = nm[host]['vendor'][mac]

            # --- MEJORA: Obtener OS ---
            os_match = nm[host].get('osmatch', [])
            os_name = os_match[0]['name'] if os_match else 'N/A'
            
            # --- MEJORA: Obtener Tipo de Dispositivo (OS Class) ---
            os_class_list = nm[host].get('osclass', [])
            os_class = os_class_list[0].get('type', 'N/A') if os_class_list else 'N/A'
            
            # --- MEJORA: Obtener Título HTTP (de NSE) ---
            http_title = nm[host].get('script', {}).get('http-title', 'N/A')
            if isinstance(http_title, dict): # A veces nmap anida la respuesta
                http_title = http_title.get('output', 'N/A')
            http_title = http_title.strip()


            # --- MEJORA: Obtener Puertos y Versiones ---
            ports_list = []
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    service = nm[host]['tcp'][port].get('name', 'unknown')
                    version = nm[host]['tcp'][port].get('version', '')
                    ports_list.append(f"{port}/{service} ({version})" if version else f"{port}/{service}")

            devices_dict[host] = {
                'ip': host, 
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'os': os_name,
                'os_class': os_class,
                'http_title': http_title,
                'ports': ports_list
            }
            
    return devices_dict

# --- 3. Configuración de Flask ---

app = Flask(__name__)

# Variables globales para el estado de la aplicación
known_devices = {}
scan_active = False
scan_in_progress = False 
scan_thread = None
network_range = get_local_network()[0] 
scan_interval = 10
scan_type = 'quick' # --- MEJORA: Añadir tipo de escaneo global
last_scan_time = None
logs = []

# --- 4. Rutas de la Aplicación Web ---

@app.route('/')
def index():
    """Renderiza la página principal de la aplicación."""
    global network_range, scan_interval, scan_active
    default_network, local_ip = get_local_network()
    return render_template_string(HTML_TEMPLATE, 
                                  network_range=network_range, 
                                  scan_interval=scan_interval,
                                  scan_active=scan_active,
                                  local_ip=local_ip)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Inicia el proceso de escaneo en un hilo separado."""
    global scan_active, scan_thread, network_range, scan_interval, scan_type
    network_range = request.form.get('network_range', network_range)
    scan_type = request.form.get('scan_type', 'quick') # --- MEJORA: Obtener tipo de escaneo
    
    try:
        scan_interval = int(request.form.get('scan_interval', scan_interval))
        if not (5 <= scan_interval <= 3600): # Aumentado el límite superior
             return jsonify({'success': False, 'message': 'Intervalo debe estar entre 5 y 3600 segundos.'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Intervalo debe ser un número entero.'})

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", network_range):
        return jsonify({'success': False, 'message': 'Formato de rango de red inválido. Use CIDR (ej. 192.168.1.0/24).'})

    mask = int(network_range.split('/')[-1])
    if not (12 <= mask <= 32): 
        return jsonify({'success': False, 'message': f'Máscara /{mask} no soportada. Use entre /12 y /32.'})

    if scan_type not in ['quick', 'detailed', 'deep']:
        return jsonify({'success': False, 'message': 'Tipo de escaneo inválido.'})

    if not scan_active:
        scan_active = True
        scan_thread = threading.Thread(target=scan_worker)
        scan_thread.daemon = True
        scan_thread.start()
        
        if scan_type == 'deep':
            add_log("Iniciando escaneo PROFUNDO. Esto puede tardar mucho tiempo.")
        elif scan_type == 'detailed':
            add_log("Iniciando escaneo DETALLADO. Esto puede tardar varios minutos.")
        else:
            add_log("Iniciando escaneo RÁPIDO.")
            
        return jsonify({'success': True, 'message': 'Escaneo iniciado.'})
    else:
        return jsonify({'success': False, 'message': 'El escaneo ya está activo.'})

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    """Detiene el proceso de escaneo."""
    global scan_active
    if scan_active:
        scan_active = False
        add_log("Escaneo detenido por el usuario.")
        return jsonify({'success': True, 'message': 'Escaneo detenido.'})
    else:
        return jsonify({'success': False, 'message': 'El escaneo no estaba activo.'})

@app.route('/get_devices')
def get_devices():
    """API endpoint para obtener la lista de dispositivos como JSON."""
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
    """API endpoint para obtener los logs como JSON."""
    global logs
    return jsonify(logs)

@app.route('/get_status')
def get_status():
    """API endpoint para obtener el estado del escaneo."""
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

# --- MEJORA: Lógica de worker mejorada ---
def scan_worker():
    """Bucle principal del hilo de escaneo."""
    global known_devices, scan_active, network_range, last_scan_time, scan_in_progress, scan_type
    
    while scan_active:
        scan_start_time = time.time()
        try:
            scan_in_progress = True
            add_log(f"Iniciando escaneo {scan_type} de {network_range}...")
            
            current_devices_dict = scan_network(network_range, scan_type)
            
            last_scan_time = datetime.now()
            current_ips = set(current_devices_dict.keys())
            
            add_log(f"Nmap detectó {len(current_ips)} hosts. Procesando...")

            # Actualizar estado de dispositivos conocidos
            for ip in known_devices:
                if ip in current_ips:
                    if not known_devices[ip].is_active:
                         add_log(f"Dispositivo reconectado: {ip}")
                    known_devices[ip].is_active = True
                    known_devices[ip].last_seen = datetime.now()
                    
                    # --- MEJORA: Actualizar datos si no se tenían ---
                    current_dev_data = current_devices_dict[ip]
                    if known_devices[ip].mac == 'N/A' and current_dev_data.get('mac', 'N/A') != 'N/A':
                        known_devices[ip].mac = current_dev_data['mac']
                        known_devices[ip].vendor = current_dev_data.get('vendor', 'N/A')
                        add_log(f"MAC/Vendor actualizado para {ip}")

                    if known_devices[ip].os == 'N/A' and current_dev_data.get('os', 'N/A') != 'N/A':
                        known_devices[ip].os = current_dev_data['os']
                        add_log(f"OS actualizado para {ip}: {known_devices[ip].os}")
                        
                    if known_devices[ip].os_class == 'N/A' and current_dev_data.get('os_class', 'N/A') != 'N/A':
                        known_devices[ip].os_class = current_dev_data['os_class']

                    if known_devices[ip].http_title == 'N/A' and current_dev_data.get('http_title', 'N/A') != 'N/A':
                        known_devices[ip].http_title = current_dev_data['http_title']

                    if not known_devices[ip].ports and current_dev_data.get('ports'):
                        known_devices[ip].ports = current_dev_data['ports']

                else:
                    if known_devices[ip].is_active:
                         add_log(f"Dispositivo desconectado: {ip}")
                    known_devices[ip].is_active = False

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
                    new_dev.ports = dev_data.get('ports', [])
                    known_devices[ip] = new_dev
                    add_log(f"Nuevo dispositivo: {ip} ({dev_data['hostname']}) [OS: {new_dev.os}]")

        except Exception as e:
            add_log(f"Error en el hilo de escaneo: {e}")
        finally:
            scan_in_progress = False
            scan_duration = time.time() - scan_start_time
            add_log(f"Escaneo tardó {scan_duration:.2f} seg.")

            # Lógica de espera inteligente
            wait_time = max(1.0, scan_interval - scan_duration)
            
            # Bucle de espera "interrumpible"
            wait_start = time.time()
            while time.time() - wait_start < wait_time:
                if not scan_active:
                    break
                time.sleep(0.5) 

    add_log("Hilo de escaneo finalizado.")


def calculate_network_size(network_range):
    """Calcula el número de hosts posibles en una red CIDR."""
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
    """Agrega un mensaje a la lista de logs."""
    global logs
    entry = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'message': message
    }
    print(f"LOG: [{entry['timestamp']}] {entry['message']}") # Imprime también a la consola
    logs.append(entry)
    # Mantener solo los últimos 100 logs
    if len(logs) > 100:
        logs.pop(0)


# --- 6. Plantilla HTML (Incrustada) ---

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Escáner de Red Web</title>
    <style>
        :root {
            --primary: #2c3e50;
            --primary-dark: #1a252f;
            --secondary: #3498db;
            --success: #2ecc71;
            --success-light: #d5f5e3;
            --warning: #f39c12;
            --warning-light: #fef9e7;
            --danger: #e74c3c;
            --danger-light: #fadbd8;
            --light-gray: #f8f9fa;
            --gray-border: #e9ecef;
            --text-dark: #212529;
            --text-muted: #6c757d;
            --shadow-sm: 0 4px 12px rgba(0, 0, 0, 0.05);
            --shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', sans-serif;
            background: var(--light-gray);
            color: var(--text-dark);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: #ffffff;
            color: var(--text-dark);
            padding: 30px 40px;
            text-align: center;
            border-radius: 12px;
            border: 1px solid var(--gray-border);
            margin-bottom: 20px;
            box-shadow: var(--shadow-sm);
        }

        header h1 {
            font-size: 2.2em;
            font-weight: 600;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
        }

        header p {
            font-weight: 400;
            opacity: 0.9;
            font-size: 1.1em;
            color: var(--text-muted);
        }

        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .status-card {
            background-color: white;
            border: 1px solid var(--gray-border);
            border-radius: 12px;
            padding: 25px;
            display: flex;
            flex-direction: column;
            align-items: center;
            box-shadow: var(--shadow-sm);
            transition: var(--transition);
        }

        .status-card:hover {
            box-shadow: var(--shadow);
            transform: translateY(-4px);
        }
        
        .status-card strong {
            color: var(--secondary);
            font-size: 0.9em;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        .status-value {
            font-weight: 600;
            font-size: 1.5em;
            color: var(--text-dark);
        }
        
        .status-value-small {
            font-weight: 600;
            font-size: 1.3em;
            color: var(--text-dark);
        }
        
        .status-indicator-wrapper {
             display: flex; 
             align-items: center; 
             gap: 10px;
        }

        .status-indicator {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            display: inline-block;
            transition: var(--transition);
        }

        .status-indicator.active {
            background-color: var(--success);
            box-shadow: 0 0 10px var(--success);
            animation: pulse 1.5s infinite;
        }
        
        .status-indicator.scanning {
            background-color: var(--warning);
            box-shadow: 0 0 10px var(--warning);
            animation: pulse-warn 1s infinite;
        }

        .status-indicator.inactive {
            background-color: var(--danger);
        }

        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(46, 204, 113, 0); }
            100% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0); }
        }
        
        @keyframes pulse-warn {
            0% { box-shadow: 0 0 0 0 rgba(243, 156, 18, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(243, 156, 18, 0); }
            100% { box-shadow: 0 0 0 0 rgba(243, 156, 18, 0); }
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 3fr;
            gap: 20px;
        }

        .card {
            background-color: white;
            border: 1px solid var(--gray-border);
            border-radius: 12px;
            box-shadow: var(--shadow-sm);
            padding: 30px;
            display: flex;
            flex-direction: column;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--gray-border);
        }

        .card-title {
            font-size: 1.5em;
            color: var(--text-dark);
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .config-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
            flex: 1;
        }

        .form-row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            align-items: end; 
        }

        .form-group {
            display: flex;
            flex-direction: column;
            flex: 1;
            min-width: 150px; 
        }

        label {
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--text-dark);
            font-size: 0.95em;
        }

        input[type="text"], input[type="number"], select {
            padding: 14px 16px;
            border: 1px solid var(--gray-border);
            border-radius: 8px;
            font-size: 1em;
            transition: var(--transition);
            background-color: var(--light-gray);
            width: 100%;
        }

        input[type="text"]:focus, input[type="number"]:focus, select:focus {
            outline: none;
            border-color: var(--secondary);
            box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.2);
            background-color: white;
        }
        
        input[type="number"] {
             width: 100px;
        }

        .controls {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 15px;
        }

        button {
            padding: 12px 26px;
            border: 1px solid transparent;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }

        button:active {
             transform: translateY(2px);
             box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        button#startBtn {
            background-color: var(--secondary);
            border-color: var(--secondary);
            color: white;
            box-shadow: 0 4px 10px rgba(52, 152, 219, 0.2);
        }

        button#startBtn:hover:not(:disabled) {
            background-color: #2980b9;
            border-color: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(52, 152, 219, 0.3);
        }

        button#stopBtn {
            background-color: var(--light-gray);
            color: var(--text-dark);
            border-color: var(--gray-border);
        }

        button#stopBtn:hover:not(:disabled) {
            background-color: var(--gray-border);
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
            box-shadow: none;
        }
        
        .table-container {
            flex: 1; 
            overflow-y: auto; 
            min-height: 400px; 
            max-height: 80vh;
        }
        
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            white-space: normal;
        }

        th {
            background-color: var(--light-gray);
            color: var(--text-muted);
            font-weight: 600;
            text-align: left;
            padding: 16px 20px;
            position: sticky; 
            top: 0;
            z-index: 1;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--gray-border);
        }

        td {
            padding: 16px 20px;
            border-bottom: 1px solid var(--gray-border);
            transition: background-color 0.2s;
            vertical-align: middle;
            font-size: 0.95em;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover {
            background-color: #fcfcfc;
        }
        
        td small {
            color: var(--text-muted);
            font-size: 0.9em;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-align: center;
            min-width: 80px;
        }

        .status-badge.active {
            background-color: var(--success-light);
            color: #1a6a42;
        }

        .status-badge.inactive {
            background-color: var(--danger-light);
            color: #a73c3c;
        }

        .port-badge {
            background-color: var(--gray-border);
            color: var(--text-muted);
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.9em;
            margin: 2px;
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
        }

        .logs-container {
            background-color: #2c3e50;
            color: #ecf0f1;
            border-radius: 8px;
            padding: 20px;
            height: 300px; 
            overflow-y: auto;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            flex: 1;
            min-height: 0;
        }

        .log-entry {
            padding: 4px 0;
            border-left: 4px solid transparent;
            display: flex;
        }

        .log-timestamp {
            color: #7f8c8d;
            margin-right: 15px;
            flex-shrink: 0; 
        }

        .log-message {
            flex: 1; 
        }

        .log-entry.info { border-left-color: #89b4fa; }
        .log-entry.success { border-left-color: #a6e3a1; }
        .log-entry.warning { border-left-color: #f9e2af; } 
        .log-entry.error { border-left-color: #f38ba8; }

        .device-count {
            background-color: var(--secondary);
            color: white;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }

        @media (max-width: 1200px) {
             .main-content {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 768px) {
            .status-grid {
                grid-template-columns: 1fr;
                text-align: center;
            }
            .form-row {
                flex-direction: column;
                align-items: stretch;
            }
            .form-group {
                min-width: 100%;
            }
            input[type="number"] {
                 width: 100%;
            }
            button {
                width: 100%;
                justify-content: center;
            }
            .card {
                padding: 20px;
            }
            header h1 {
                font-size: 1.8em;
            }
            .container {
                padding: 10px;
            }
            body {
                padding: 0;
            }
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <header>
            <h1>🌐 Escáner de Red Web</h1>
            <p>Monitoriza dispositivos activos en tu red</p>
        </header>

        <div class="status-grid">
            <div class="status-card">
                <strong>Red Actual</strong>
                <span class="status-value" id="currentNetwork">-</span>
            </div>
            <div class="status-card">
                <strong>Tipo de Escaneo</strong>
                <span class="status-value-small" id="currentScanType">-</span>
            </div>
            <div class="status-card">
                <strong>Último Escaneo</strong>
                <span class="status-value-small" id="lastScanTime">-</span>
            </div>
            <div class="status-card">
                <strong>Tamaño Estimado</strong>
                <span class="status-value-small" id="networkSize">-</span>
            </div>
            <div class="status-card">
                <strong>Estado del Escaneo</strong>
                <div class="status-indicator-wrapper">
                    <span class="status-indicator" id="scanIndicator"></span>
                    <span class="status-value" id="scanStatus">Detenido</span>
                </div>
            </div>
        </div>


        <div class="main-content">
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">⚙️ Configuración</h2>
                </div>
                <div class="config-form">
                    <div class="form-group">
                        <label for="network_range">Rango de Red (CIDR)</label>
                        <input type="text" id="network_range" value="{{ network_range }}" placeholder="ej. 192.168.1.0/24">
                    </div>
                    <div class="form-group">
                        <label for="scan_type">Tipo de Escaneo</label>
                        <select id="scan_type">
                            <option value="quick" selected>Rápido (Solo Descubrir)</option>
                            <option value="detailed">Detallado (OS y Puertos)</option>
                            <option value="deep">Profundo (Versión y Scripts)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="scan_interval">Intervalo (segundos)</label>
                        <input type="number" id="scan_interval" min="5" max="3600" value="{{ scan_interval }}">
                    </div>
                    <div class="controls">
                        <button id="startBtn" onclick="startScan()">▶️ Iniciar Escaneo</button>
                        <button id="stopBtn" onclick="stopScan()" disabled>⏹️ Detener Escaneo</button>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        🖥️ Dispositivos Detectados
                        <span class="device-count" id="deviceCount">0</span>
                    </h2>
                </div>
                <div class="table-container">
                    <table id="devicesTable">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Hostname / Fabricante</th>
                                <th>MAC Address</th>
                                <th>Sistema Operativo</th>
                                <th>Tipo / Título Web</th>
                                <th>Puertos Abiertos</th>
                                <th>Estado</th>
                                <th>Última Vez Visto</th>
                                <th>Primera Vez Visto</th>
                            </tr>
                        </thead>
                        <tbody id="devicesTableBody">
                            <!-- Datos cargados por JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card" style="grid-column: 1 / -1;"> <!-- Ocupa las dos columnas -->
                <div class="card-header">
                    <h2 class="card-title">📝 Registros (Logs)</h2>
                </div>
                <div class="logs-container" id="logs">
                    <!-- Logs cargados por JavaScript -->
                </div>
            </div>
        </div>
    </div>

    <script>
        let scanActive = {{ 'true' if scan_active else 'false' }};
        let dataRefreshIntervalId;

        function updateStatus() {
            fetch('/get_status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('currentNetwork').textContent = data.network_range;
                    document.getElementById('networkSize').textContent = data.network_size;
                    document.getElementById('lastScanTime').textContent = data.last_scan_time;
                    
                    const type_map = {'quick': 'Rápido', 'detailed': 'Detallado', 'deep': 'Profundo'};
                    document.getElementById('currentScanType').textContent = type_map[data.scan_type] || data.scan_type;

                    const indicator = document.getElementById('scanIndicator');
                    const statusText = document.getElementById('scanStatus');
                    const startBtn = document.getElementById('startBtn');
                    const stopBtn = document.getElementById('stopBtn');

                    if (data.scan_active) {
                        if (data.scan_in_progress) {
                            indicator.className = 'status-indicator scanning';
                            statusText.textContent = 'Escaneando...';
                        } else {
                            indicator.className = 'status-indicator active';
                            statusText.textContent = 'Activo';
                        }
                        startBtn.disabled = true;
                        stopBtn.disabled = false;
                    } else {
                        indicator.className = 'status-indicator inactive';
                        statusText.textContent = 'Detenido';
                        startBtn.disabled = false;
                        stopBtn.disabled = true;
                    }
                    scanActive = data.scan_active; 
                })
                .catch(error => console.error('Error al obtener estado:', error));
        }

        function updateDevices() {
            if (!scanActive) return; 

            fetch('/get_devices')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('devicesTableBody');
                    tbody.innerHTML = ''; // Limpiar tabla
                    let activeCount = 0;
                    data.forEach(device => {
                        if(device.status === 'ACTIVO') activeCount++;
                        const row = tbody.insertRow();
                        
                        let cellIndex = 0;
                        row.insertCell(cellIndex++).textContent = device.ip;

                        // Celda de Hostname y Vendor
                        const hostCell = row.insertCell(cellIndex++);
                        hostCell.innerHTML = `<strong>${device.hostname}</strong><br><small>${device.vendor || 'N/A'}</small>`;

                        // Celda de MAC
                        row.insertCell(cellIndex++).textContent = device.mac || 'N/A';
                        
                        // Celda de OS
                        row.insertCell(cellIndex++).textContent = device.os || 'N/A';

                        // Celda de Tipo / Título
                        const detailsCell = row.insertCell(cellIndex++);
                        detailsCell.innerHTML = `<strong>${device.os_class || 'N/A'}</strong><br><small>${device.http_title || ''}</small>`;
                        
                        // Celda de Puertos
                        const portsCell = row.insertCell(cellIndex++);
                        if(device.ports && device.ports.length > 0) {
                            portsCell.innerHTML = device.ports.map(p => `<span class="port-badge">${p}</span>`).join(' ');
                        } else {
                            portsCell.textContent = 'N/A';
                        }

                        // Celda de Status
                        const statusCell = row.insertCell(cellIndex++);
                        const badge = document.createElement('span');
                        badge.className = `status-badge ${device.status.toLowerCase()}`;
                        badge.textContent = device.status;
                        statusCell.appendChild(badge);

                        row.insertCell(cellIndex++).textContent = device.last_seen;
                        row.insertCell(cellIndex++).textContent = device.first_seen;
                    });
                    document.getElementById('deviceCount').textContent = `${activeCount} / ${data.length}`;
                })
                .catch(error => console.error('Error al obtener dispositivos:', error));
        }

        function updateLogs() {
            fetch('/get_logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('logs');
                    const shouldScroll = logsDiv.scrollTop + logsDiv.clientHeight >= logsDiv.scrollHeight - 30;
                    
                    logsDiv.innerHTML = ''; 
                    data.forEach(log => {
                        const logEntry = document.createElement('div');
                        if (log.message.toLowerCase().includes('error')) {
                            logEntry.className = 'log-entry error';
                        } else if (log.message.includes('Nuevo dispositivo') || log.message.includes('reconectado')) {
                            logEntry.className = 'log-entry success';
                        } else if (log.message.includes('desconectado') || log.message.includes('sudo')) {
                             logEntry.className = 'log-entry warning';
                        } else {
                            logEntry.className = 'log-entry info';
                        }
                        logEntry.innerHTML = `<span class="log-timestamp">[${log.timestamp}]</span><span class="log-message">${log.message}</span>`;
                        logsDiv.appendChild(logEntry);
                    });
                    
                    if(shouldScroll) {
                        logsDiv.scrollTop = logsDiv.scrollHeight; // Auto-scroll abajo
                    }
                })
                .catch(error => console.error('Error al obtener logs:', error));
        }
        
        function startDataRefreshLoop() {
             if (!dataRefreshIntervalId) {
                dataRefreshIntervalId = setInterval(() => {
                    updateDevices();
                    updateLogs();
                }, 3000); // Intervalo de actualización de datos (3 seg)
            }
        }
        
        function stopDataRefreshLoop() {
            if (dataRefreshIntervalId) {
                clearInterval(dataRefreshIntervalId);
                dataRefreshIntervalId = null;
            }
        }

        function startScan() {
            const network = document.getElementById('network_range').value;
            const interval = document.getElementById('scan_interval').value;
            const scanType = document.getElementById('scan_type').value;
            
            fetch('/start_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', },
                body: `network_range=${encodeURIComponent(network)}&scan_interval=${encodeURIComponent(interval)}&scan_type=${encodeURIComponent(scanType)}`
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    updateStatus(); 
                    startDataRefreshLoop(); 
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => console.error('Error al iniciar escaneo:', error));
        }

        function stopScan() {
            fetch('/stop_scan', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    updateStatus(); 
                    stopDataRefreshLoop(); 
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => console.error('Error al detener escaneo:', error));
        }

        // --- BUCLES DE ACTUALIZACIÓN PRINCIPALES ---
        
        if (scanActive) {
            startDataRefreshLoop();
        }
        
        setInterval(updateStatus, 3000); // El estado se chequea cada 3 seg
        
        // Carga inicial de datos
        updateStatus();
        updateLogs();
        if (scanActive) {
            updateDevices(); 
        }
    </script>
</body>
</html>
'''

# --- 7. Punto de Entrada ---
if __name__ == '__main__':
    # Obtiene la IP local para sugerir la URL
    _, local_ip = get_local_network()
    print(f"\n--- Aplicación Web Iniciada ---")
    
    if os.name == 'nt':
        print(f"\n*** IMPORTANTE (Windows): ***")
        print(f"1. Asegúrate de que Nmap (nmap.exe) esté instalado y en tu PATH del sistema.")
        print(f"2. Ejecuta este script como Administrador para detectar MACs.")
    else:
        print(f"\n*** IMPORTANTE (Linux/Mac): Para detectar MAC/Vendor, ejecuta este script con privilegios (ej. sudo python3 app.py) ***")

    print(f"\nAbre tu navegador y visita: http://127.0.0.1:5000")
    print(f"O desde otro dispositivo de la red: http://{local_ip}:5000")
    print("Para detener la aplicación, presiona Ctrl+C aquí.")
    print("--------------------------------\n")
    
    # debug=False es mejor para producción y evita hilos duplicados
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)

