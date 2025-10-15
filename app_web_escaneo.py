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

def scan_network(network_range):
    """Escanea la red usando nmap para dispositivos activos."""
    nm = nmap.PortScanner()
    devices = []
    try:
        # Escaneo ping (-sn) con timeout
        nm.scan(hosts=network_range, arguments='-sn --host-timeout 60s')
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                hostname = nm[host].hostname() or "Desconocido"
                devices.append({'ip': host, 'hostname': hostname})
    except Exception as e:
        print(f"Error en el escaneo de nmap: {e}")
    return devices

# --- 3. Configuración de Flask ---

app = Flask(__name__)

# Variables globales para el estado de la aplicación
# En un entorno real, esto se manejaría con una base de datos o un sistema de almacenamiento compartido
known_devices = {}
scan_active = False
scan_thread = None
network_range = get_local_network()[0] # Inicializar con la red local
scan_interval = 10
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
    global scan_active, scan_thread, network_range, scan_interval
    network_range = request.form.get('network_range', network_range)
    try:
        scan_interval = int(request.form.get('scan_interval', scan_interval))
        if not (5 <= scan_interval <= 60):
             return jsonify({'success': False, 'message': 'Intervalo debe estar entre 5 y 60 segundos.'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Intervalo debe ser un número entero.'})

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", network_range):
        return jsonify({'success': False, 'message': 'Formato de rango de red inválido. Use CIDR (ej. 192.168.1.0/24).'})

    mask = int(network_range.split('/')[-1])
    if not (12 <= mask <= 32):
        return jsonify({'success': False, 'message': f'Máscara /{mask} no soportada. Use entre /12 y /32.'})

    if not scan_active:
        scan_active = True
        scan_thread = threading.Thread(target=scan_worker)
        scan_thread.daemon = True
        scan_thread.start()
        add_log("Escaneo iniciado.")
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
    global scan_active, network_range, scan_interval, last_scan_time
    net_size = calculate_network_size(network_range)
    return jsonify({
        'scan_active': scan_active,
        'network_range': network_range,
        'scan_interval': scan_interval,
        'last_scan_time': last_scan_time.strftime('%H:%M:%S') if last_scan_time else 'Nunca',
        'network_size': f"~{net_size} hosts"
    })

# --- 5. Funciones del Hilo de Escaneo ---

def scan_worker():
    """Bucle principal del hilo de escaneo."""
    global known_devices, scan_active, network_range, last_scan_time
    while scan_active:
        try:
            current_devices = scan_network(network_range)
            current_ips = {device['ip'] for device in current_devices}
            last_scan_time = datetime.now()

            # Actualizar estado de dispositivos conocidos
            for ip in known_devices:
                if ip in current_ips:
                    known_devices[ip].is_active = True
                    known_devices[ip].last_seen = datetime.now()
                else:
                    known_devices[ip].is_active = False

            # Agregar nuevos dispositivos
            for device in current_devices:
                if device['ip'] not in known_devices:
                    known_devices[device['ip']] = Device(device['ip'], device['hostname'])
                    add_log(f"Nuevo dispositivo detectado: {device['ip']} ({device['hostname']})")

            add_log(f"Escaneo completado. {len(current_ips)} hosts activos detectados.")

        except Exception as e:
            add_log(f"Error en el hilo de escaneo: {e}")

        time.sleep(scan_interval)
        # Verificar si se debe detener el bucle
        if not scan_active:
            break

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
    logs.append({
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'message': message
    })
    # Mantener solo los últimos 50 logs para no consumir mucha memoria
    if len(logs) > 50:
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
            --danger: #e74c3c;
            --danger-light: #fadbd8;
            --light: #ecf0f1;
            --lighter: #f8f9fa;
            --dark: #34495e;
            --darker: #2c3e50;
            --text: #2c3e50;
            --text-light: #7f8c8d;
            --border: #dcdde1;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --shadow-hover: 0 8px 15px rgba(0, 0, 0, 0.12);
            --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', sans-serif;
            background: linear-gradient(135deg, #f0f4f8 0%, #d9e2ec 100%);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            border-radius: 16px;
            box-shadow: var(--shadow);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        header {
            background: linear-gradient(to right, var(--primary), var(--primary-dark));
            color: white;
            padding: 30px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        header::before {
            content: "";
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 70%);
            transform: rotate(30deg);
        }

        header h1 {
            font-size: 2.5em;
            font-weight: 400;
            letter-spacing: 1.2px;
            margin-bottom: 8px;
            position: relative;
            z-index: 2;
        }

        header p {
            font-weight: 300;
            opacity: 0.9;
            font-size: 1.1em;
            position: relative;
            z-index: 2;
        }

        .status-bar {
            background-color: var(--darker);
            color: white;
            padding: 18px 40px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            align-items: center;
        }

        .status-item {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }

        .status-item strong {
            color: var(--secondary);
            font-size: 0.9em;
            margin-bottom: 3px;
        }

        .status-value {
            font-weight: 600;
            font-size: 1.1em;
        }

        .status-indicator {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
            transition: var(--transition);
        }

        .status-indicator.active {
            background-color: var(--success);
            box-shadow: 0 0 10px var(--success);
            animation: pulse 1.5s infinite;
        }

        .status-indicator.inactive {
            background-color: var(--danger);
        }

        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(46, 204, 113, 0); }
            100% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0); }
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px;
        }

        .card {
            background-color: white;
            border-radius: 12px;
            box-shadow: var(--shadow);
            padding: 25px;
            transition: var(--transition);
            display: flex;
            flex-direction: column;
        }

        .card:hover {
             box-shadow: var(--shadow-hover);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }

        .card-title {
            font-size: 1.5em;
            color: var(--darker);
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
            align-items: end; /* Alinea items al final del contenedor */
        }

        .form-group {
            display: flex;
            flex-direction: column;
            flex: 1;
            min-width: 200px; /* Ancho mínimo para mantener proporciones */
        }

        label {
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--dark);
            font-size: 0.95em;
        }

        input[type="text"], input[type="number"] {
            padding: 14px 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 1em;
            transition: var(--transition);
            background-color: var(--lighter);
        }

        input[type="text"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: var(--secondary);
            box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.2);
            background-color: white;
        }

        .controls {
            display: flex;
            gap: 12px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        button {
            padding: 12px 26px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        button:active {
             transform: translateY(2px);
             box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        button#startBtn {
            background-color: var(--success);
            color: white;
        }

        button#startBtn:hover:not(:disabled) {
            background-color: #27ae60;
            transform: translateY(-3px);
            box-shadow: 0 6px 10px rgba(0, 0, 0, 0.15);
        }

        button#stopBtn {
            background-color: var(--danger);
            color: white;
        }

        button#stopBtn:hover:not(:disabled) {
            background-color: #c0392b;
            transform: translateY(-3px);
            box-shadow: 0 6px 10px rgba(0, 0, 0, 0.15);
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
            box-shadow: none;
        }

        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin-top: 10px;
            flex: 1; /* Hacer que la tabla ocupe el espacio restante */
            min-height: 0; /* Para que flex funcione correctamente dentro de un contenedor con display grid */
        }

        th {
            background-color: var(--primary);
            color: white;
            font-weight: 600;
            text-align: left;
            padding: 16px 20px;
            position: sticky; /* Fijar encabezado al desplazar */
            top: 0;
        }

        td {
            padding: 14px 20px;
            border-bottom: 1px solid var(--border);
            transition: background-color 0.2s;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:nth-child(even) {
            background-color: var(--lighter);
        }

        tr:hover {
            background-color: #e3f2fd;
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
            color: var(--success);
        }

        .status-badge.inactive {
            background-color: var(--danger-light);
            color: var(--danger);
        }

        .logs-container {
            background-color: #1e1e2e;
            color: #cdd6f4;
            border-radius: 8px;
            padding: 20px;
            height: 300px; /* Altura fija para el panel de logs */
            overflow-y: auto;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            flex: 1; /* Hacer que el contenedor de logs ocupe el espacio restante */
            min-height: 0;
        }

        .log-entry {
            padding: 4px 0;
            border-left: 4px solid transparent;
            display: flex;
        }

        .log-timestamp {
            color: #6c7086;
            margin-right: 15px;
            flex-shrink: 0; /* No permitir que el timestamp se encoja */
        }

        .log-message {
            flex: 1; /* El mensaje ocupa el resto del espacio */
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

        @media (max-width: 992px) {
            .main-content {
                grid-template-columns: 1fr; /* Una columna en pantallas medianas */
            }
            .status-bar {
                grid-template-columns: 1fr 1fr; /* Dos columnas en pantallas medianas */
            }
        }

        @media (max-width: 768px) {
            .status-bar {
                grid-template-columns: 1fr; /* Una columna en móviles */
                text-align: center;
            }
            .form-row {
                flex-direction: column;
                align-items: stretch;
            }
            .form-group {
                min-width: 100%;
            }
            button {
                width: 100%;
                justify-content: center;
            }
            .card {
                padding: 20px;
            }
            header h1 {
                font-size: 2em;
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

        <div class="status-bar">
            <div class="status-item">
                <strong>Red Actual</strong>
                <span class="status-value" id="currentNetwork">-</span>
            </div>
            <div class="status-item">
                <strong>Tamaño Estimado</strong>
                <span class="status-value" id="networkSize">-</span>
            </div>
            <div class="status-item">
                <strong>Último Escaneo</strong>
                <span class="status-value" id="lastScanTime">-</span>
            </div>
            <div class="status-item">
                <strong>Estado del Escaneo</strong>
                <div style="display: flex; align-items: center;">
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
                    <div class="form-row">
                        <div class="form-group">
                            <label for="network_range">Rango de Red (CIDR)</label>
                            <input type="text" id="network_range" value="{{ network_range }}" placeholder="ej. 192.168.1.0/24">
                        </div>
                        <div class="form-group">
                            <label for="scan_interval">Intervalo (segundos)</label>
                            <input type="number" id="scan_interval" min="5" max="60" value="{{ scan_interval }}" style="width: 100px;">
                        </div>
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
                        _DEVICES Dispositivos Detectados
                        <span class="device-count" id="deviceCount">0</span>
                    </h2>
                </div>
                <table id="devicesTable">
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Hostname</th>
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
        let refreshIntervalId;

        function updateStatus() {
            fetch('/get_status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('currentNetwork').textContent = data.network_range;
                    document.getElementById('networkSize').textContent = data.network_size;
                    document.getElementById('lastScanTime').textContent = data.last_scan_time;

                    const indicator = document.getElementById('scanIndicator');
                    const statusText = document.getElementById('scanStatus');
                    const startBtn = document.getElementById('startBtn');
                    const stopBtn = document.getElementById('stopBtn');

                    if (data.scan_active) {
                        indicator.className = 'status-indicator active';
                        statusText.textContent = 'Activo';
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
            if (scanActive) { // Solo actualizar si está activo
                fetch('/get_devices')
                    .then(response => response.json())
                    .then(data => {
                        const tbody = document.getElementById('devicesTableBody');
                        tbody.innerHTML = ''; // Limpiar tabla
                        let activeCount = 0;
                        data.forEach(device => {
                            if(device.status === 'ACTIVO') activeCount++;
                            const row = tbody.insertRow();
                            row.insertCell(0).textContent = device.ip;
                            row.insertCell(1).textContent = device.hostname;

                            const statusCell = row.insertCell(2);
                            const badge = document.createElement('span');
                            badge.className = `status-badge ${device.status.toLowerCase()}`;
                            badge.textContent = device.status;
                            statusCell.appendChild(badge);

                            row.insertCell(3).textContent = device.last_seen;
                            row.insertCell(4).textContent = device.first_seen;
                        });
                        // Actualizar contador de dispositivos activos
                        document.getElementById('deviceCount').textContent = `${activeCount} / ${data.length}`;
                    })
                    .catch(error => console.error('Error al obtener dispositivos:', error));
            }
        }

        function updateLogs() {
            fetch('/get_logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('logs');
                    logsDiv.innerHTML = ''; // Limpiar logs anteriores
                    data.forEach(log => {
                        const logEntry = document.createElement('div');
                        if (log.message.includes('ERROR')) {
                            logEntry.className = 'log-entry error';
                        } else if (log.message.includes('Nuevo dispositivo')) {
                            logEntry.className = 'log-entry success';
                        } else if (log.message.includes('Escaneo completado')) {
                            logEntry.className = 'log-entry info';
                        } else {
                            logEntry.className = 'log-entry info';
                        }
                        logEntry.innerHTML = `<span class="log-timestamp">[${log.timestamp}]</span><span class="log-message">${log.message}</span>`;
                        logsDiv.appendChild(logEntry);
                    });
                    logsDiv.scrollTop = logsDiv.scrollHeight; // Auto-scroll abajo
                })
                .catch(error => console.error('Error al obtener logs:', error));
        }

        function startScan() {
            const network = document.getElementById('network_range').value;
            const interval = document.getElementById('scan_interval').value;
            fetch('/start_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', },
                body: `network_range=${encodeURIComponent(network)}&scan_interval=${encodeURIComponent(interval)}`
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    updateStatus();
                    if (!refreshIntervalId) {
                        refreshIntervalId = setInterval(() => { updateDevices(); updateLogs(); }, 2000);
                    }
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
                    if (refreshIntervalId) {
                        clearInterval(refreshIntervalId);
                        refreshIntervalId = null;
                    }
                    // Limpiar contador cuando se detiene
                    document.getElementById('deviceCount').textContent = '0';
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => console.error('Error al detener escaneo:', error));
        }

        if (scanActive) {
            refreshIntervalId = setInterval(() => { updateDevices(); updateLogs(); }, 2000);
        }
        setInterval(updateStatus, 5000);
        setInterval(updateLogs, 2000);

        updateDevices();
        updateLogs();
        updateStatus();
    </script>
</body>
</html>
'''

# --- 7. Punto de Entrada ---
if __name__ == '__main__':
    # Obtiene la IP local para sugerir la URL
    local_ip, _ = get_local_network()
    print(f"\n--- Aplicación Web Iniciada ---")
    print(f"Abre tu navegador y visita: http://127.0.0.1:5000")
    print(f"O desde otro dispositivo de la red: http://{local_ip}:5000")
    print("Para detener la aplicación, presiona Ctrl+C aquí.")
    print("--------------------------------\n")
    app.run(debug=True, host='0.0.0.0', port=5000) # host='0.0.0.0' permite acceso desde otros dispositivos en la red