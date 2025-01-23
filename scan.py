#!/usr/bin/env python3

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Archivos de salida
OUTPUT_FILE = "devices.log"
NETWORKS_FILE = "NETWORKS.txt"
ACTIVE_IPS_FILE = "active_ips.txt"

# Limpia los archivos de salida previos
with open(OUTPUT_FILE, "w") as f:
    pass
with open(ACTIVE_IPS_FILE, "w") as f:
    pass

print("Iniciando escaneo de redes...")


def procesar_snmp(ip, output_file):
    """
    Procesa una IP activa:
    - Obtiene el nombre del dispositivo.
    - Obtiene la descripción del sistema.
    - Guarda la información en el archivo de salida.
    """
    try:
        # Obtener nombre del dispositivo
        name_result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "NETCOM", "-r",
                "1", "-t", "3", ip, "1.3.6.1.2.1.1.5.0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        name = name_result.stdout.split(
            ": ", 1)[-1].strip() if name_result.returncode == 0 else ""

        # Obtener descripción del sistema
        description_result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "NETCOM", "-r",
                "1", "-t", "3", ip, "1.3.6.1.2.1.1.1.0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        description = description_result.stdout.split(
            ": ", 1)[-1].strip() if description_result.returncode == 0 else ""

        # Si no se pudo obtener el nombre, usar "NAME-{IP}"
        if not name:
            name = f"\"NAME-{ip}\""

        # Si no se pudo obtener la descripción, usar "NODESC"
        if not description:
            description = "\"NODESC NODESC\""

        # Guardar la información en el archivo de salida
        with open(output_file, "a") as output:
            output.write(f"{name} {ip} {description}\n")

        print(f"Procesado: {ip} -> {name} ({description})")
    except Exception as ex:
        print(f"Error al procesar la IP {ip}: {ex}")


def escaneo_nmap(network):
    """Escanea una red con nmap"""
    try:
        print(f"Escaneando dispositivos activos en {network}...")
        nmap_result = subprocess.run(
            ["nmap", "-p", "22","-T5", network, "-oG", "-"],
            stdout=subprocess.PIPE, text=True, check=True
        )
        active_ips = [
            line.split()[1]
            for line in nmap_result.stdout.splitlines()
            if "Up" in line
        ]
        return active_ips
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar nmap en la red {network}: {e}")
        return []

def proceso_paralelo(networks, max_threads=50):
    """Procesa redes en paralelo para reducir el tiempo de escaneo."""
    all_active_ips = []  # Lista para almacenar todas las IPs activas
    with ThreadPoolExecutor(max_threads) as executor:
        # Ejecutar los escaneos en paralelo
        results = executor.map(escaneo_nmap, networks)
        with open(ACTIVE_IPS_FILE, "a") as ips_file:
            for ips in results:
                all_active_ips.extend(ips)  # Agregar las IPs activas de cada red
                if ips:  # Solo escribir si hay IPs activas
                    ips_file.write("\n".join(ips) + "\n")
    return all_active_ips

# Leer las redes del archivo NETWORKS.txt
with open(NETWORKS_FILE, "r") as networks_file:
    networks = [line.strip() for line in networks_file if line.strip()]

# Escanear todas las redes en paralelo
active_ips = proceso_paralelo(networks, max_threads=50)

# Procesar las IPs activas obtenidas
print("Obteniendo información con SNMP...")
with ThreadPoolExecutor(max_workers=70) as executor:
    for ip in active_ips:
        executor.submit(procesar_snmp, ip, OUTPUT_FILE)

print(f"Escaneo de todas las redes completo. Registro de dispositivo: {OUTPUT_FILE}")
print(f"Las IPs activas se guardaron en: {ACTIVE_IPS_FILE}")


# Escaneo con SSH
#print("Ejecutando script Python para escanear y cargar datos de interfaces con SSH...")
#subprocess.run(["python3", "netcom-scann-ssh.py"])

# Subida a Netbox
#print("Ejecutando script Python para registrar y actualizar dispositivos en Netbox...")
#subprocess.run(["python3", "netcom-netbox.py", "/app/devices.json"])

# CF