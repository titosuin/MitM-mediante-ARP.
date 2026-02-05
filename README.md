Estudiante: Martin Alexander Perez Moya
Matrícula: 2024-2295
Asignatura: Seguridad en Redes
Fecha: Febrero 2026

Link del video: https://youtu.be/s6Emg7BInSg
 
 ## 1. Descripción y Topología del Escenario

El laboratorio se ha desplegado en un entorno virtualizado utilizando **GNS3**, simulando una infraestructura de red corporativa vulnerada desde el interior.

### Detalles de la Topología
* **Segmentación de Red:** Se ha configurado la **VLAN 2295** (basada en los últimos 4 dígitos de la matrícula).
* **Direccionamiento IP:** Subred `10.22.95.0/24`.
* **Infraestructura:**
    * **Gateway (Router Cisco IOU L3):** Configurado como *Router-on-a-Stick* en la interfaz `e0/1.2295` con IP `10.22.95.1`.
    * **Switch (Cisco IOU L2):** Puertos de acceso configurados en la VLAN 2295.
* **Actores:**
    * **Atacante:** Kali Linux (IP asignada por DHCP: `10.22.95.4`).
    * **Víctima:** PC1 / VPCS (IP asignada por DHCP: `10.22.95.3`).

<img width="641" height="712" alt="image" src="https://github.com/user-attachments/assets/07ad4a81-ae2d-4e63-ad94-2061a26abefb" />

Dispositivo,Interfaz,Dirección IP,Máscara de Subred,Gateway Predeterminado:

RouterGateway,e0/0.2295,10.22.95.1,255.255.255.0 (/24),N/A

Switch L2,VLAN 2295,10.22.95.2 (Gestión),255.255.255.0 (/24),10.22.95.1

Kali Linux (Atacante),eth0,10.22.95.4/255.255.255.0 (/24),10.22.95.1

PC1 (Víctima),eth0, 10.22.95.3/255.255.255.0 (/24),10.22.95.1

---

## 2. Requisitos Previos y Herramientas

Para la ejecución exitosa de estos scripts, se requiere el siguiente entorno:

* **Sistema Operativo:** Kali Linux o cualquier distribución Linux basada en Debian.
* **Lenguaje:** Python 3.x.
* **Librerías:** `Scapy` (Instalación: `sudo apt install python3-scapy`).
* **Privilegios:** Acceso **Root** (sudo) es obligatorio para la inyección de paquetes en crudo y la manipulación de interfaces de red.

---
 Man-in-the-Middle (ARP Spoofing)

### Objetivo del Script
El script `ataque_arp.py` intercepta el tráfico confidencial entre la víctima (PC1) y la puerta de enlace (Gateway). Aprovecha la naturaleza "sin estado" (stateless) del protocolo ARP para envenenar la caché ARP de ambos objetivos.

### Funcionamiento Técnico
1.  **Identificación:** El script escanea la red para obtener las direcciones MAC reales de la víctima y el Gateway.
2.  **Envenenamiento (Spoofing):** Envía paquetes ARP Reply (OpCode 2) falsificados:
    * A la Víctima le indica que la MAC del Gateway es la del Atacante.
    * Al Gateway le indica que la MAC de la Víctima es la del Atacante.
3.  **Persistencia:** Mantiene el ataque activo enviando paquetes cada 2 segundos.
4.  **Routing:** Habilita el `ip_forward` en Linux para que la víctima no pierda conectividad a Internet.

### Evidencia de Ejecución

<img width="380" height="171" alt="image" src="https://github.com/user-attachments/assets/0e2413cc-e7fc-488f-b6f8-6c163e179a7e" />


---

## 5. Medidas de Mitigación


### Contra ARP Spoofing
1.  **Dynamic ARP Inspection (DAI):** Característica de seguridad en switches Cisco que inspecciona paquetes ARP y descarta aquellos que no coinciden con la base de datos de asignación de DHCP.
    ```bash
    Switch(config)# ip arp inspection vlan 2295
    Switch(config)# interface e0/0 (Uplink)
    Switch(config-if)# ip arp inspection trust
