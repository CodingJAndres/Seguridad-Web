import os
import time
import socket
import requests
import logging
import ssl
from lxml import etree
from urllib.parse import urlparse
from lxml import html
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Tuple

init()

ASCII_ART = """
 ██████████                                                                                     █████    
░░███░░░░░█                                                                                    ░░███     
 ░███  █ ░   █████   ██████   ██████   ████████    ██████   ██████     █████ ███ █████  ██████  ░███████ 
 ░██████    ███░░   ███░░███ ░░░░░███ ░░███░░███  ███░░███ ███░░███   ░░███ ░███░░███  ███░░███ ░███░░███
 ░███░░█   ░░█████ ░███ ░░░   ███████  ░███ ░███ ░███████ ░███ ░███    ░███ ░███ ░███ ░███████  ░███ ░███
 ░███ ░   █ ░░░░███░███  ███ ███░░███  ░███ ░███ ░███░░░  ░███ ░███    ░░███████████  ░███░░░   ░███ ░███
 ██████████ ██████ ░░██████ ░░████████ ████ █████░░██████ ░░██████      ░░████░████   ░░██████  ████████ 
░░░░░░░░░░ ░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░  ░░░░░░   ░░░░░░        ░░░░ ░░░░     ░░░░░░  ░░░░░░░░  

        Autor: Julian Andres (Codespectre)
        Contacto: julianandresvallestero@proton.me
        Script de análisis de seguridad web para escaneo de puertos, vulnerabilidades,
        archivos ocultos, métodos HTTP, y certificados SSL/TLS.
"""

print(ASCII_ART)

# Función para limpiar la pantalla
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Función para mostrar la barra de carga
def show_loading_bar():
    print(Fore.GREEN + "Cargando", end="")
    for _ in range(5):
        print(".", end="", flush=True)
        time.sleep(0.5)
    print(" Hecho!" + Style.RESET_ALL)

# Función para guardar los resultados en un archivo
def save_to_file(filename, content):
    try:
        with open(filename, 'w') as file:
            file.write(content)
        print(Fore.GREEN + f"Resultados guardados en {filename}" + Style.RESET_ALL)
    except IOError as e:
        print(Fore.RED + f"Error al guardar en el archivo: {e}" + Style.RESET_ALL)

# Función para escanear puertos
def scan_ports(ip):
    open_ports = []
    ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    return port
            except socket.error as e:
                logging.error(f"Error al escanear el puerto {port}: {e}")
            return None

    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(future_to_port):
                port = future.result()
                if port is not None:
                    open_ports.append(port)

        result = f"Resultados del escaneo de puertos en {ip}:\n\n"
        result += "Puertos abiertos: " + ', '.join(map(str, open_ports)) + "\n"
        if not open_ports:
            result += "No se encontraron puertos abiertos.\n"

        save_to_file('scan_ports_results.txt', result)
    except Exception as e:
        logging.error(f"Error durante el escaneo de puertos: {e}")

# Función para verificar vulnerabilidades CSRF
def verificar_csrf(formulario):
    """
    Verifica la presencia de un token CSRF en el formulario.

    :param formulario: Objeto de formulario en formato XML/HTML.
    :return: Mensaje indicando la presencia o ausencia de una vulnerabilidad CSRF.
    """
    try:
        # Verificar que 'formulario' es un objeto lxml y tiene el método xpath
        if not isinstance(formulario, etree._Element):
            raise TypeError("El objeto proporcionado no es un elemento de lxml.")

        # Buscar el token CSRF
        csrf_tokens = formulario.xpath('//input[@name="csrf_token"]')
        
        # Verificar si se encontró al menos un token CSRF
        if not csrf_tokens:
            logging.warning("Posible vulnerabilidad CSRF en el formulario.")
            return "Posible vulnerabilidad CSRF en el formulario.\n"
        
        return "No se detectó vulnerabilidad CSRF en el formulario.\n"
    except TypeError as te:
        logging.error(f"Error de tipo al verificar CSRF: {te}")
        return f"Error de tipo al verificar CSRF: {te}\n"
    except etree.XMLSyntaxError as xml_e:
        logging.error(f"Error de sintaxis XML al verificar CSRF: {xml_e}")
        return f"Error de sintaxis XML al verificar CSRF: {xml_e}\n"
    except Exception as e:
        logging.error(f"Error inesperado al verificar CSRF: {e}")
        return f"Error inesperado al verificar CSRF: {e}\n"

# Función para verificar inyección SQL
def verificar_inyeccion_sql(url):
    """
    Verifica la presencia de posibles vulnerabilidades de inyección SQL en el contenido de una URL.

    :param url: La URL del recurso a verificar.
    :return: Mensaje indicando la presencia de vulnerabilidades de inyección SQL.
    """
    palabras_clave_sql = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']
    try:
        # Hacer la solicitud HTTP
        response = requests.get(url)
        response.raise_for_status()  # Lanza una excepción para códigos de estado HTTP 4xx/5xx

        # Buscar palabras clave en el contenido de la respuesta
        issues = []
        content = response.text.upper()  # Convertir el contenido a mayúsculas para una búsqueda insensible a mayúsculas/minúsculas
        for palabra_clave in palabras_clave_sql:
            if palabra_clave in content:
                issues.append(f"Posible vulnerabilidad de inyección SQL detectada: {palabra_clave}")

        if not issues:
            return "No se detectaron vulnerabilidades de inyección SQL.\n"

        return "\n".join(issues) + "\n"
    
    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud HTTP: {e}")
        return f"Error al realizar la solicitud HTTP: {e}\n"
    except Exception as e:
        logging.error(f"Error inesperado al verificar inyección SQL: {e}")
        return f"Error inesperado al verificar inyección SQL: {e}\n"

# Función para verificar XSS
def verificar_xss(url):
    """
    Verifica la presencia de posibles vulnerabilidades de Cross-Site Scripting (XSS) en una URL.

    :param url: La URL del recurso a verificar.
    :return: Mensaje indicando la presencia o ausencia de vulnerabilidades XSS.
    """
    try:
        # Hacer la solicitud HTTP
        response = requests.get(url)
        response.raise_for_status()  # Lanza una excepción para códigos de estado HTTP 4xx/5xx

        # Parsear el contenido HTML
        root = html.fromstring(response.content)

        # Buscar etiquetas <script> y atributos peligrosos
        scripts = root.xpath('//script')
        inline_event_handlers = root.xpath('//@*[contains(., "javascript:") or contains(., "data:")]')

        issues = []
        if scripts:
            issues.append("Posible vulnerabilidad de Cross-Site Scripting (XSS) detectada: etiquetas <script> encontradas.")
        if inline_event_handlers:
            issues.append("Posible vulnerabilidad de Cross-Site Scripting (XSS) detectada: atributos con potencial de inyección de JavaScript encontrados.")

        if not issues:
            return "No se detectaron vulnerabilidades de XSS.\n"

        return "\n".join(issues) + "\n"
    
    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud HTTP: {e}")
        return f"Error al realizar la solicitud HTTP: {e}\n"
    except Exception as e:
        logging.error(f"Error inesperado al verificar XSS: {e}")
        return f"Error inesperado al verificar XSS: {e}\n"

# Función para obtener HTML de una URL
def get_html(url):
    """
    Obtiene el HTML de una URL.

    :param url: La URL del recurso a obtener.
    :return: El contenido HTML de la URL.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logging.error(f"Error al obtener el HTML: {e}")
        return None

# Función para analizar un dominio
def analyze_domains(url):
    """
    Realiza un análisis de seguridad de un dominio específico.

    :param url: La URL del dominio a analizar.
    """
    logging.info(f"Analizando dominio: {url}")

    # Obtener HTML
    html_content = get_html(url)
    if html_content is None:
        return

    # Analizar vulnerabilidades CSRF
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        csrf_results = ""
        for form in forms:
            form_html = str(form)
            formulario = etree.HTML(form_html)
            csrf_results += verificar_csrf(formulario)
        save_to_file('csrf_results.txt', csrf_results)
    except Exception as e:
        logging.error(f"Error al analizar formularios para CSRF: {e}")

    # Analizar inyección SQL
    sql_injection_results = verificar_inyeccion_sql(url)
    save_to_file('sql_injection_results.txt', sql_injection_results)

    # Analizar XSS
    xss_results = verificar_xss(url)
    save_to_file('xss_results.txt', xss_results)

# Función para obtener detalles de certificados SSL
def get_ssl_certificate_info(hostname):
    """
    Obtiene la información del certificado SSL/TLS de un host.

    :param hostname: Nombre del host para obtener el certificado.
    :return: Información del certificado SSL/TLS.
    """
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return cert
    except Exception as e:
        logging.error(f"Error al obtener la información del certificado SSL: {e}")
        return None

# Función para verificar la validez del certificado SSL
def check_ssl_certificate(hostname: str) -> Tuple[str, str, str]:
    port = 443
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

    # Parse certificate validity dates
    valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    now = datetime.now()

    # Check if the certificate is valid
    if now < valid_from or now > valid_until:
        return "El certificado SSL no es válido."
    
    # Extract issuer and subject information
    issuer = dict(x[0] for x in cert['issuer'])
    subject = dict(x[0] for x in cert['subject'])
    
    return (f"Certificado SSL válido.\n"
            f"Válido desde: {valid_from}\n"
            f"Válido hasta: {valid_until}\n"
            f"Emisor: {issuer}\n"
            f"Sujeto: {subject}")

# Función para geolocalizar una IP
def geolocalizar_ip(ip):
 
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'fail':
            return f"No se pudo obtener la geolocalización para la IP: {data['message']}\n"
        return (
            f"Geolocalización para {ip}:\n"
            f"País: {data['country']}\n"
            f"Región: {data['regionName']}\n"
            f"Ciudad: {data['city']}\n"
            f"Código Postal: {data['zip']}\n"
            f"Latitud: {data['lat']}\n"
            f"Longitud: {data['lon']}\n"
            f"ISP: {data['isp']}\n"
        )
    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud de geolocalización: {e}")
        return f"Error al realizar la solicitud de geolocalización: {e}\n"
    except Exception as e:
        logging.error(f"Error inesperado al obtener la geolocalización: {e}")
        return f"Error inesperado al obtener la geolocalización: {e}\n"

# Función principal del menú
def main_menu():
    while True:
        clear_screen()
        print(ASCII_ART)
        print(Fore.YELLOW + "Menú Principal" + Style.RESET_ALL)
        print("1. Escanear puertos")
        print("2. Analizar dominio")
        print("3. Verificar certificado SSL")
        print("4. Geolocalizar IP")
        print("5. Salir")

        choice = input(Fore.CYAN + "Seleccione una opción: " + Style.RESET_ALL)
        if choice == '1':
            ip = input("Ingrese la dirección IP para escanear: ")
            scan_ports(ip)
        elif choice == '2':
            url = input("Ingrese la URL del dominio a analizar: ")
            analyze_domains(url)
        elif choice == '3':
            hostname = input("Ingrese el nombre del host para verificar el certificado SSL: ")
            cert_info = check_ssl_certificate(hostname)
            print(cert_info)
            save_to_file('ssl_certificate_info.txt', cert_info)
        elif choice == '4':
            ip = input("Ingrese la dirección IP para geolocalizar: ")
            geo_info = geolocalizar_ip(ip)
            print(geo_info)
            save_to_file('geolocalizacion_ip.txt', geo_info)
        elif choice == '5':
            print(Fore.GREEN + "Saliendo..." + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Opción no válida. Intente nuevamente." + Style.RESET_ALL)
        input(Fore.YELLOW + "Presione Enter para continuar..." + Style.RESET_ALL)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main_menu()
