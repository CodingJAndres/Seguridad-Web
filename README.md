# Análisis de Seguridad Web

## Descripción

Este script es una herramienta de análisis de seguridad web diseñada para realizar una serie de pruebas de seguridad en sitios web y servidores. Permite escanear puertos abiertos, verificar vulnerabilidades específicas, analizar dominios, y obtener información sobre certificados SSL/TLS, entre otras comprobaciones relacionadas con la seguridad.

## Características

- **Escaneo de Puertos**: Identifica los puertos abiertos en un servidor.
- **Análisis de Dominios**: Verifica vulnerabilidades CSRF, inyección SQL y XSS, y analiza formularios para detectar problemas de seguridad.
- **Certificados SSL/TLS**: Obtiene y verifica detalles del certificado SSL/TLS del sitio web.
- **Geolocalización de IP**: Obtiene información de geolocalización para una dirección IP específica.

## Requisitos

- Python 3.x
- Bibliotecas Python:
  - `requests`
  - `lxml`
  - `beautifulsoup4`
  - `colorama`

## Instalación

Para instalar las dependencias necesarias, ejecuta el siguiente comando en tu terminal:

```bash
pip install requests lxml beautifulsoup4 colorama


Uso
Ejecuta el Script

Ejecuta el script desde tu terminal o línea de comandos:

python Escaneo_web.py



 Interacción con el Menú

El script te presentará un menú con las siguientes opciones:

1.Escanear puertos: Ingresa una dirección IP para escanear los puertos abiertos y guardar los resultados en un archivo scan_ports_results.txt).
2.Analizar dominio: Ingresa una URL para analizar vulnerabilidades como CSRF, inyección SQL y XSS. Los resultados se guardan en archivos (csrf_results.txt, sql_injection_results.txt, xss_results.txt).
3.Verificar certificado SSL: Ingresa el nombre del host para verificar el certificado SSL/TLS. La información se guarda en un archivo (ssl_certificate_info.txt).
4.Geolocalizar IP: Ingresa una dirección IP para obtener información de geolocalización. Los resultados se guardan en un archivo (geolocalizacion_ip.txt).
5.Salir: Cierra el script.