# Análisis de Seguridad Web

## Descripción

Este script es una herramienta de análisis de seguridad web diseñada para realizar una serie de pruebas de seguridad en sitios web y servidores. Permite escanear vulnerabilidades específicas, analizar dominios, y obtener información relevante sobre la seguridad de las aplicaciones web.

## Características

- **Análisis de Vulnerabilidades**: Verifica vulnerabilidades comunes como inyección SQL, XSS, CSRF, encabezados de seguridad, cookies inseguras, archivos expuestos, errores de depuración, y LFI/RFI.
- **Resultados Detallados**: Los resultados del análisis se guardan en un archivo JSON (`resultados_analisis.json`) que incluye los hallazgos de cada prueba realizada.
- **Interfaz de Usuario Mejorada**: Proporciona una barra de carga visual durante el análisis de cada vulnerabilidad, mejorando la experiencia del usuario.
- **Colores en la Salida**: Utiliza colores en la salida de consola para mejorar la legibilidad y destacar los resultados.

## Requisitos

- Python 3.x
- Bibliotecas Python:
  - `requests`
  - `beautifulsoup4`
  - `lxml`

## Instalación

Para instalar las dependencias necesarias, ejecuta el siguiente comando en tu terminal:

```bash
pip install requests beautifulsoup4 lxml
```

## Uso

### Ejecuta el Script

Ejecuta el script desde tu terminal o línea de comandos:

```bash
python Escaneo_web.py
```

### Interacción con el Script

El script solicitará una URL para analizar y realizará un análisis de seguridad, mostrando los resultados en la consola y guardándolos en un archivo JSON.

## Ejemplo de Salida

Al ejecutar el script, la salida será similar a:

```
[+] Ingrese la URL a analizar: https://www.comeek.co/
2024-10-01 15:49:00,450 - INFO - [-] Analizando la página: https://www.comeek.co/
Analizando: Inyección SQL
Cargando: [##################################################] 100% completado
Analizando: XSS
Cargando: [##################################################] 100% completado
...
2024-10-01 15:49:35,104 - INFO - [-] Análisis completado. Resultados guardados en 'resultados_analisis.json'.
```

## Notas Adicionales

Asegúrate de tener permisos adecuados para realizar análisis de seguridad en los sitios web y servidores que desees investigar.
