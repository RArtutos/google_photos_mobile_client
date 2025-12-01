
# Script para compilar el binario para Ubuntu (Linux)

Para compilar un binario compatible con Ubuntu, lo ideal es hacerlo **desde un entorno Linux**. Dado que estás en Windows, tienes dos opciones principales:

## Opción A: Usar Docker (Recomendado)
Esta es la forma más limpia y asegura que el binario sea compatible con Linux.

1.  Asegúrate de tener Docker instalado.
2.  Crea un archivo llamado `Dockerfile.build` con el siguiente contenido:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema necesarias para compilar
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copiar el código fuente
COPY . .

# Instalar dependencias de Python y PyInstaller
RUN pip install --no-cache-dir -e .
RUN pip install --no-cache-dir pyinstaller

# Comando para compilar
CMD ["pyinstaller", "--onefile", "--name", "gpmc_linux", "gpmc/cli.py"]
```

3.  Ejecuta los siguientes comandos en tu terminal (PowerShell):

```powershell
# Construir la imagen
docker build -t gpmc-builder -f Dockerfile.build .

# Ejecutar el contenedor y compilar (el binario aparecerá en la carpeta 'dist' local)
docker run --rm -v ${PWD}:/app gpmc-builder
```

## Opción B: Usar WSL (Windows Subsystem for Linux)
Si tienes WSL instalado (Ubuntu en Windows):

1.  Abre tu terminal de WSL (ej. `wsl` en PowerShell).
2.  Navega a la carpeta del proyecto (probablemente en `/mnt/c/Users/...`).
3.  Instala las dependencias y PyInstaller:
    ```bash
    sudo apt-get update && sudo apt-get install python3-pip python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -e .
    pip install pyinstaller
    ```
4.  Compila:
    ```bash
    pyinstaller --onefile --name gpmc_linux gpmc/cli.py
    ```

## Opción C: Compilación Cruzada (No recomendada)
Compilar desde Windows para Linux (cross-compilation) con PyInstaller es complejo y propenso a errores, por lo que **no se recomienda**. Es mejor usar Docker o una máquina virtual Linux.

---

### Verificación
Una vez compilado (usando Opción A o B), encontrarás el archivo ejecutable en la carpeta `dist/`.
- Nombre: `gpmc_linux`
- Para usarlo en Ubuntu:
  1. Copia el archivo a tu servidor Ubuntu.
  2. Dale permisos de ejecución: `chmod +x gpmc_linux`
  3. Ejecuta: `./gpmc_linux --help`
