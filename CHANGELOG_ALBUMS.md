# Cambios en el Sistema de Nomenclatura de Álbumes y Reintentos

Este documento resume los cambios implementados, nuevas funciones añadidas y mejoras sugeridas para el flujo de subida y asignación de álbumes.

## Resumen de Cambios

- Implementado agrupamiento de álbumes basado en rutas con soporte para `AUTO` y `AUTO=/base/path`.
- Persistencia de mapeos carpeta→álbum en la base de datos local (`~/.gpmc/<email>/storage.db`).
- Reintentos robustos para subida de archivos con espera aleatoria y reporte de fallos.
- Documentación y tests actualizados para reflejar el comportamiento.

## Nuevas Funciones y Refactor

- `gpmc/utils.py`
  - `sanitize_album_name(name: str) -> str`
    - Normaliza nombres: barras, colapsa duplicados, trim y fallback a `Uploads`.
  - `compute_album_groups(results: Mapping[str, str], album_name: str) -> dict[str, list[str]]`
    - Agrupa claves de media por nombre de álbum.
    - Modos:
      - Nombre fijo: todo va al mismo álbum.
      - `AUTO=/base/path`: usa la base literal, sin requerir existencia en disco; si el archivo está directamente en la base, el álbum es el nombre hoja de la base; si está en subcarpetas, es el path relativo (sin prefijo de la hoja).
      - `AUTO`: infiere base común entre archivos; si el archivo está directamente en la base, el álbum es el nombre hoja; si está en subcarpetas, usa el path relativo.

- `gpmc/db.py`
  - Tabla `album_mappings(folder_path TEXT PRIMARY KEY, album_name TEXT)`.
  - Métodos:
    - `get_album_mapping(folder_path) -> str | None`
    - `set_album_mapping(folder_path, album_name) -> None`
    - `get_all_album_mappings() -> dict[str, str]`

- `gpmc/client.py`
  - `_handle_album_creation(results, album_name, show_progress)` refactorizado:
    - Usa `compute_album_groups` para calcular los grupos.
    - Persiste mapeos carpeta→álbum mediante `Storage`.
    - Crea álbumes en orden jerárquico (padres antes que hijos).
  - `_upload_file_with_retry(...)` añadido:
    - Hasta 10 reintentos.
    - Espera aleatoria 1–10s entre intentos.
    - Registra el detalle de cada intento fallido.
    - Lanza `RuntimeError` tras agotar reintentos para que el concurrente cuente y reporte errores.

- `tests/album_grouping_test.py`
  - Pruebas unitarias offline que verifican:
    - Nombre fijo agrupa todo.
    - `AUTO` agrupa por base común y subcarpetas.
    - `AUTO=/base` usa base explícita.
    - Archivos en la misma carpeta van al mismo álbum.

- `readme.md`
  - Actualizado `--album` para documentar `AUTO=/base/path` y el comportamiento de `AUTO`.
  - Se añade sección de Nomenclatura de Álbumes, Mecanismo de Reintentos y Tests.

## Alineación con la Especificación Solicitada

Para la base `/media/fotos/`:
- Si la foto está directamente en `/media/fotos/`, el nombre del álbum será `fotos`.
- Si la foto está en una subcarpeta, por ejemplo `/media/fotos/fotosplaya/viaje1/foto1.jpg`, el nombre del álbum será `fotosplaya/viaje1`.
- Se preserva el orden exacto de las carpetas.
- Se ignora el nombre del archivo final.
- Funciona con cualquier extensión válida.

Esto se logra invocando `compute_album_groups(results, "AUTO=/media/fotos/")` durante la subida.

## Sugerencias de Mejora de Flujo

- Cacheo de base explícita: Si el usuario suele usar una base fija (como `/media/fotos/`), exponer un flag/config global (por ejemplo `GPMC_BASE_ALBUM_PATH`) para no tener que pasar `AUTO=/...` cada vez.
- Previsualización de agrupación: Añadir un modo "dry-run" que muestre las agrupaciones y los álbumes a crear antes de ejecutar las llamadas a la API.
- Reintentos con jitter exponencial: Evolucionar de espera uniforme a backoff exponencial con jitter para mitigar thundering herd en uploads concurrentes.
- Validación opcional de nombre de álbum: Aplicar reglas de longitud y caracteres permitidos, con truncamiento elegante si supera límites.
- Telemetría de errores: Contabilizar en el resumen de subida el número de fallos y los archivos implicados, con exportación opcional a un log estructurado (JSON).

## Cómo Usarlo

- CLI: `gpmc "/media/fotos" --album "AUTO=/media/fotos/" --progress --threads 4`
- Librería:
```python
from gpmc import Client
client = Client(auth_data="...")
result = client.upload(target="/media/fotos", album_name="AUTO=/media/fotos/", show_progress=True, threads=4)
```

## Notas

- Las pruebas añadidas no requieren credenciales ni red.
- La persistencia de mapeos permite mantener consistencia si se suben más archivos posteriormente.
- El mecanismo de reintentos trabaja junto al retry HTTP ya existente a nivel de sesión.