"""
Cache de metadatos para archivos procesados.
Evita recalcular hashes y metadatos de archivos que no han cambiado.
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime
import logging


class MetadataCache:
    """
    Cache de metadatos de archivos para optimizar procesamiento repetido.
    
    Estructura del cache:
    {
        "file_path": {
            "size": int,
            "mtime": float,
            "hash": str,
            "last_processed": str,
            "upload_status": str,  # "success", "failed", "pending"
            "album_name": str,
            "media_key": str
        }
    }
    """
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_file = cache_dir / "metadata_cache.json"
        self.logger = logging.getLogger(__name__)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Cargar cache desde archivo JSON."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self._cache = json.load(f)
                self.logger.debug(f"Cache cargado: {len(self._cache)} entradas")
            else:
                self._cache = {}
                self.logger.debug("Cache inicializado vacío")
        except (json.JSONDecodeError, IOError) as e:
            self.logger.warning(f"Error cargando cache, iniciando vacío: {e}")
            self._cache = {}
    
    def _save_cache(self) -> None:
        """Guardar cache a archivo JSON."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self._cache, f, indent=2, ensure_ascii=False)
            self.logger.debug(f"Cache guardado: {len(self._cache)} entradas")
        except IOError as e:
            self.logger.error(f"Error guardando cache: {e}")
    
    def _get_file_stats(self, file_path: Path) -> tuple[int, float]:
        """Obtener tamaño y tiempo de modificación del archivo."""
        stat = file_path.stat()
        return stat.st_size, stat.st_mtime
    
    def is_file_cached(self, file_path: Path) -> bool:
        """
        Verificar si el archivo está en cache y no ha cambiado.
        
        Args:
            file_path: Ruta del archivo a verificar
            
        Returns:
            True si el archivo está en cache y no ha cambiado
        """
        file_str = str(file_path.absolute())
        
        if file_str not in self._cache:
            return False
        
        try:
            current_size, current_mtime = self._get_file_stats(file_path)
            cached_entry = self._cache[file_str]
            
            return (
                cached_entry.get("size") == current_size and
                cached_entry.get("mtime") == current_mtime
            )
        except (OSError, KeyError):
            return False
    
    def get_cached_hash(self, file_path: Path) -> Optional[str]:
        """
        Obtener hash cacheado si el archivo no ha cambiado.
        
        Args:
            file_path: Ruta del archivo
            
        Returns:
            Hash del archivo si está cacheado y válido, None en caso contrario
        """
        if self.is_file_cached(file_path):
            file_str = str(file_path.absolute())
            return self._cache[file_str].get("hash")
        return None
    
    def get_cached_metadata(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Obtener todos los metadatos cacheados si el archivo no ha cambiado.
        
        Args:
            file_path: Ruta del archivo
            
        Returns:
            Diccionario con metadatos si está cacheado y válido, None en caso contrario
        """
        if self.is_file_cached(file_path):
            file_str = str(file_path.absolute())
            return self._cache[file_str].copy()
        return None
    
    def cache_file_metadata(
        self, 
        file_path: Path, 
        hash_value: str, 
        album_name: str = "", 
        upload_status: str = "pending",
        media_key: str = ""
    ) -> None:
        """
        Cachear metadatos de un archivo.
        
        Args:
            file_path: Ruta del archivo
            hash_value: Hash SHA1 del archivo
            album_name: Nombre del álbum asignado
            upload_status: Estado de subida ("success", "failed", "pending")
            media_key: Clave de media de Google Photos
        """
        try:
            size, mtime = self._get_file_stats(file_path)
            file_str = str(file_path.absolute())
            
            self._cache[file_str] = {
                "size": size,
                "mtime": mtime,
                "hash": hash_value,
                "last_processed": datetime.now().isoformat(),
                "upload_status": upload_status,
                "album_name": album_name,
                "media_key": media_key
            }
            
            self.logger.debug(f"Metadatos cacheados para: {file_path.name}")
        except OSError as e:
            self.logger.error(f"Error cacheando metadatos para {file_path}: {e}")
    
    def update_upload_status(self, file_path: Path, status: str, media_key: str = "") -> None:
        """
        Actualizar estado de subida de un archivo cacheado.
        
        Args:
            file_path: Ruta del archivo
            status: Nuevo estado ("success", "failed", "pending")
            media_key: Clave de media si la subida fue exitosa
        """
        file_str = str(file_path.absolute())
        if file_str in self._cache:
            self._cache[file_str]["upload_status"] = status
            self._cache[file_str]["last_processed"] = datetime.now().isoformat()
            if media_key:
                self._cache[file_str]["media_key"] = media_key
            self.logger.debug(f"Estado actualizado para {file_path.name}: {status}")
    
    def get_upload_statistics(self) -> Dict[str, int]:
        """
        Obtener estadísticas de archivos procesados.
        
        Returns:
            Diccionario con conteos por estado de subida
        """
        stats = {"success": 0, "failed": 0, "pending": 0, "total": 0}
        
        for entry in self._cache.values():
            status = entry.get("upload_status", "pending")
            stats[status] = stats.get(status, 0) + 1
            stats["total"] += 1
        
        return stats
    
    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Limpiar entradas antiguas del cache.
        
        Args:
            days: Días de antigüedad para considerar una entrada como vieja
            
        Returns:
            Número de entradas eliminadas
        """
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        entries_to_remove = []
        
        for file_path, entry in self._cache.items():
            try:
                last_processed = datetime.fromisoformat(entry.get("last_processed", ""))
                if last_processed < cutoff_date:
                    # Verificar si el archivo aún existe
                    if not Path(file_path).exists():
                        entries_to_remove.append(file_path)
            except (ValueError, TypeError):
                # Entrada con fecha inválida, marcar para eliminación
                entries_to_remove.append(file_path)
        
        for file_path in entries_to_remove:
            del self._cache[file_path]
        
        if entries_to_remove:
            self.logger.info(f"Limpiadas {len(entries_to_remove)} entradas antiguas del cache")
        
        return len(entries_to_remove)
    
    def save(self) -> None:
        """Guardar cache a disco."""
        self._save_cache()
    
    def clear(self) -> None:
        """Limpiar todo el cache."""
        self._cache.clear()
        self._save_cache()
        self.logger.info("Cache limpiado completamente")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.save()