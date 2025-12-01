"""
Sistema de checkpoint para manejar subidas interrumpidas y reanudación.
"""

import json
from .enhanced_logging import checkpoint_logger
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from enum import Enum


class FileStatus(Enum):
    """Estados posibles de un archivo en el checkpoint."""
    PENDING = "pending"
    UPLOADING = "uploading"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class FileCheckpoint:
    """Información de checkpoint para un archivo individual."""
    file_path: str
    file_size: int
    file_hash: str
    album_name: Optional[str]
    status: FileStatus
    media_key: Optional[str] = None
    error_message: Optional[str] = None
    upload_attempts: int = 0
    last_updated: str = ""
    
    def __post_init__(self):
        if not self.last_updated:
            self.last_updated = datetime.now(timezone.utc).isoformat()


@dataclass
class UploadCheckpoint:
    """Checkpoint completo de una sesión de subida."""
    session_id: str
    target_path: str
    album_name: Optional[str]
    created_at: str
    last_updated: str
    total_files: int
    completed_files: int
    failed_files: int
    upload_parameters: Dict[str, Any]
    files: Dict[str, FileCheckpoint]
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.last_updated:
            self.last_updated = self.created_at


class CheckpointManager:
    """Gestor de checkpoints para subidas interrumpidas."""
    
    def __init__(self, checkpoint_dir: Path = None):
        """
        Inicializar el gestor de checkpoints.
        
        Args:
            checkpoint_dir: Directorio para almacenar checkpoints (por defecto: ~/.gpmc/checkpoints)
        """
        if checkpoint_dir is None:
            checkpoint_dir = Path.home() / ".gpmc" / "checkpoints"
        
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.current_checkpoint: UploadCheckpoint | None = None
        
        import logging
        self.logger = logging.getLogger(__name__)
    
    def _generate_session_id(self, target_path: str, album_name: Optional[str], 
                           upload_params: Dict[str, Any]) -> str:
        """Generar ID único para la sesión basado en parámetros."""
        # Crear hash basado en parámetros clave
        content = f"{target_path}|{album_name or ''}|{json.dumps(upload_params, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _get_checkpoint_file(self, session_id: str) -> Path:
        """Obtener ruta del archivo de checkpoint para una sesión."""
        return self.checkpoint_dir / f"checkpoint_{session_id}.json"
    
    def create_checkpoint(self, target_path: str, album_name: Optional[str],
                         upload_params: Dict[str, Any], 
                         file_paths: List[Path]) -> str:
        """
        Crear un nuevo checkpoint para una sesión de subida.
        
        Args:
            target_path: Ruta objetivo de la subida
            album_name: Nombre del álbum (si aplica)
            upload_params: Parámetros de la subida
            file_paths: Lista de archivos a subir
            
        Returns:
            ID de la sesión creada
        """
        session_id = self._generate_session_id(target_path, album_name, upload_params)
        
        # Crear información de archivos
        files = {}
        for file_path in file_paths:
            try:
                file_size = file_path.stat().st_size
                # Crear hash simple del path para identificación
                file_hash = hashlib.md5(str(file_path.absolute()).encode()).hexdigest()[:8]
                
                files[str(file_path.absolute())] = FileCheckpoint(
                    file_path=str(file_path.absolute()),
                    file_size=file_size,
                    file_hash=file_hash,
                    album_name=album_name,
                    status=FileStatus.PENDING
                )
            except Exception as e:
                self.logger.warning(f"No se pudo procesar archivo {file_path}: {e}")
                continue
        
        # Crear checkpoint
        checkpoint = UploadCheckpoint(
            session_id=session_id,
            target_path=target_path,
            album_name=album_name,
            created_at=datetime.now(timezone.utc).isoformat(),
            last_updated=datetime.now(timezone.utc).isoformat(),
            total_files=len(files),
            completed_files=0,
            failed_files=0,
            upload_parameters=upload_params,
            files=files
        )
        
        self.active_checkpoint = checkpoint
        self.checkpoint_file = self._get_checkpoint_file(session_id)
        
        # Guardar checkpoint inicial
        self._save_checkpoint()
        
        checkpoint_logger.log_checkpoint_created(
            session_id, 
            target_path, 
            len(files), 
            sum(f.file_size for f in files.values())
        )
        return session_id
    
    def load_checkpoint(self, session_id: str) -> Optional[UploadCheckpoint]:
        """
        Cargar un checkpoint existente.
        
        Args:
            session_id: ID de la sesión a cargar
            
        Returns:
            Checkpoint cargado o None si no existe
        """
        checkpoint_file = self._get_checkpoint_file(session_id)
        
        if not checkpoint_file.exists():
            return None
        
        try:
            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convertir archivos de dict a FileCheckpoint
            files = {}
            for file_path, file_data in data['files'].items():
                file_data['status'] = FileStatus(file_data['status'])
                files[file_path] = FileCheckpoint(**file_data)
            
            data['files'] = files
            checkpoint = UploadCheckpoint(**data)
            
            self.active_checkpoint = checkpoint
            self.checkpoint_file = checkpoint_file
            
            self.logger.info(f"Checkpoint cargado: {session_id}")
            return checkpoint
            
        except Exception as e:
            self.logger.error(f"Error cargando checkpoint {session_id}: {e}")
            return None
    
    def find_existing_checkpoints(self, target_path: str, 
                                album_name: Optional[str]) -> List[str]:
        """
        Buscar checkpoints existentes para una ruta y álbum específicos.
        
        Args:
            target_path: Ruta objetivo
            album_name: Nombre del álbum
            
        Returns:
            Lista de IDs de sesiones encontradas
        """
        existing_sessions = []
        
        for checkpoint_file in self.checkpoint_dir.glob("checkpoint_*.json"):
            try:
                with open(checkpoint_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if (data.get('target_path') == target_path and 
                    data.get('album_name') == album_name):
                    existing_sessions.append(data['session_id'])
                    
            except Exception as e:
                self.logger.warning(f"Error leyendo checkpoint {checkpoint_file}: {e}")
                continue
        
        return existing_sessions
    
    def update_file_status(self, file_path: Path, status: FileStatus,
                          media_key: Optional[str] = None,
                          error_message: Optional[str] = None):
        """
        Actualizar el estado de un archivo en el checkpoint activo.
        
        Args:
            file_path: Ruta del archivo
            status: Nuevo estado
            media_key: Clave del media (si se completó exitosamente)
            error_message: Mensaje de error (si falló)
        """
        if not self.active_checkpoint:
            return
        
        file_key = str(file_path.absolute())
        if file_key not in self.active_checkpoint.files:
            return
        
        file_checkpoint = self.active_checkpoint.files[file_key]
        old_status = file_checkpoint.status
        
        # Actualizar estado del archivo
        file_checkpoint.status = status
        file_checkpoint.last_updated = datetime.now(timezone.utc).isoformat()
        
        if media_key:
            file_checkpoint.media_key = media_key
        
        if error_message:
            file_checkpoint.error_message = error_message
            file_checkpoint.upload_attempts += 1
        
        # Actualizar contadores del checkpoint
        if old_status != FileStatus.COMPLETED and status == FileStatus.COMPLETED:
            self.active_checkpoint.completed_files += 1
        elif old_status != FileStatus.FAILED and status == FileStatus.FAILED:
            self.active_checkpoint.failed_files += 1
        elif old_status == FileStatus.COMPLETED and status != FileStatus.COMPLETED:
            self.active_checkpoint.completed_files -= 1
        elif old_status == FileStatus.FAILED and status != FileStatus.FAILED:
            self.active_checkpoint.failed_files -= 1
        
        self.active_checkpoint.last_updated = datetime.now(timezone.utc).isoformat()
        
        # Guardar cambios
        self._save_checkpoint()
        
        self.logger.debug(f"Archivo {file_path.name}: {old_status.value} -> {status.value}")
        
    def update_file_progress(self, file_path: Path, status: str, 
                           media_key: Optional[str] = None,
                           error: Optional[str] = None):
        """
        Alias de compatibilidad para update_file_status con conversión de tipos.
        
        Args:
            file_path: Ruta del archivo
            status: Estado como string ('completed', 'failed', etc.)
            media_key: Clave de media opcional
            error: Mensaje de error opcional
        """
        try:
            enum_status = FileStatus(status)
            self.update_file_status(file_path, enum_status, media_key, error)
        except ValueError:
            self.logger.warning(f"Estado inválido recibido: {status}")
    
    def get_pending_files(self) -> List[Path]:
        """
        Obtener lista de archivos pendientes de subir.
        
        Returns:
            Lista de rutas de archivos pendientes
        """
        if not self.active_checkpoint:
            return []
        
        pending_files = []
        for file_path, file_checkpoint in self.active_checkpoint.files.items():
            if file_checkpoint.status in [FileStatus.PENDING, FileStatus.FAILED]:
                # Verificar que el archivo aún existe
                path_obj = Path(file_path)
                if path_obj.exists():
                    pending_files.append(path_obj)
                else:
                    self.logger.warning(f"Archivo no encontrado: {file_path}")
        
        return pending_files
    
    def get_completed_files(self) -> List[Path]:
        """
        Obtener lista de archivos ya completados.
        
        Returns:
            Lista de rutas de archivos completados
        """
        if not self.active_checkpoint:
            return []
        
        completed_files = []
        for file_path, file_checkpoint in self.active_checkpoint.files.items():
            if file_checkpoint.status == FileStatus.COMPLETED:
                completed_files.append(Path(file_path))
        
        return completed_files
    
    def get_progress_summary(self) -> Dict[str, Any]:
        """
        Obtener resumen del progreso actual.
        
        Returns:
            Diccionario con estadísticas de progreso
        """
        if not self.active_checkpoint:
            return {}
        
        return {
            'session_id': self.active_checkpoint.session_id,
            'total_files': self.active_checkpoint.total_files,
            'completed_files': self.active_checkpoint.completed_files,
            'failed_files': self.active_checkpoint.failed_files,
            'pending_files': self.active_checkpoint.total_files - 
                           self.active_checkpoint.completed_files - 
                           self.active_checkpoint.failed_files,
            'progress_percentage': (self.active_checkpoint.completed_files / 
                                  max(1, self.active_checkpoint.total_files)) * 100,
            'created_at': self.active_checkpoint.created_at,
            'last_updated': self.active_checkpoint.last_updated
        }
    
    def is_upload_complete(self) -> bool:
        """
        Verificar si la subida está completa.
        
        Returns:
            True si todos los archivos están completados o fallidos
        """
        if not self.active_checkpoint:
            return True
        
        total_processed = (self.active_checkpoint.completed_files + 
                          self.active_checkpoint.failed_files)
        return total_processed >= self.active_checkpoint.total_files
    
    def cleanup_checkpoint(self, session_id: Optional[str] = None):
        """
        Limpiar checkpoint completado.
        
        Args:
            session_id: ID específico a limpiar. Si es None, usa el activo.
        """
        if session_id is None and self.active_checkpoint:
            session_id = self.active_checkpoint.session_id
        
        if session_id:
            checkpoint_file = self._get_checkpoint_file(session_id)
            if checkpoint_file.exists():
                checkpoint_file.unlink()
                self.logger.info(f"Checkpoint {session_id} eliminado")
        
        if self.active_checkpoint and self.active_checkpoint.session_id == session_id:
            self.active_checkpoint = None
            self.checkpoint_file = None
    
    def _save_checkpoint(self):
        """Guardar el checkpoint activo en disco."""
        if not self.active_checkpoint or not self.checkpoint_file:
            return
        
        try:
            # Convertir a diccionario serializable
            data = asdict(self.active_checkpoint)
            
            # Convertir enums a strings
            for file_path, file_data in data['files'].items():
                file_data['status'] = file_data['status'].value
            
            # Guardar con backup temporal
            temp_file = self.checkpoint_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Reemplazar archivo original
            temp_file.replace(self.checkpoint_file)
            
        except Exception as e:
            self.logger.error(f"Error guardando checkpoint: {e}")
    
    def list_all_checkpoints(self) -> List[Dict[str, Any]]:
        """
        Listar todos los checkpoints disponibles.
        
        Returns:
            Lista de información de checkpoints
        """
        checkpoints = []
        
        for checkpoint_file in self.checkpoint_dir.glob("checkpoint_*.json"):
            try:
                with open(checkpoint_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                checkpoints.append({
                    'session_id': data['session_id'],
                    'target_path': data['target_path'],
                    'album_name': data.get('album_name'),
                    'total_files': data['total_files'],
                    'completed_files': data['completed_files'],
                    'failed_files': data['failed_files'],
                    'created_at': data['created_at'],
                    'last_updated': data['last_updated']
                })
                
            except Exception as e:
                self.logger.warning(f"Error leyendo checkpoint {checkpoint_file}: {e}")
                continue
        
        # Ordenar por fecha de actualización (más reciente primero)
        checkpoints.sort(key=lambda x: x['last_updated'], reverse=True)
        return checkpoints