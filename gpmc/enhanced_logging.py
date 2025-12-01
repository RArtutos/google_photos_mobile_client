"""
Sistema de logging mejorado para el sistema de checkpoints y reanudación.
"""

import logging
import logging.handlers
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import sys


class CheckpointLogger:
    """Logger especializado para el sistema de checkpoints."""
    
    def __init__(self, log_dir: Path = None, log_level: str = "INFO"):
        """
        Inicializar el logger de checkpoints.
        
        Args:
            log_dir: Directorio para los logs (por defecto: ~/.gpmc/logs)
            log_level: Nivel de logging
        """
        if log_dir is None:
            log_dir = Path.home() / ".gpmc" / "logs"
        
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurar logger principal
        self.logger = logging.getLogger("gpmc.checkpoint")
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Evitar duplicar handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self) -> None:
        """Configurar handlers de logging."""
        # Handler para archivo de log general
        general_log = self.log_dir / "gpmc_checkpoint.log"
        file_handler = logging.handlers.RotatingFileHandler(
            general_log,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        
        # Handler para archivo de log de operaciones críticas
        critical_log = self.log_dir / "gpmc_critical.log"
        critical_handler = logging.handlers.RotatingFileHandler(
            critical_log,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        critical_handler.setLevel(logging.WARNING)
        
        # Handler para consola
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Aplicar formatters
        file_handler.setFormatter(detailed_formatter)
        critical_handler.setFormatter(detailed_formatter)
        console_handler.setFormatter(console_formatter)
        
        # Agregar handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(critical_handler)
        self.logger.addHandler(console_handler)
    
    def log_checkpoint_created(self, session_id: str, target_path: str, 
                              file_count: int, total_size: int) -> None:
        """
        Registrar creación de checkpoint.
        
        Args:
            session_id: ID de la sesión
            target_path: Ruta objetivo
            file_count: Número de archivos
            total_size: Tamaño total en bytes
        """
        self.logger.info(
            f"📝 CHECKPOINT CREADO | Session: {session_id} | "
            f"Path: {target_path} | Files: {file_count} | "
            f"Size: {self._format_size(total_size)}"
        )
        
        # Log detallado en JSON
        self._log_structured_data("checkpoint_created", {
            "session_id": session_id,
            "target_path": target_path,
            "file_count": file_count,
            "total_size": total_size,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_checkpoint_loaded(self, session_id: str, pending_files: int, 
                             completed_files: int, failed_files: int) -> None:
        """
        Registrar carga de checkpoint.
        
        Args:
            session_id: ID de la sesión
            pending_files: Archivos pendientes
            completed_files: Archivos completados
            failed_files: Archivos fallidos
        """
        self.logger.info(
            f"📂 CHECKPOINT CARGADO | Session: {session_id} | "
            f"Pending: {pending_files} | Completed: {completed_files} | "
            f"Failed: {failed_files}"
        )
        
        self._log_structured_data("checkpoint_loaded", {
            "session_id": session_id,
            "pending_files": pending_files,
            "completed_files": completed_files,
            "failed_files": failed_files,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_file_progress(self, session_id: str, file_path: str, 
                         status: str, progress: float = 0.0, 
                         error: str = None, media_key: str = None) -> None:
        """
        Registrar progreso de archivo individual.
        
        Args:
            session_id: ID de la sesión
            file_path: Ruta del archivo
            status: Estado del archivo
            progress: Progreso (0.0-1.0)
            error: Mensaje de error si aplica
            media_key: Clave de media si se completó
        """
        file_name = Path(file_path).name
        
        if status == "completed":
            self.logger.info(f"✅ ARCHIVO COMPLETADO | {file_name} | Key: {media_key}")
        elif status == "failed":
            self.logger.warning(f"❌ ARCHIVO FALLIDO | {file_name} | Error: {error}")
        elif status == "uploading":
            self.logger.debug(f"⬆️  SUBIENDO | {file_name} | Progress: {progress:.1%}")
        
        self._log_structured_data("file_progress", {
            "session_id": session_id,
            "file_path": file_path,
            "file_name": file_name,
            "status": status,
            "progress": progress,
            "error": error,
            "media_key": media_key,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_interruption(self, session_id: str, signal_name: str, 
                        files_completed: int, files_pending: int) -> None:
        """
        Registrar interrupción del proceso.
        
        Args:
            session_id: ID de la sesión
            signal_name: Nombre de la señal recibida
            files_completed: Archivos completados
            files_pending: Archivos pendientes
        """
        self.logger.warning(
            f"🛑 INTERRUPCIÓN DETECTADA | Session: {session_id} | "
            f"Signal: {signal_name} | Completed: {files_completed} | "
            f"Pending: {files_pending}"
        )
        
        self._log_structured_data("interruption", {
            "session_id": session_id,
            "signal_name": signal_name,
            "files_completed": files_completed,
            "files_pending": files_pending,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_resume_attempt(self, session_id: str, action: str, 
                          user_choice: str = None) -> None:
        """
        Registrar intento de reanudación.
        
        Args:
            session_id: ID de la sesión
            action: Acción realizada
            user_choice: Elección del usuario
        """
        self.logger.info(
            f"🔄 REANUDACIÓN | Session: {session_id} | "
            f"Action: {action} | Choice: {user_choice}"
        )
        
        self._log_structured_data("resume_attempt", {
            "session_id": session_id,
            "action": action,
            "user_choice": user_choice,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_checkpoint_cleanup(self, session_id: str, reason: str) -> None:
        """
        Registrar limpieza de checkpoint.
        
        Args:
            session_id: ID de la sesión
            reason: Razón de la limpieza
        """
        self.logger.info(f"🧹 CHECKPOINT LIMPIADO | Session: {session_id} | Reason: {reason}")
        
        self._log_structured_data("checkpoint_cleanup", {
            "session_id": session_id,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_error(self, session_id: str, operation: str, error: str, 
                 context: Dict[str, Any] = None) -> None:
        """
        Registrar error crítico.
        
        Args:
            session_id: ID de la sesión
            operation: Operación que falló
            error: Mensaje de error
            context: Contexto adicional
        """
        self.logger.error(
            f"💥 ERROR CRÍTICO | Session: {session_id} | "
            f"Operation: {operation} | Error: {error}"
        )
        
        self._log_structured_data("critical_error", {
            "session_id": session_id,
            "operation": operation,
            "error": error,
            "context": context or {},
            "timestamp": datetime.now().isoformat()
        })
    
    def log_upload_summary(self, session_id: str, total_files: int, 
                          completed: int, failed: int, skipped: int,
                          total_time: float, total_size: int) -> None:
        """
        Registrar resumen final de subida.
        
        Args:
            session_id: ID de la sesión
            total_files: Total de archivos
            completed: Archivos completados
            failed: Archivos fallidos
            skipped: Archivos omitidos
            total_time: Tiempo total en segundos
            total_size: Tamaño total procesado
        """
        success_rate = (completed / total_files * 100) if total_files > 0 else 0
        
        self.logger.info(
            f"📊 RESUMEN FINAL | Session: {session_id} | "
            f"Total: {total_files} | Completed: {completed} | "
            f"Failed: {failed} | Skipped: {skipped} | "
            f"Success: {success_rate:.1f}% | Time: {self._format_time(total_time)} | "
            f"Size: {self._format_size(total_size)}"
        )
        
        self._log_structured_data("upload_summary", {
            "session_id": session_id,
            "total_files": total_files,
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "success_rate": success_rate,
            "total_time": total_time,
            "total_size": total_size,
            "timestamp": datetime.now().isoformat()
        })
    
    def _log_structured_data(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Registrar datos estructurados en formato JSON.
        
        Args:
            event_type: Tipo de evento
            data: Datos del evento
        """
        structured_log = self.log_dir / "gpmc_structured.jsonl"
        
        try:
            log_entry = {
                "event_type": event_type,
                "data": data
            }
            
            with open(structured_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, default=str) + '\n')
                
        except Exception as e:
            self.logger.error(f"Error al escribir log estructurado: {e}")
    
    def _format_size(self, size_bytes: int) -> str:
        """Formatear tamaño en bytes a formato legible."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def _format_time(self, seconds: float) -> str:
        """Formatear tiempo en segundos a formato legible."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    def get_session_logs(self, session_id: str, 
                        event_types: list[str] = None) -> list[Dict[str, Any]]:
        """
        Obtener logs de una sesión específica.
        
        Args:
            session_id: ID de la sesión
            event_types: Tipos de eventos a filtrar
            
        Returns:
            Lista de entradas de log
        """
        structured_log = self.log_dir / "gpmc_structured.jsonl"
        
        if not structured_log.exists():
            return []
        
        logs = []
        try:
            with open(structured_log, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get('data', {}).get('session_id') == session_id:
                            if not event_types or entry.get('event_type') in event_types:
                                logs.append(entry)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.logger.error(f"Error al leer logs de sesión: {e}")
        
        return logs
    
    def cleanup_old_logs(self, days: int = 30) -> None:
        """
        Limpiar logs antiguos.
        
        Args:
            days: Días de antigüedad para limpiar
        """
        try:
            cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
            
            for log_file in self.log_dir.glob("*.log*"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    self.logger.info(f"Log antiguo eliminado: {log_file}")
            
            # Limpiar logs estructurados antiguos
            structured_log = self.log_dir / "gpmc_structured.jsonl"
            if structured_log.exists():
                self._cleanup_structured_log(structured_log, cutoff_time)
                
        except Exception as e:
            self.logger.error(f"Error al limpiar logs antiguos: {e}")
    
    def _cleanup_structured_log(self, log_file: Path, cutoff_time: float) -> None:
        """Limpiar entradas antiguas del log estructurado."""
        temp_file = log_file.with_suffix('.tmp')
        
        try:
            with open(log_file, 'r', encoding='utf-8') as infile, \
                 open(temp_file, 'w', encoding='utf-8') as outfile:
                
                for line in infile:
                    try:
                        entry = json.loads(line.strip())
                        timestamp_str = entry.get('data', {}).get('timestamp', '')
                        if timestamp_str:
                            timestamp = datetime.fromisoformat(timestamp_str).timestamp()
                            if timestamp >= cutoff_time:
                                outfile.write(line)
                    except (json.JSONDecodeError, ValueError):
                        # Mantener líneas que no se pueden parsear
                        outfile.write(line)
            
            # Reemplazar archivo original
            temp_file.replace(log_file)
            
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise e


# Instancia global del logger
checkpoint_logger = CheckpointLogger()