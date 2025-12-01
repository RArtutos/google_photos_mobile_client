"""
Sistema de manejo de interrupciones para garantizar la integridad de los checkpoints.
"""

import signal
import sys
import logging
import atexit
from typing import Optional, Callable, Any
from pathlib import Path

from .checkpoint_manager import CheckpointManager


class InterruptionHandler:
    """Manejador de interrupciones para garantizar la consistencia de checkpoints."""
    
    def __init__(self, checkpoint_manager: CheckpointManager):
        """
        Inicializar el manejador de interrupciones.
        
        Args:
            checkpoint_manager: Instancia del gestor de checkpoints
        """
        self.checkpoint_manager = checkpoint_manager
        self.logger = logging.getLogger(__name__)
        self.cleanup_callbacks: list[Callable[[], None]] = []
        self.is_handling_interruption = False
        
        # Registrar manejadores de señales
        self._register_signal_handlers()
        
        # Registrar cleanup al salir
        atexit.register(self._cleanup_on_exit)
    
    def _register_signal_handlers(self) -> None:
        """Registrar manejadores para diferentes tipos de interrupciones."""
        # SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, self._handle_interruption)
        
        # SIGTERM (terminación del proceso)
        signal.signal(signal.SIGTERM, self._handle_interruption)
        
        # En Windows, también manejar SIGBREAK
        if sys.platform == "win32":
            try:
                signal.signal(signal.SIGBREAK, self._handle_interruption)
            except AttributeError:
                # SIGBREAK no disponible en todas las versiones
                pass
    
    def _handle_interruption(self, signum: int, frame: Any) -> None:
        """
        Manejar interrupciones de forma segura.
        
        Args:
            signum: Número de señal recibida
            frame: Frame de ejecución actual
        """
        if self.is_handling_interruption:
            # Evitar recursión en el manejo de interrupciones
            self.logger.warning("Interrupcción múltiple detectada, forzando salida...")
            sys.exit(1)
        
        self.is_handling_interruption = True
        
        signal_names = {
            signal.SIGINT: "SIGINT (Ctrl+C)",
            signal.SIGTERM: "SIGTERM",
        }
        
        if sys.platform == "win32":
            signal_names[signal.SIGBREAK] = "SIGBREAK"
        
        signal_name = signal_names.get(signum, f"Señal {signum}")
        
        self.logger.info(f"\n🛑 Interrupcción detectada: {signal_name}")
        self.logger.info("💾 Guardando estado actual del checkpoint...")
        
        try:
            # Guardar checkpoint actual
            if self.checkpoint_manager.current_checkpoint:
                self.checkpoint_manager.save_checkpoint()
                self.logger.info("✅ Checkpoint guardado exitosamente")
            
            # Ejecutar callbacks de limpieza
            self._execute_cleanup_callbacks()
            
            self.logger.info("🔄 Para continuar la subida, ejecuta el mismo comando nuevamente")
            self.logger.info("❌ Saliendo de forma segura...")
            
        except Exception as e:
            self.logger.error(f"❌ Error al guardar checkpoint durante interrupcción: {e}")
        
        finally:
            sys.exit(0)
    
    def _cleanup_on_exit(self) -> None:
        """Cleanup automático al salir del programa."""
        if not self.is_handling_interruption:
            # Solo hacer cleanup si no estamos ya manejando una interrupcción
            try:
                if self.checkpoint_manager.current_checkpoint:
                    self.checkpoint_manager.save_checkpoint()
                    self.logger.debug("Checkpoint guardado automáticamente al salir")
            except Exception as e:
                self.logger.error(f"Error en cleanup automático: {e}")
    
    def add_cleanup_callback(self, callback: Callable[[], None]) -> None:
        """
        Agregar callback de limpieza que se ejecutará durante interrupciones.
        
        Args:
            callback: Función a ejecutar durante la limpieza
        """
        self.cleanup_callbacks.append(callback)
    
    def remove_cleanup_callback(self, callback: Callable[[], None]) -> None:
        """
        Remover callback de limpieza.
        
        Args:
            callback: Función a remover
        """
        if callback in self.cleanup_callbacks:
            self.cleanup_callbacks.remove(callback)
    
    def _execute_cleanup_callbacks(self) -> None:
        """Ejecutar todos los callbacks de limpieza registrados."""
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                self.logger.error(f"Error en callback de limpieza: {e}")
    
    def safe_operation(self, operation: Callable[[], Any], 
                      operation_name: str = "operación") -> Any:
        """
        Ejecutar una operación de forma segura con manejo de interrupciones.
        
        Args:
            operation: Función a ejecutar
            operation_name: Nombre descriptivo de la operación
            
        Returns:
            Resultado de la operación
        """
        try:
            self.logger.debug(f"Iniciando {operation_name}")
            result = operation()
            self.logger.debug(f"Completado {operation_name}")
            return result
            
        except KeyboardInterrupt:
            self.logger.info(f"Interrupcción durante {operation_name}")
            self._handle_interruption(signal.SIGINT, None)
            
        except Exception as e:
            self.logger.error(f"Error durante {operation_name}: {e}")
            # Guardar checkpoint en caso de error
            if self.checkpoint_manager.current_checkpoint:
                try:
                    self.checkpoint_manager.save_checkpoint()
                    self.logger.info("Checkpoint guardado después del error")
                except Exception as save_error:
                    self.logger.error(f"Error al guardar checkpoint: {save_error}")
            raise
    
    def create_progress_checkpoint(self, completed_files: list[Path], 
                                 failed_files: list[Path]) -> None:
        """
        Crear checkpoint de progreso durante la subida.
        
        Args:
            completed_files: Lista de archivos completados
            failed_files: Lista de archivos fallidos
        """
        try:
            if self.checkpoint_manager.current_checkpoint:
                # Actualizar progreso en el checkpoint
                for file_path in completed_files:
                    self.checkpoint_manager.update_file_progress(
                        file_path, 'completed'
                    )
                
                for file_path in failed_files:
                    self.checkpoint_manager.update_file_progress(
                        file_path, 'failed', error="Error durante subida"
                    )
                
                # Guardar checkpoint actualizado
                self.checkpoint_manager.save_checkpoint()
                self.logger.debug(f"Checkpoint actualizado: {len(completed_files)} completados, {len(failed_files)} fallidos")
                
        except Exception as e:
            self.logger.error(f"Error al crear checkpoint de progreso: {e}")
    
    def validate_checkpoint_integrity(self) -> bool:
        """
        Validar la integridad del checkpoint actual.
        
        Returns:
            True si el checkpoint es válido, False en caso contrario
        """
        try:
            if not self.checkpoint_manager.current_checkpoint:
                return True  # No hay checkpoint, es válido
            
            checkpoint = self.checkpoint_manager.current_checkpoint
            
            # Verificar que los archivos del checkpoint existan
            missing_files = []
            for file_checkpoint in checkpoint.files.values():
                if file_checkpoint.status == 'pending':
                    file_path = Path(file_checkpoint.file_path)
                    if not file_path.exists():
                        missing_files.append(file_path)
            
            if missing_files:
                self.logger.warning(f"Archivos faltantes en checkpoint: {len(missing_files)}")
                for missing_file in missing_files[:5]:  # Mostrar solo los primeros 5
                    self.logger.warning(f"  - {missing_file}")
                
                if len(missing_files) > 5:
                    self.logger.warning(f"  ... y {len(missing_files) - 5} más")
                
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error al validar integridad del checkpoint: {e}")
            return False
    
    def emergency_save(self) -> bool:
        """
        Guardar checkpoint de emergencia.
        
        Returns:
            True si se guardó exitosamente, False en caso contrario
        """
        try:
            if self.checkpoint_manager.current_checkpoint:
                # Crear backup de emergencia
                emergency_path = self.checkpoint_manager.checkpoint_dir / f"emergency_{self.checkpoint_manager.current_checkpoint.session_id}.json"
                
                import json
                from datetime import datetime
                
                emergency_data = {
                    'timestamp': datetime.now().isoformat(),
                    'checkpoint': self.checkpoint_manager.current_checkpoint.__dict__,
                    'reason': 'emergency_save'
                }
                
                with open(emergency_path, 'w', encoding='utf-8') as f:
                    json.dump(emergency_data, f, indent=2, default=str)
                
                self.logger.info(f"💾 Checkpoint de emergencia guardado: {emergency_path}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Error al guardar checkpoint de emergencia: {e}")
            return False