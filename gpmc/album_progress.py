"""
Progreso por álbum para subidas de archivos.
Permite mostrar progreso separado para cada álbum durante la subida concurrente.
"""

from typing import Dict, List, Optional
from pathlib import Path
from rich.progress import Progress, TaskID, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
from rich.console import Group
from rich.panel import Panel
from rich.text import Text
import logging


class AlbumProgressTracker:
    """
    Rastreador de progreso por álbum para subidas concurrentes.
    
    Mantiene progreso separado para cada álbum y muestra estadísticas
    individuales durante el proceso de subida.
    """
    
    def __init__(self, show_progress: bool = True):
        self.show_progress = show_progress
        self.logger = logging.getLogger(__name__)
        
        # Progreso principal para todos los álbumes
        self.main_progress = Progress(
            TextColumn("[bold blue]Progreso General:"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        )
        
        # Progreso individual por álbum
        self.album_progress = Progress(
            TextColumn("[bold green]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("({task.fields[status]})"),
        )
        
        # Datos de seguimiento
        self.album_tasks: Dict[str, TaskID] = {}
        self.album_files: Dict[str, List[Path]] = {}
        self.album_completed: Dict[str, int] = {}
        self.album_failed: Dict[str, int] = {}
        self.main_task_id: Optional[TaskID] = None
        self.total_files = 0
        
    def initialize_albums(self, file_album_mapping: Dict[Path, str]) -> None:
        """
        Inicializar álbumes basado en el mapeo de archivos.
        
        Args:
            file_album_mapping: Diccionario que mapea archivos a nombres de álbum
        """
        # Agrupar archivos por álbum
        for file_path, album_name in file_album_mapping.items():
            if album_name not in self.album_files:
                self.album_files[album_name] = []
                self.album_completed[album_name] = 0
                self.album_failed[album_name] = 0
            self.album_files[album_name].append(file_path)
        
        self.total_files = len(file_album_mapping)
        
        # Crear tareas de progreso para cada álbum
        if self.show_progress:
            self.main_task_id = self.main_progress.add_task(
                "Subiendo archivos", 
                total=self.total_files
            )
            
            for album_name, files in self.album_files.items():
                task_id = self.album_progress.add_task(
                    f"📁 {album_name}",
                    total=len(files),
                    status="Pendiente"
                )
                self.album_tasks[album_name] = task_id
        
        self.logger.info(f"Inicializados {len(self.album_files)} álbumes con {self.total_files} archivos totales")
    
    def update_file_progress(self, file_path: Path, album_name: str, success: bool) -> None:
        """
        Actualizar progreso cuando se completa la subida de un archivo.
        
        Args:
            file_path: Ruta del archivo procesado
            album_name: Nombre del álbum
            success: True si la subida fue exitosa, False si falló
        """
        if album_name not in self.album_completed:
            self.logger.warning(f"Álbum no inicializado: {album_name}")
            return
        
        # Actualizar contadores
        if success:
            self.album_completed[album_name] += 1
            status = "✅ Completando"
        else:
            self.album_failed[album_name] += 1
            status = "❌ Con errores"
        
        # Actualizar progreso visual
        if self.show_progress and album_name in self.album_tasks:
            task_id = self.album_tasks[album_name]
            completed = self.album_completed[album_name]
            failed = self.album_failed[album_name]
            total = len(self.album_files[album_name])
            
            # Determinar estado del álbum
            if completed + failed == total:
                if failed == 0:
                    status = "✅ Completado"
                else:
                    status = f"⚠️ {completed} ok, {failed} errores"
            
            self.album_progress.update(
                task_id,
                advance=1,
                status=status
            )
            
            # Actualizar progreso principal
            if self.main_task_id:
                self.main_progress.advance(self.main_task_id)
        
        self.logger.debug(f"Progreso actualizado - {album_name}: {file_path.name} ({'éxito' if success else 'fallo'})")
    
    def get_progress_group(self) -> Group:
        """
        Obtener grupo de progreso para mostrar en Rich Live.
        
        Returns:
            Group con los elementos de progreso para mostrar
        """
        if not self.show_progress:
            return Group()
        
        # Crear panel con resumen
        summary_text = self._create_summary_text()
        summary_panel = Panel(
            summary_text,
            title="📊 Resumen de Subida",
            border_style="blue"
        )
        
        return Group(
            self.main_progress,
            "",  # Línea en blanco
            self.album_progress,
            "",  # Línea en blanco
            summary_panel
        )
    
    def _create_summary_text(self) -> Text:
        """Crear texto de resumen con estadísticas actuales."""
        text = Text()
        
        total_completed = sum(self.album_completed.values())
        total_failed = sum(self.album_failed.values())
        total_pending = self.total_files - total_completed - total_failed
        
        text.append(f"📁 Álbumes: {len(self.album_files)}\n", style="bold")
        text.append(f"✅ Completados: {total_completed}\n", style="green")
        text.append(f"❌ Fallidos: {total_failed}\n", style="red")
        text.append(f"⏳ Pendientes: {total_pending}", style="yellow")
        
        return text
    
    def get_final_statistics(self) -> Dict[str, Dict[str, int]]:
        """
        Obtener estadísticas finales por álbum.
        
        Returns:
            Diccionario con estadísticas detalladas por álbum
        """
        stats = {}
        
        for album_name in self.album_files:
            stats[album_name] = {
                "total": len(self.album_files[album_name]),
                "completed": self.album_completed[album_name],
                "failed": self.album_failed[album_name],
                "success_rate": (
                    self.album_completed[album_name] / len(self.album_files[album_name]) * 100
                    if len(self.album_files[album_name]) > 0 else 0
                )
            }
        
        return stats
    
    def log_final_summary(self) -> None:
        """Registrar resumen final en los logs."""
        stats = self.get_final_statistics()
        
        self.logger.info("=== RESUMEN FINAL POR ÁLBUM ===")
        
        total_files = 0
        total_completed = 0
        total_failed = 0
        
        for album_name, album_stats in stats.items():
            total_files += album_stats["total"]
            total_completed += album_stats["completed"]
            total_failed += album_stats["failed"]
            
            self.logger.info(
                f"📁 {album_name}: "
                f"{album_stats['completed']}/{album_stats['total']} archivos "
                f"({album_stats['success_rate']:.1f}% éxito)"
            )
            
            if album_stats["failed"] > 0:
                self.logger.warning(f"   ❌ {album_stats['failed']} archivos fallaron")
        
        self.logger.info(f"📊 TOTAL: {total_completed}/{total_files} archivos subidos exitosamente")
        if total_failed > 0:
            self.logger.warning(f"⚠️ {total_failed} archivos fallaron en total")