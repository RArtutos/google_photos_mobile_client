"""
Sistema de progreso detallado para subidas de archivos.
Proporciona indicadores visuales completos con información detallada por archivo,
resumen general de la operación y contadores en tiempo real.
"""

from typing import Dict, List, Optional, Set
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import time
import mimetypes
from rich.progress import (
    Progress, TaskID, TextColumn, BarColumn, MofNCompleteColumn, 
    TimeElapsedColumn, TimeRemainingColumn, FileSizeColumn,
    TransferSpeedColumn, SpinnerColumn
)
from rich.console import Group, Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich import box
import logging


@dataclass
class FileProgress:
    """Información de progreso para un archivo individual."""
    path: Path
    size: int
    album: str
    status: str = "pending"  # pending, uploading, success, failed
    progress: float = 0.0
    speed: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: str = ""
    task_id: Optional[TaskID] = None
    # Nuevo: bytes subidos para calcular delta y sincronizar progreso global
    uploaded_bytes: int = 0


@dataclass
class AlbumStats:
    """Estadísticas por álbum."""
    name: str
    total_files: int = 0
    total_size: int = 0
    completed_files: int = 0
    completed_size: int = 0
    failed_files: int = 0
    failed_size: int = 0
    videos_count: int = 0
    videos_completed: int = 0
    photos_count: int = 0
    photos_completed: int = 0


class DetailedProgressTracker:
    """
    Sistema de progreso detallado para subidas de archivos.
    
    Proporciona:
    - Indicadores visuales por archivo (nombre, tamaño, velocidad, tiempo)
    - Resumen general de la operación
    - Contadores corregidos por álbum y tipo de archivo
    - Diseño jerárquico y colores distintivos
    """
    
    def __init__(self, show_progress: bool = True, max_visible_files: int = 5, compact_mode: bool = True):
        self.show_progress = show_progress
        self.max_visible_files = max_visible_files
        self.compact_mode = compact_mode
        self.logger = logging.getLogger(__name__)
        
        # Datos de seguimiento
        self.files: Dict[Path, FileProgress] = {}
        self.albums: Dict[str, AlbumStats] = {}
        self.active_uploads: Set[Path] = set()
        self.start_time = datetime.now()
        
        # Componentes de progreso Rich
        self._setup_progress_components()
        
        # Estadísticas globales
        self.total_files = 0
        self.total_size = 0
        self.completed_files = 0
        self.completed_size = 0
        self.failed_files = 0
        self.failed_size = 0
        
    def _setup_progress_components(self):
        """Configurar componentes de progreso Rich."""
        if self.compact_mode:
            # Progreso general compacto
            self.main_progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Subiendo"),
                BarColumn(bar_width=25),
                TextColumn("{task.percentage:>3.0f}%"),
                TextColumn("•"),
                MofNCompleteColumn(),
                TextColumn("•"),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
            )
            
            # Progreso de archivos más compacto
            self.file_progress = Progress(
                TextColumn("{task.description}", justify="left"),
                BarColumn(bar_width=15),
                TextColumn("{task.percentage:>3.0f}%"),
                TransferSpeedColumn(),
            )
        else:
            # Progreso general completo (original)
            self.main_progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Progreso General"),
                BarColumn(bar_width=40),
                MofNCompleteColumn(),
                TextColumn("•"),
                FileSizeColumn(),
                TextColumn("•"),
                TransferSpeedColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            )
            
            # Progreso de archivos individuales completo
            self.file_progress = Progress(
                TextColumn("[bold green]{task.description}", justify="left"),
                BarColumn(bar_width=20),
                TextColumn("{task.percentage:>3.0f}%"),
                FileSizeColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
            )
        
        # Progreso por álbum (siempre compacto)
        self.album_progress = Progress(
            TextColumn("📁 [bold cyan]{task.description}"),
            BarColumn(bar_width=20),
            TextColumn("{task.percentage:>3.0f}%"),
            TextColumn("({task.fields[details]})"),
        )
        
        self.main_task_id: Optional[TaskID] = None
        
    def initialize_files(self, file_album_mapping: Dict[Path, str]) -> None:
        """
        Inicializar archivos y álbumes para el seguimiento.
        
        Args:
            file_album_mapping: Mapeo de archivos a álbumes
        """
        self.total_files = len(file_album_mapping)
        
        # Inicializar archivos
        for file_path, album_name in file_album_mapping.items():
            try:
                file_size = file_path.stat().st_size
                self.total_size += file_size
                
                # Crear registro de archivo
                self.files[file_path] = FileProgress(
                    path=file_path,
                    size=file_size,
                    album=album_name
                )
                
                # Inicializar álbum si no existe
                if album_name not in self.albums:
                    self.albums[album_name] = AlbumStats(name=album_name)
                
                # Actualizar estadísticas del álbum
                album_stats = self.albums[album_name]
                album_stats.total_files += 1
                album_stats.total_size += file_size
                
                # Clasificar por tipo de archivo
                mime_type, _ = mimetypes.guess_type(str(file_path))
                if mime_type and mime_type.startswith('video/'):
                    album_stats.videos_count += 1
                else:
                    album_stats.photos_count += 1
                    
            except OSError as e:
                self.logger.error(f"Error accediendo archivo {file_path}: {e}")
                continue
        
        # Crear tareas de progreso
        if self.show_progress:
            self.main_task_id = self.main_progress.add_task(
                "Subiendo archivos",
                total=self.total_size
            )
            
            # Crear tareas por álbum
            for album_name, stats in self.albums.items():
                self.album_progress.add_task(
                    album_name,
                    total=stats.total_files,
                    details=f"📷 {stats.photos_count} fotos, 🎥 {stats.videos_count} videos"
                )
        
        self.logger.info(
            f"Inicializados {len(self.albums)} álbumes con {self.total_files} archivos "
            f"({self._format_size(self.total_size)})"
        )
    
    def start_file_upload(self, file_path: Path) -> None:
        """
        Marcar inicio de subida de un archivo.
        
        Args:
            file_path: Ruta del archivo que inicia subida
        """
        if file_path not in self.files:
            # Si no está (ej. modo carpeta sin escaneo previo), agregarlo dinámicamente
            try:
                size = file_path.stat().st_size
            except OSError:
                size = 0
            
            # Crear nueva entrada
            self.files[file_path] = FileProgress(
                path=file_path,
                size=size,
                album="Unknown"
            )
            # file_info se asignará después
        
        file_info = self.files[file_path]
        file_info.status = "uploading"
        file_info.start_time = datetime.now()
        self.active_uploads.add(file_path)
        
        # Crear tarea de progreso individual si hay espacio o en modo compacto
        if self.show_progress:
            # Nombre más corto para modo compacto
            if self.compact_mode:
                display_name = f"{file_path.name}"
            else:
                display_name = f"{file_path.name} ({self._format_size(file_info.size)})"
                
            file_info.task_id = self.file_progress.add_task(
                display_name,
                total=file_info.size
            )
    
    def update_file_progress(self, file_path: Path, bytes_uploaded: int) -> None:
        """
        Actualizar progreso de subida de un archivo.
        
        Args:
            file_path: Ruta del archivo
            bytes_uploaded: Bytes subidos hasta ahora
        """
        if file_path not in self.files:
            return
        
        file_info = self.files[file_path]
        # Calcular delta desde última actualización
        delta = max(bytes_uploaded - file_info.uploaded_bytes, 0)
        file_info.uploaded_bytes = bytes_uploaded
        file_info.progress = min(bytes_uploaded / file_info.size, 1.0) if file_info.size > 0 else 1.0
        
        # Calcular velocidad
        if file_info.start_time:
            elapsed = (datetime.now() - file_info.start_time).total_seconds()
            if elapsed > 0:
                file_info.speed = bytes_uploaded / elapsed
        
        # Actualizar progreso visual
        if self.show_progress and file_info.task_id is not None:
            self.file_progress.update(
                file_info.task_id,
                completed=bytes_uploaded
            )
        
        # Avanzar progreso global por bytes para ETA y velocidad
        if self.show_progress and self.main_task_id and delta > 0:
            self.main_progress.update(
                self.main_task_id,
                advance=delta
            )
    
    def complete_file_upload(self, file_path: Path, success: bool, error_message: str = "") -> None:
        """
        Marcar completado (exitoso o fallido) de subida de archivo.
        
        Args:
            file_path: Ruta del archivo
            success: True si fue exitoso, False si falló
            error_message: Mensaje de error si falló
        """
        if file_path not in self.files:
            return
        
        file_info = self.files[file_path]
        file_info.end_time = datetime.now()
        file_info.status = "success" if success else "failed"
        file_info.error_message = error_message
        
        # Actualizar estadísticas globales
        if success:
            self.completed_files += 1
            self.completed_size += file_info.size
        else:
            self.failed_files += 1
            self.failed_size += file_info.size
        
        # Actualizar estadísticas del álbum
        album_stats = self.albums[file_info.album]
        old_completed = album_stats.completed_files
        
        if success:
            album_stats.completed_files += 1
            album_stats.completed_size += file_info.size
            
            # Actualizar contador por tipo
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and mime_type.startswith('video/'):
                album_stats.videos_completed += 1
            else:
                album_stats.photos_completed += 1
        else:
            album_stats.failed_files += 1
            album_stats.failed_size += file_info.size
        
        # Debug: Log para verificar actualización
        self.logger.debug(f"Álbum '{file_info.album}': {old_completed} -> {album_stats.completed_files} completados")
        
        # Limpiar progreso individual
        if file_info.task_id is not None and self.show_progress:
            self.file_progress.remove_task(file_info.task_id)
            file_info.task_id = None
        
        self.active_uploads.discard(file_path)
        
        # Actualizar progreso principal evitando doble avance
        if self.show_progress and self.main_task_id:
            remaining = max(file_info.size - file_info.uploaded_bytes, 0)
            if remaining > 0:
                self.main_progress.update(
                    self.main_task_id,
                    advance=remaining
                )
        
        # Actualizar progreso del álbum
        if self.show_progress:
            self._update_album_progress(file_info.album)
    
    def _update_album_progress(self, album_name: str) -> None:
        """Actualizar progreso visual del álbum."""
        if album_name not in self.albums:
            return
        
        stats = self.albums[album_name]
        
        # Buscar task_id del álbum
        for task in self.album_progress.tasks:
            if task.description == album_name:
                # Crear detalles actualizados
                details_parts = []
                if stats.photos_completed > 0 or stats.photos_count > 0:
                    details_parts.append(f"📷 {stats.photos_completed}/{stats.photos_count}")
                if stats.videos_completed > 0 or stats.videos_count > 0:
                    details_parts.append(f"🎥 {stats.videos_completed}/{stats.videos_count}")
                if stats.failed_files > 0:
                    details_parts.append(f"❌ {stats.failed_files}")
                
                details = ", ".join(details_parts)
                
                self.album_progress.update(
                    task.id,
                    completed=stats.completed_files,
                    details=details
                )
                break
    
    def get_progress_layout(self) -> Group:
        """
        Obtener layout completo de progreso para mostrar.
        
        Returns:
            Group con todos los componentes de progreso
        """
        if not self.show_progress:
            return Group()

        components = []
        
        if self.compact_mode:
            # Modo compacto: solo elementos esenciales
            components.append(self.main_progress)
            
            # Resumen en una línea
            completion_rate = (self.completed_size / self.total_size * 100) if self.total_size > 0 else 0
            pending = self.total_files - self.completed_files - self.failed_files
            
            summary_text = Text()
            summary_text.append(f"📊 {self.completed_files}/{self.total_files} archivos ", style="cyan")
            summary_text.append(f"✅ {self.completed_files} ", style="green")
            if self.failed_files > 0:
                summary_text.append(f"❌ {self.failed_files} ", style="red")
            if pending > 0:
                summary_text.append(f"⏳ {pending} ", style="yellow")
            summary_text.append(f"📁 {len(self.albums)} álbumes", style="blue")
            
            components.append(Panel(summary_text, border_style="blue", height=3))
            
            # Mostrar archivos activos si hay uploads en progreso
            if self.active_uploads:
                components.append(Panel(
                    self.file_progress,
                    title=f"📄 Subiendo ({len(self.active_uploads)})",
                    border_style="green",
                    height=min(len(self.active_uploads) + 2, 8)  # Máximo 8 líneas de altura
                ))
            
            # Mostrar álbumes con información detallada pero compacta
            components.append(Panel(
                self.album_progress,
                title="📁 Estado de Álbumes",
                border_style="cyan",
                height=min(len(self.albums) + 4, 15)
            ))
        else:
            # Modo completo (original)
            summary_panel = self._create_summary_panel()
            albums_table = self._create_albums_table()
            
            components = [
                self.main_progress,
                "",  # Línea en blanco
                summary_panel,
                "",
                self.album_progress,
            ]
            
            # Añadir progreso de archivos individuales si hay uploads activos
            if self.active_uploads:
                components.extend([
                    "",
                    Panel(
                        self.file_progress,
                        title=f"📄 Archivos en Subida ({len(self.active_uploads)})",
                        border_style="green"
                    )
                ])
            
            # Añadir tabla de álbumes
            components.extend([
                "",
                albums_table
            ])
        
        return Group(*components)
    
    def _create_summary_panel(self) -> Panel:
        """Crear panel de resumen general."""
        text = Text()
        
        # Estadísticas generales
        completion_rate = (self.completed_size / self.total_size * 100) if self.total_size > 0 else 0
        
        text.append("📊 RESUMEN GENERAL\n", style="bold blue")
        text.append(f"📁 Álbumes: {len(self.albums)}\n", style="cyan")
        text.append(f"📄 Archivos: {self.completed_files + self.failed_files}/{self.total_files}\n")
        text.append(f"💾 Tamaño: {self._format_size(self.completed_size + self.failed_size)}/{self._format_size(self.total_size)}\n")
        text.append(f"📈 Progreso: {completion_rate:.1f}%\n", style="green" if completion_rate > 50 else "yellow")
        
        # Tiempo estimado
        if self.completed_size > 0:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if elapsed > 0:
                speed = self.completed_size / elapsed
                remaining_size = self.total_size - self.completed_size - self.failed_size
                if speed > 0 and remaining_size > 0:
                    eta_seconds = remaining_size / speed
                    eta = timedelta(seconds=int(eta_seconds))
                    text.append(f"⏱️ Tiempo restante: {eta}\n", style="yellow")
        
        # Contadores por estado
        text.append(f"✅ Completados: {self.completed_files}\n", style="green")
        if self.failed_files > 0:
            text.append(f"❌ Fallidos: {self.failed_files}\n", style="red")
        pending = self.total_files - self.completed_files - self.failed_files
        if pending > 0:
            text.append(f"⏳ Pendientes: {pending}", style="yellow")
        
        return Panel(text, title="📊 Estado General", border_style="blue")
    
    def _create_compact_albums_table(self) -> Panel:
        """Crear tabla compacta de álbumes con información detallada."""
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        table.add_column("📁 Álbum", style="cyan", no_wrap=False, min_width=20)
        table.add_column("📊 Progreso", justify="center", min_width=12)
        table.add_column("📄 Archivos", justify="center", min_width=10)
        table.add_column("✅ Completados", justify="center", min_width=10, style="green")
        table.add_column("❌ Fallos", justify="center", min_width=8, style="red")
        table.add_column("⏳ Pendientes", justify="center", min_width=10, style="yellow")
        
        for album_name, stats in self.albums.items():
            total = stats.total_files
            completed = stats.completed_files
            failed = stats.failed_files
            pending = total - completed - failed
            
            # Debug: Log para verificar datos en tiempo real
            self.logger.debug(f"Tabla - Álbum '{album_name}': {completed}/{total} completados, {failed} fallos, {pending} pendientes")
            
            # Barra de progreso compacta
            if total > 0:
                progress_percent = (completed / total) * 100
                progress_bar = f"[{'█' * int(progress_percent / 10)}{'░' * (10 - int(progress_percent / 10))}] {progress_percent:.0f}%"
            else:
                progress_bar = "[░░░░░░░░░░] 0%"
            
            # Nombre del álbum (truncado si es muy largo)
            display_name = album_name if len(album_name) <= 25 else f"{album_name[:22]}..."
            
            table.add_row(
                display_name,
                progress_bar,
                str(total),
                str(completed),
                str(failed) if failed > 0 else "-",
                str(pending) if pending > 0 else "-"
            )
        
        return Panel(
            table,
            title="📁 Estado de Álbumes",
            border_style="cyan",
            height=min(len(self.albums) + 4, 15)  # Limitar altura máxima
        )
    
    def _create_albums_table(self) -> Panel:
        """Crear tabla detallada de álbumes."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("📁 Álbum", style="cyan", no_wrap=True)
        table.add_column("📷 Fotos", justify="center")
        table.add_column("🎥 Videos", justify="center")
        table.add_column("✅ Completados", justify="center", style="green")
        table.add_column("❌ Fallidos", justify="center", style="red")
        table.add_column("📊 Progreso", justify="center")
        table.add_column("💾 Tamaño", justify="right")
        
        for album_name, stats in self.albums.items():
            photos_text = f"{stats.photos_completed}/{stats.photos_count}"
            videos_text = f"{stats.videos_completed}/{stats.videos_count}"
            completed_text = str(stats.completed_files)
            failed_text = str(stats.failed_files) if stats.failed_files > 0 else "-"
            
            progress_pct = (stats.completed_files / stats.total_files * 100) if stats.total_files > 0 else 0
            progress_text = f"{progress_pct:.1f}%"
            
            size_text = f"{self._format_size(stats.completed_size)}/{self._format_size(stats.total_size)}"
            
            table.add_row(
                album_name,
                photos_text,
                videos_text,
                completed_text,
                failed_text,
                progress_text,
                size_text
            )
        
        return Panel(table, title="📁 Detalle por Álbum", border_style="cyan")
    
    def _format_size(self, size_bytes: int) -> str:
        """Formatear tamaño en bytes a formato legible."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def get_final_statistics(self) -> Dict:
        """Obtener estadísticas finales completas."""
        return {
            "general": {
                "total_files": self.total_files,
                "total_size": self.total_size,
                "completed_files": self.completed_files,
                "completed_size": self.completed_size,
                "failed_files": self.failed_files,
                "failed_size": self.failed_size,
                "success_rate": (self.completed_files / self.total_files * 100) if self.total_files > 0 else 0,
                "duration": (datetime.now() - self.start_time).total_seconds()
            },
            "albums": {name: {
                "total_files": stats.total_files,
                "completed_files": stats.completed_files,
                "failed_files": stats.failed_files,
                "photos_completed": stats.photos_completed,
                "videos_completed": stats.videos_completed,
                "total_size": stats.total_size,
                "completed_size": stats.completed_size
            } for name, stats in self.albums.items()}
        }
    
    def log_final_summary(self) -> None:
        """Registrar resumen final en logs."""
        stats = self.get_final_statistics()
        general = stats["general"]
        
        self.logger.info("=== RESUMEN FINAL DE SUBIDA ===")
        self.logger.info(
            f"📊 Total: {general['completed_files']}/{general['total_files']} archivos "
            f"({general['success_rate']:.1f}% éxito)"
        )
        self.logger.info(
            f"💾 Tamaño: {self._format_size(general['completed_size'])}/{self._format_size(general['total_size'])}"
        )
        self.logger.info(f"⏱️ Duración: {timedelta(seconds=int(general['duration']))}")
        
        if general['failed_files'] > 0:
            self.logger.warning(f"❌ {general['failed_files']} archivos fallaron")
        
        # Resumen por álbum
        for album_name, album_stats in stats["albums"].items():
            self.logger.info(
                f"📁 {album_name}: {album_stats['completed_files']}/{album_stats['total_files']} "
                f"(📷 {album_stats['photos_completed']} fotos, 🎥 {album_stats['videos_completed']} videos)"
            )