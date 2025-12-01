"""
Sistema de detección y reanudación de subidas interrumpidas.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from .enhanced_logging import checkpoint_logger

from .checkpoint_manager import CheckpointManager, UploadCheckpoint


class ResumeManager:
    """Gestor para detectar y reanudar subidas interrumpidas."""
    
    def __init__(self, checkpoint_manager: CheckpointManager):
        """
        Inicializar el gestor de reanudación.
        
        Args:
            checkpoint_manager: Instancia del gestor de checkpoints
        """
        self.checkpoint_manager = checkpoint_manager
        self.console = Console()
        self.logger = logging.getLogger(__name__)
    
    def check_for_interrupted_uploads(self, target_path: str, 
                                    album_name: Optional[str]) -> List[str]:
        """
        Verificar si existen subidas interrumpidas para la ruta y álbum dados.
        
        Args:
            target_path: Ruta objetivo de la subida
            album_name: Nombre del álbum (si aplica)
            
        Returns:
            Lista de IDs de sesiones interrumpidas encontradas
        """
        self.logger.info(f"Verificando subidas interrumpidas para: {target_path}")
        
        existing_sessions = self.checkpoint_manager.find_existing_checkpoints(
            target_path, album_name
        )
        
        # Filtrar solo las sesiones que no están completas
        incomplete_sessions = []
        for session_id in existing_sessions:
            checkpoint = self.checkpoint_manager.load_checkpoint(session_id)
            if checkpoint and not self.checkpoint_manager.is_upload_complete():
                incomplete_sessions.append(session_id)
        
        if incomplete_sessions:
            self.logger.info(f"Encontradas {len(incomplete_sessions)} subidas interrumpidas")
        else:
            self.logger.info("No se encontraron subidas interrumpidas")
        
        return incomplete_sessions
    
    def display_interrupted_uploads(self, session_ids: List[str]) -> None:
        """
        Mostrar información detallada de las subidas interrumpidas.
        
        Args:
            session_ids: Lista de IDs de sesiones interrumpidas
        """
        if not session_ids:
            return
        
        self.console.print("\n[bold yellow]⚠️  Subidas Interrumpidas Detectadas[/bold yellow]")
        
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("ID Sesión", style="cyan", width=12)
        table.add_column("Ruta", style="green")
        table.add_column("Álbum", style="magenta")
        table.add_column("Progreso", style="yellow")
        table.add_column("Archivos", style="white")
        table.add_column("Última Actualización", style="dim")
        
        for session_id in session_ids:
            checkpoint = self.checkpoint_manager.load_checkpoint(session_id)
            if not checkpoint:
                continue
            
            progress = self.checkpoint_manager.get_progress_summary()
            progress_text = f"{progress['completed_files']}/{progress['total_files']} ({progress['progress_percentage']:.1f}%)"
            
            # Formatear archivos
            files_text = f"✅ {progress['completed_files']} | ❌ {progress['failed_files']} | ⏳ {progress['pending_files']}"
            
            # Formatear fecha
            from datetime import datetime
            try:
                last_updated = datetime.fromisoformat(checkpoint.last_updated.replace('Z', '+00:00'))
                time_str = last_updated.strftime("%Y-%m-%d %H:%M")
            except:
                time_str = checkpoint.last_updated[:16]
            
            table.add_row(
                session_id,
                str(Path(checkpoint.target_path).name),
                checkpoint.album_name or "[dim]Sin álbum[/dim]",
                progress_text,
                files_text,
                time_str
            )
        
        self.console.print(table)
    
    def prompt_user_action(self, session_ids: List[str]) -> Tuple[str, Optional[str]]:
        """
        Preguntar al usuario qué acción tomar con las subidas interrumpidas.
        
        Args:
            session_ids: Lista de IDs de sesiones disponibles
            
        Returns:
            Tupla con (acción, session_id_seleccionado)
            Acciones posibles: 'resume', 'restart', 'cancel'
        """
        if not session_ids:
            return 'restart', None
        
        self.console.print("\n[bold]¿Qué deseas hacer?[/bold]")
        
        # Mostrar opciones
        options_text = Text()
        options_text.append("1. ", style="bold cyan")
        options_text.append("Continuar desde la última subida interrumpida\n")
        options_text.append("2. ", style="bold yellow")
        options_text.append("Reiniciar completamente (eliminar progreso anterior)\n")
        options_text.append("3. ", style="bold red")
        options_text.append("Cancelar operación")
        
        panel = Panel(options_text, title="Opciones Disponibles", border_style="blue")
        self.console.print(panel)
        
        while True:
            choice = Prompt.ask(
                "\n[bold]Selecciona una opción[/bold]",
                choices=["1", "2", "3"],
                default="1"
            )
            
            if choice == "1":
                # Continuar desde checkpoint
                if len(session_ids) == 1:
                    selected_session = session_ids[0]
                    self.console.print(f"\n[green]✓[/green] Continuando desde sesión: {selected_session}")
                else:
                    # Múltiples sesiones, permitir selección
                    selected_session = self._select_session(session_ids)
                    if not selected_session:
                        continue
                
                try:
                    checkpoint_logger.log_resume_attempt(selected_session, action='resume', user_choice='interactive')
                except Exception:
                    pass
                return 'resume', selected_session
            
            elif choice == "2":
                # Reiniciar completamente
                confirm = Confirm.ask(
                    "\n[bold red]⚠️  Esto eliminará todo el progreso anterior. ¿Continuar?[/bold red]",
                    default=False
                )
                if confirm:
                    # Limpiar checkpoints existentes
                    for session_id in session_ids:
                        self.checkpoint_manager.cleanup_checkpoint(session_id)
                    self.console.print("\n[yellow]🔄 Reiniciando subida desde cero...[/yellow]")
                    try:
                        checkpoint_logger.log_resume_attempt(session_ids[0], action='restart', user_choice='interactive')
                    except Exception:
                        pass
                    return 'restart', None
                else:
                    continue
            
            elif choice == "3":
                # Cancelar
                self.console.print("\n[red]❌ Operación cancelada[/red]")
                try:
                    checkpoint_logger.log_resume_attempt(session_ids[0], action='cancel', user_choice='interactive')
                except Exception:
                    pass
                return 'cancel', None
    
    def _select_session(self, session_ids: List[str]) -> Optional[str]:
        """
        Permitir al usuario seleccionar una sesión específica.
        
        Args:
            session_ids: Lista de IDs de sesiones disponibles
            
        Returns:
            ID de sesión seleccionado o None si se cancela
        """
        self.console.print("\n[bold]Múltiples sesiones encontradas. Selecciona una:[/bold]")
        
        # Mostrar sesiones numeradas
        for i, session_id in enumerate(session_ids, 1):
            checkpoint = self.checkpoint_manager.load_checkpoint(session_id)
            if checkpoint:
                progress = self.checkpoint_manager.get_progress_summary()
                self.console.print(
                    f"{i}. {session_id} - {progress['completed_files']}/{progress['total_files']} archivos "
                    f"({progress['progress_percentage']:.1f}%)"
                )
        
        while True:
            try:
                choice = Prompt.ask(
                    f"\nSelecciona sesión (1-{len(session_ids)}) o 'c' para cancelar",
                    default="1"
                )
                
                if choice.lower() == 'c':
                    return None
                
                index = int(choice) - 1
                if 0 <= index < len(session_ids):
                    return session_ids[index]
                else:
                    self.console.print(f"[red]Opción inválida. Usa 1-{len(session_ids)} o 'c'[/red]")
            
            except ValueError:
                self.console.print("[red]Entrada inválida. Usa un número o 'c'[/red]")
    
    def prepare_resume_data(self, session_id: str) -> Dict[str, Any]:
        """
        Preparar datos necesarios para reanudar una subida interrumpida.
        
        Args:
            session_id: ID de la sesión a reanudar
            
        Returns:
            Diccionario con datos de reanudación
        """
        checkpoint = self.checkpoint_manager.load_checkpoint(session_id)
        if not checkpoint:
            self.logger.error(f"No se pudo cargar el checkpoint para la sesión: {session_id}")
            return {}
        
        # Clasificar archivos por estado
        pending_files = []
        completed_files = []
        missing_files = []
        
        from datetime import datetime
        for file_data in checkpoint.files.values():
            file_path = Path(file_data['file_path']) if isinstance(file_data, dict) else Path(file_data.file_path)
            status = file_data['status'] if isinstance(file_data, dict) else file_data.status
            if status == 'pending':
                if file_path.exists():
                    pending_files.append(file_path)
                else:
                    missing_files.append(file_path)
            elif status == 'completed':
                completed_files.append(file_path)
        
        # Eliminar duplicados y ordenar
        valid_pending = list(dict.fromkeys(pending_files))
        
        progress = self.checkpoint_manager.get_progress_summary()
        progress_text = (
            f"{progress['completed_files']}/{progress['total_files']} archivos completados "
            f"({progress['progress_percentage']:.1f}%)"
        )
        
        # Logging mejorado de carga de checkpoint
        try:
            checkpoint_logger.log_checkpoint_loaded(
                session_id,
                pending_files=len(valid_pending),
                completed_files=len(completed_files),
                failed_files=len(missing_files),
            )
        except Exception:
            pass
        
        resume_panel = Panel(
            f"[cyan]Session ID:[/cyan] {session_id}\n"
            f"[green]Archivos completados:[/green] {len(completed_files)}\n"
            f"[yellow]Archivos pendientes:[/yellow] {len(valid_pending)}\n"
            f"[red]Archivos faltantes:[/red] {len(missing_files)}\n"
            f"[blue]Progreso total:[/blue] {progress['progress_percentage']:.1f}%",
            title="🔄 Reanudando Subida",
            border_style="green"
        )
        self.console.print(resume_panel)
        
        return {
            'session_id': session_id,
            'checkpoint': checkpoint,
            'pending_files': valid_pending,
            'completed_files': completed_files,
            'missing_files': missing_files,
            'upload_parameters': checkpoint.upload_parameters
        }
    
    def validate_resume_consistency(self, resume_data: Dict[str, Any], 
                                  current_params: Dict[str, Any],
                                  non_interactive: bool = False,
                                  continue_on_inconsistency: bool = False) -> bool:
        """
        Validar que los parámetros actuales sean consistentes con el checkpoint.
        
        Args:
            resume_data: Datos de reanudación
            current_params: Parámetros actuales de subida
            non_interactive: Si es True, no solicitar confirmación al usuario
            continue_on_inconsistency: En modo no interactivo, continuar aunque haya inconsistencias
            
        Returns:
            True si son consistentes, False en caso contrario
        """
        checkpoint_params = resume_data['upload_parameters']
        
        # Parámetros críticos que deben coincidir
        critical_params = ['album_name', 'use_quota', 'saver']
        
        inconsistencies = []
        for param in critical_params:
            if checkpoint_params.get(param) != current_params.get(param):
                inconsistencies.append(param)
        
        if inconsistencies:
            # Modo no interactivo: respetar política definida
            if non_interactive:
                if continue_on_inconsistency:
                    self.logger.warning("Continuando con parámetros inconsistentes en modo no interactivo")
                    try:
                        checkpoint_logger.log_resume_attempt(resume_data.get('session_id', ''), action='resume_inconsistent_continue', user_choice='cli')
                    except Exception:
                        pass
                    return True
                else:
                    self.logger.error("Parámetros inconsistentes en modo no interactivo; abortando reanudación")
                    try:
                        checkpoint_logger.log_error(resume_data.get('session_id', ''), 'validate_resume_consistency', 'inconsistencies', context={'inconsistencies': inconsistencies, 'current': current_params, 'checkpoint': checkpoint_params})
                    except Exception:
                        pass
                    return False
            
            self.console.print(f"\n[red]⚠️  Inconsistencias detectadas en parámetros:[/red]")
            
            table = Table(show_header=True, header_style="bold red")
            table.add_column("Parámetro", style="yellow")
            table.add_column("Checkpoint", style="cyan")
            table.add_column("Actual", style="magenta")
            
            for param in inconsistencies:
                table.add_row(
                    param,
                    str(checkpoint_params.get(param, 'N/A')),
                    str(current_params.get(param, 'N/A'))
                )
            
            self.console.print(table)
            
            # Preguntar si continuar de todos modos
            continue_anyway = Confirm.ask(
                "\n[bold]¿Continuar con los parámetros actuales?[/bold]",
                default=False
            )
            
            if continue_anyway:
                self.logger.warning("Continuando con parámetros inconsistentes por decisión del usuario")
                try:
                    checkpoint_logger.log_resume_attempt(resume_data.get('session_id', ''), action='resume_inconsistent_continue', user_choice='interactive')
                except Exception:
                    pass
                return True
            else:
                try:
                    checkpoint_logger.log_resume_attempt(resume_data.get('session_id', ''), action='resume_inconsistent_abort', user_choice='interactive')
                except Exception:
                    pass
                return False
        
        return True
    
    def show_resume_summary(self, resume_data: Dict[str, Any]) -> None:
        """
        Mostrar resumen final antes de iniciar la reanudación.
        
        Args:
            resume_data: Datos de reanudación
        """
        checkpoint = resume_data['checkpoint']
        pending_count = len(resume_data['pending_files'])
        completed_count = len(resume_data['completed_files'])
        
        summary_text = Text()
        summary_text.append("🎯 ", style="bold blue")
        summary_text.append(f"Ruta: {Path(checkpoint.target_path).name}\n", style="white")
        
        if checkpoint.album_name:
            summary_text.append("📁 ", style="bold green")
            summary_text.append(f"Álbum: {checkpoint.album_name}\n", style="white")
        
        summary_text.append("✅ ", style="bold green")
        summary_text.append(f"Ya completados: {completed_count} archivos\n", style="white")
        
        summary_text.append("⏳ ", style="bold yellow")
        summary_text.append(f"Por procesar: {pending_count} archivos\n", style="white")
        
        # Calcular tamaño total pendiente
        total_size = sum(f.stat().st_size for f in resume_data['pending_files'] if f.exists())
        size_mb = total_size / (1024 * 1024)
        
        summary_text.append("💾 ", style="bold cyan")
        summary_text.append(f"Tamaño pendiente: {size_mb:.1f} MB", style="white")
        
        panel = Panel(
            summary_text,
            title="📋 Resumen de Reanudación",
            border_style="blue"
        )
        
        self.console.print(panel)
        self.logger.info(f"Reanudando subida: {pending_count} archivos pendientes, {size_mb:.1f} MB")