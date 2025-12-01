from typing import Literal, Sequence, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from contextlib import nullcontext
import os
import time
import random
import re
import mimetypes
from pathlib import Path
import requests

from rich.console import Group
from rich.live import Live
from rich.progress import (
    SpinnerColumn,
    MofNCompleteColumn,
    DownloadColumn,
    TaskProgressColumn,
    TransferSpeedColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TaskID,
)

from .db import Storage
from .api import Api, DEFAULT_TIMEOUT
from . import utils
from .hash_handler import calculate_sha1_hash, convert_sha1_hash
from .db_update_parser import parse_db_update
from .metadata_cache import MetadataCache
from .album_progress import AlbumProgressTracker
from .detailed_progress import DetailedProgressTracker
from .checkpoint_manager import CheckpointManager
from .resume_manager import ResumeManager
from .interruption_handler import InterruptionHandler
from .enhanced_logging import checkpoint_logger
from .album_validator import album_validator
from .exceptions import UploadRejected

# Make Ctrl+C work for cancelling threads
signal.signal(signal.SIGINT, signal.SIG_DFL)


LogLevel = Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"]


class NullProgress:
    def add_task(self, *args, **kwargs):
        return 0

    def update(self, *args, **kwargs):
        pass

    def reset(self, *args, **kwargs):
        pass

    def open(self, file_path, mode, task_id=None):
        return open(file_path, mode)

# Wrapper para archivo que reporta bytes leídos al DetailedProgressTracker
class ReadProgressWrapper:
    def __init__(self, raw, file_path: Path, tracker: DetailedProgressTracker):
        self._raw = raw
        self._file_path = file_path
        self._tracker = tracker
        self._uploaded = 0

    def read(self, size: int = -1):
        chunk = self._raw.read(size)
        if chunk:
            self._uploaded += len(chunk)
            try:
                # Reportar bytes subidos hasta ahora
                self._tracker.update_file_progress(self._file_path, self._uploaded)
            except Exception:
                pass
        return chunk

    def __getattr__(self, name):
        return getattr(self._raw, name)


class Client:
    """Google Photos client based on reverse engineered mobile API."""

    def __init__(self, auth_data: str = "", proxy: str = "", language: str = "", timeout: int = DEFAULT_TIMEOUT, log_level: LogLevel = "INFO") -> None:
        """
        Google Photos client based on reverse engineered mobile API.

        Args:
            auth_data: Google authentication data string. If not provided, will attempt to use
                      the `GP_AUTH_DATA` environment variable.
            proxy: Proxy url `protocol://username:password@ip:port`.
            language: Accept-Language header value. If not provided, will attempt to parse from auth_data. Fallback value is `en_US`.
            log_level: Logging level to use. Must be one of "INFO", "DEBUG", "WARNING",
                      "ERROR", or "CRITICAL". Defaults to "INFO".
            timeout: Requests timeout, seconds. Defaults to DEFAULT_TIMEOUT.

        Raises:
            ValueError: If no auth_data is provided and GP_AUTH_DATA environment variable is not set.
            requests.HTTPError: If the authentication request fails.
        """
        self.logger = utils.create_logger(log_level)
        self.valid_mimetypes = ["image/", "video/"]
        self.timeout = timeout
        self.auth_data = self._handle_auth_data(auth_data)
        self.language = language or utils.parse_language(self.auth_data) or "en_US"
        email = utils.parse_email(self.auth_data)
        self.logger.info(f"User: {email}")
        self.logger.info(f"Language: {self.language}")
        self.api = Api(self.auth_data, proxy=proxy, language=self.language, timeout=timeout)
        self.cache_dir = Path.home() / ".gpmc" / email
        self.db_path = self.cache_dir / "storage.db"
        self.metadata_cache = MetadataCache(self.cache_dir)
        self._albums_state: dict[str, dict[str, object]] = {}

    def _handle_auth_data(self, auth_data: str | None) -> str:
        """
        Validate and return authentication data.

        Args:
            auth_data: Authentication data string.

        Returns:
            str: Validated authentication data.

        Raises:
            ValueError: If no auth_data is provided and GP_AUTH_DATA environment variable is not set.
        """
        if auth_data:
            return auth_data

        env_auth = os.getenv("GP_AUTH_DATA")
        if env_auth is not None:
            return env_auth

        raise ValueError("`GP_AUTH_DATA` environment variable not set. Create it or provide `auth_data` as an argument.")

    def _upload_file(self, file_path: str | Path, hash_value: bytes | str, progress: Progress, force_upload: bool, use_quota: bool, saver: bool, detailed_tracker: DetailedProgressTracker | None = None) -> dict[str, str]:
        """
        Upload a single file to Google Photos.

        Args:
            file_path: Path to the file to upload, can be string or Path object.
            hash_value: The file's SHA-1 hash, represented as bytes, a hexadecimal string,
                    or a Base64-encoded string.
            progress: Rich Progress object for tracking upload progress.
            force_upload: Whether to upload the file even if it's already present in Google Photos.
            use_quota: Uploaded files will count against your Google Photos storage quota.
            saver: Upload files in storage saver quality.
            detailed_tracker: Detailed tracker to update per-byte progress when available.

        Returns:
            dict[str, str]: A dictionary mapping the absolute file path to its Google Photos media key.

        Raises:
            FileNotFoundError: If the file does not exist.
            IOError: If there are issues reading the file.
            ValueError: If the file is empty or cannot be processed.
        """

        file_path = Path(file_path)
        file_size = file_path.stat().st_size

        file_progress_id = progress.add_task(description="")
        if hash_value:
            hash_bytes, hash_b64 = convert_sha1_hash(hash_value)
        else:
            hash_bytes, hash_b64 = calculate_sha1_hash(file_path, progress, file_progress_id)
        try:
            if not force_upload:
                progress.update(task_id=file_progress_id, description=f"Checking: {file_path.name}")
                if remote_media_key := self.api.find_remote_media_by_hash(hash_bytes):
                    return {file_path.absolute().as_posix(): remote_media_key}

            upload_token = self.api.get_upload_token(hash_b64, file_size)
            progress.reset(task_id=file_progress_id)
            progress.update(task_id=file_progress_id, description=f"Uploading: {file_path.name}")

            if detailed_tracker is not None:
                # Usar wrapper que reporta bytes leídos al tracker detallado
                with open(file_path, "rb") as raw:
                    file_obj = ReadProgressWrapper(raw, file_path, detailed_tracker)
                    upload_response = self.api.upload_file(file=file_obj, upload_token=upload_token)
            else:
                # Fallback: usar progreso tradicional de Rich
                with progress.open(file_path, "rb", task_id=file_progress_id) as file:
                    upload_response = self.api.upload_file(file=file, upload_token=upload_token)

            progress.update(task_id=file_progress_id, description=f"Finalizing Upload: {file_path.name}")
            last_modified_timestamp = int(os.path.getmtime(file_path))
            model = "Pixel XL"
            quality = "original"
            if saver:
                quality = "saver"
                model = "Pixel 2"
            if use_quota:
                model = "Pixel 8"
            media_key = self.api.commit_upload(
                upload_response_decoded=upload_response,
                file_name=file_path.name,
                sha1_hash=hash_bytes,
                upload_timestamp=last_modified_timestamp,
                model=model,
                quality=quality,
            )
            return {file_path.absolute().as_posix(): media_key}
        finally:
            progress.update(file_progress_id, visible=False)

    def get_media_key_by_hash(self, sha1_hash: bytes | str) -> str | None:
        """
        Get a Google Photos media key by media's hash.

        Args:
            sha1_hash: The file's SHA-1 hash, represented as bytes, a hexadecimal string,
                    or a Base64-encoded string.

        Returns:
            str | None: The Google Photos media key if found, otherwise None.
        """
        hash_bytes, _ = convert_sha1_hash(sha1_hash)
        return self.api.find_remote_media_by_hash(
            hash_bytes,
        )

    def _handle_album_creation(self, results: dict[str, str], album_name: str, show_progress: bool) -> None:
        """
        Handle album creation based on the provided album_name.
        - Regular name: all files go into that album.
        - "AUTO": albums created based on folder structure relative to upload root.
        - "AUTO=/custom/path": albums created based on folder structure relative to specified path.
        """
        # Calcular grupos de álbum de forma consistente y descriptiva
        groups = utils.compute_album_groups(results, album_name)
        self.logger.info(f"Álbumes calculados ({len(groups)}): {', '.join(groups.keys())}")

        # Validar nombres de álbum antes de crear
        album_names = list(groups.keys())
        validation_results = album_validator.validate_album_names_batch(album_names)
        
        # Registrar resultados de validación
        album_validator.log_validation_results(album_names)
        
        # Aplicar sanitización a nombres inválidos
        sanitized_groups = {}
        name_mapping = {}  # original -> sanitized
        
        for original_name, media_keys in groups.items():
            is_valid, errors, sanitized_name = validation_results[original_name]
            
            if not is_valid:
                self.logger.warning(f"Nombre de álbum inválido: '{original_name}' -> '{sanitized_name}'")
                for error in errors:
                    self.logger.warning(f"  - {error}")
            
            sanitized_groups[sanitized_name] = media_keys
            name_mapping[original_name] = sanitized_name

        # Invertir mapeo para conocer álbum por media_key (usando nombres sanitizados)
        inverse: dict[str, str] = {}
        for name, keys in sanitized_groups.items():
            for key in keys:
                inverse[key] = name

        # Persistir carpeta→álbum para mantener consistencia con archivos añadidos posteriormente
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        try:
            with Storage(self.db_path) as storage:
                for file_path, media_key in results.items():
                    folder = Path(file_path).parent.resolve()
                    album = inverse.get(media_key)
                    if album:
                        storage.set_album_mapping(folder, album)
                        self.logger.debug(f"Mapeado carpeta→álbum: '{folder}' → '{album}'")
        except Exception as e:
            self.logger.warning(f"No se pudo persistir mapeos de álbum: {e}")

        # Crear álbumes en orden jerárquico (padres antes que hijos) usando nombres sanitizados
        for name in sorted(sanitized_groups.keys(), key=lambda x: x.count("/")):
            self.logger.info(f"Creando/actualizando álbum: {name} con {len(sanitized_groups[name])} elementos")
            self.add_to_album(sanitized_groups[name], name, show_progress=show_progress)

    def _filter_files(self, expression: str, filter_exclude: bool, filter_regex: bool, filter_ignore_case: bool, filter_path: bool, paths: list[Path]) -> list[Path]:
        """
        Filter a list of Path objects based on a filter expression.

        Args:
            expression: The filter expression to match against.
            filter_exclude: If True, exclude matching files.
            filter_regex: If True, treat expression as regex.
            filter_ignore_case: If True, perform case-insensitive matching.
            filter_path: If True, check full path instead of just filename.
            paths: List of Path objects to filter.

        Returns:
            list[Path]: Filtered list of Path objects.
        """
        filtered_paths = []

        for path in paths:
            text_to_check = str(path) if filter_path else str(path.name)

            if filter_regex:
                flags = re.IGNORECASE if filter_ignore_case else 0
                matches = bool(re.search(expression, text_to_check, flags))
            else:
                if filter_ignore_case:
                    matches = expression.lower() in text_to_check.lower()
                else:
                    matches = expression in text_to_check

            if (matches and not filter_exclude) or (not matches and filter_exclude):
                filtered_paths.append(path)

        return filtered_paths

    def upload(
        self,
        target: str | Path | Sequence[str | Path] | Mapping[Path, bytes | str],
        album_name: str | None = None,
        use_quota: bool = False,
        saver: bool = False,
        recursive: bool = False,
        show_progress: bool = False,
        threads: int = 1,
        force_upload: bool = False,
        delete_from_host: bool = False,
        filter_exp: str = "",
        filter_exclude: bool = False,
        filter_regex: bool = False,
        filter_ignore_case: bool = False,
        filter_path: bool = False,
        resume_session: str | None = None,
        resume: bool = False,
        restart: bool = False,
    ) -> dict[str, str]:
        """
        Upload one or more files or directories to Google Photos.

        Args:
            target: A file path, directory path, a sequence of such paths, or a mapping of file paths to their SHA-1 hashes.
            album_name:
                If provided, the uploaded media will be added to a new album.
                If set to "AUTO", albums will be created based on the immediate parent directory of each file.

                "AUTO" Example:
                    - When uploading '/foo':
                        - '/foo/image1.jpg' will be placed in a 'foo' album.
                        - '/foo/bar/image2.jpg' will be placed in a 'bar' album.
                        - '/foo/bar/foo/image3.jpg' will be placed in a 'foo' album, distinct from the first 'foo' album.

                Defaults to None.
            use_quota: Uploaded files will count against your Google Photos storage quota. Defaults to False.
            saver: Upload files in storage saver quality. Defaults to False.
            recursive: Whether to recursively search for media files in subdirectories.
                                Only applies when uploading directories. Defaults to False.
            show_progress: Whether to display upload progress in the console. Defaults to False.
            threads: Number of concurrent upload threads for multiple files. Defaults to 1.
            force_upload: Whether to upload files even if they're already present in
                                Google Photos (based on hash). Defaults to False.
            delete_from_host: Whether to delete the file from the host after successful upload.
                                    Defaults to False.
            filter_exp: The filter expression to match against filenames or paths.
            filter_exclude: If True, exclude files matching the filter.
            filter_regex: If True, treat the expression as a regular expression.
            filter_ignore_case: If True, perform case-insensitive matching.
            filter_path: If True, check for matches in the full path instead of just the filename.
            resume_session: If provided, resume from a specific checkpoint session ID.
                          If None, the system will automatically detect interrupted uploads.

        Returns:
            dict[str, str]: A dictionary mapping absolute file paths to their Google Photos media keys.
                            Example: {
                                "/path/to/photo1.jpg": "media_key_123",
                                "/path/to/photo2.jpg": "media_key_456"
                            }

        Raises:
            TypeError: If `target` is not a file path, directory path, or a squence of such paths.
            ValueError: If no valid media files are found to upload.
        """
        # Inicializar gestores de checkpoint y reanudación
        # Usar directorio específico del usuario para los checkpoints
        checkpoint_dir = self.cache_dir / "checkpoints"
        checkpoint_manager = CheckpointManager(checkpoint_dir=checkpoint_dir)
        
        # Configurar manejador de interrupciones
        interruption_handler = InterruptionHandler(checkpoint_manager)
        
        resume_manager = ResumeManager(checkpoint_manager)
        
        # Determinar la ruta objetivo para detección de interrupciones
        target_path = str(target) if isinstance(target, (str, Path)) else str(list(target)[0] if target else "")
        
        # Verificar si hay subidas interrumpidas (controlado por flags)
        resume_data = None
        if restart:
            # Forzar reinicio: ignorar checkpoints
            self.logger.info("Reinicio forzado: ignorando checkpoints existentes")
        elif resume_session:
            # Reanudación manual con session ID específico
            resume_data = resume_manager.prepare_resume_data(resume_session)
            if not resume_data:
                raise ValueError(f"No se pudo cargar la sesión de reanudación: {resume_session}")
        elif resume:
            # Reanudación automática sin interacción
            interrupted_sessions = resume_manager.check_for_interrupted_uploads(target_path, album_name)
            if interrupted_sessions:
                # Elegir la sesión más reciente
                last_updated_map = {}
                for sid in interrupted_sessions:
                    cp = checkpoint_manager.load_checkpoint(sid)
                    if cp:
                        last_updated_map[sid] = cp.last_updated
                selected_session = max(last_updated_map, key=last_updated_map.get) if last_updated_map else interrupted_sessions[0]
                self.logger.info(f"Reanudando automáticamente sesión: {selected_session}")
                resume_data = resume_manager.prepare_resume_data(selected_session)
                if not resume_data:
                    self.logger.error(f"Error al preparar datos de reanudación para: {selected_session}")
                    return {}
        else:
            # Detección automática con interacción (modo por defecto)
            interrupted_sessions = resume_manager.check_for_interrupted_uploads(target_path, album_name)
            
            if interrupted_sessions:
                resume_manager.display_interrupted_uploads(interrupted_sessions)
                action, selected_session = resume_manager.prompt_user_action(interrupted_sessions)
                
                if action == 'cancel':
                    return {}
                elif action == 'resume' and selected_session:
                    resume_data = resume_manager.prepare_resume_data(selected_session)
                    if not resume_data:
                        self.logger.error(f"Error al preparar datos de reanudación para: {selected_session}")
                        return {}
                # Si action == 'restart', continuar con el flujo normal
        
        # Si hay datos de reanudación, validar consistencia
        if resume_data:
            current_params = {
                'album_name': album_name,
                'use_quota': use_quota,
                'saver': saver,
                'threads': threads,
                'force_upload': force_upload,
                'delete_from_host': delete_from_host
            }
            
            # En modo CLI (--resume o --resume-session), no interactuar
            non_interactive_mode = bool(resume or resume_session)
            if not resume_manager.validate_resume_consistency(
                resume_data,
                current_params,
                non_interactive=non_interactive_mode,
                continue_on_inconsistency=False,
            ):
                self.logger.error("Parámetros inconsistentes, cancelando reanudación")
                return {}
            
            resume_manager.show_resume_summary(resume_data)
            # Registrar intento de reanudación en logs mejorados
            try:
                checkpoint_logger.log_resume_attempt(resume_data['session_id'], action='resume', user_choice='cli' if non_interactive_mode else 'interactive')
            except Exception:
                pass
            
            # Usar datos del checkpoint para la reanudación
            path_hash_pairs = {f: b'' for f in resume_data['pending_files']}  # Hash se calculará después
            checkpoint_manager.current_checkpoint = resume_data['checkpoint']
            
            # Crear mapeo de archivos a álbumes desde el checkpoint
            file_album_mapping = resume_data['checkpoint'].file_album_mapping or {}
        else:
            # Flujo normal: procesar target input
            path_hash_pairs = self._handle_target_input(
                target,
                recursive,
                filter_exp,
                filter_exclude,
                filter_regex,
                filter_ignore_case,
                filter_path,
            )
            
            # Crear mapeo de archivos a álbumes si se especifica album_name
            file_album_mapping = {}
            if album_name:
                if album_name.startswith("AUTO"):
                    # Usar compute_album_groups de forma previa con placeholders para derivar nombre de álbum por archivo
                    placeholder_results = {str(p): str(p) for p in path_hash_pairs.keys()}
                    groups = utils.compute_album_groups(placeholder_results, album_name)
                    for album, file_list in groups.items():
                        for file_path_str in file_list:
                            file_album_mapping[Path(file_path_str)] = album
                else:
                    for file_path in path_hash_pairs.keys():
                        file_album_mapping[file_path] = album_name
            else:
                # Intentar recuperar mapeo de álbumes previos desde la base de datos
                try:
                    with Storage(self.db_path) as storage:
                        for file_path in path_hash_pairs.keys():
                            folder = file_path.parent.resolve()
                            if saved_album_info := storage.get_album_mapping(folder):
                                # saved_album_info es (nombre, id)
                                file_album_mapping[file_path] = saved_album_info[0]
                except Exception as e:
                    self.logger.warning(f"No se pudo recuperar mapeo de álbumes: {e}")
        
        # Registrar callback de emergencia para guardar checkpoint en interrupciones
        def _save_on_interrupt():
            try:
                interruption_handler.emergency_save()
            except Exception:
                pass
        interruption_handler.add_cleanup_callback(_save_on_interrupt)

        # Inicializar estado de álbumes para adición inmediata
        self._albums_state = {}

        results = self._upload_persistently(
            path_hash_pairs,
            threads=threads,
            show_progress=show_progress,
            force_upload=force_upload,
            use_quota=use_quota,
            saver=saver,
            file_album_mapping=file_album_mapping,
            checkpoint_manager=checkpoint_manager,
            interruption_handler=interruption_handler,
            album_name=album_name,
        )

        # La adición al álbum ya ocurre inmediatamente durante la subida

        if delete_from_host:
            for file_path, _ in results.items():
                self.logger.info(f"{file_path} deleting from host")
                os.remove(file_path)
        return results

    def _handle_target_input(
        self,
        target: str | Path | Sequence[str | Path] | Mapping[Path, bytes | str],
        recursive: bool,
        filter_exp: str,
        filter_exclude: bool,
        filter_regex: bool,
        filter_ignore_case: bool,
        filter_path: bool,
    ) -> Mapping[Path, bytes | str]:
        """
        Process and validate the upload target input into a consistent path-hash mapping.

        Args:
            target: A file path, directory path, sequence of paths, or mapping of paths to hashes.
            recursive: Whether to search directories recursively for media files.
            filter_exp: The filter expression to match against filenames or paths.
            filter_exclude: If True, exclude files matching the filter.
            filter_regex: If True, treat the expression as a regular expression.
            filter_ignore_case: If True, perform case-insensitive matching.
            filter_path: If True, check for matches in the full path instead of just the filename.

        Returns:
            Mapping[Path, bytes | str]: A dictionary mapping file paths to their SHA-1 hashes.
                                    Files without precomputed hashes will have empty bytes (b"").

        Raises:
            TypeError: If `target` is not a valid path, sequence of paths, or path-to-hash mapping.
            ValueError: If no valid media files are found or if filtering leaves no files to upload.
        """
        path_hash_pairs: Mapping[Path, bytes | str] = {}
        if isinstance(target, (str, Path)):
            target = [target]

        if isinstance(target, Sequence) and all(isinstance(p, (str, Path)) for p in target):
            # Expand all paths to a flat list of files
            files_to_upload = [file for path in target for file in self._search_for_media_files(path, recursive=recursive)]

            if not files_to_upload:
                raise ValueError("No valid media files found to upload.")

            if filter_exp:
                files_to_upload = self._filter_files(filter_exp, filter_exclude, filter_regex, filter_ignore_case, filter_path, files_to_upload)

            if not files_to_upload:
                raise ValueError("No media files left after filtering.")

            path_hash_pairs = {path: b"" for path in files_to_upload}  # empty hash values to be calculated later

        elif isinstance(target, dict) and all(isinstance(k, Path) and isinstance(v, (bytes, str)) for k, v in target.items()):
            path_hash_pairs = target
        else:
            raise TypeError("`target` must be a file path, a directory path, or a sequence of such paths.")
            
        return path_hash_pairs

    def _search_for_media_files(self, path: str | Path, recursive: bool) -> list[Path]:
        """
        Search for valid media files in the specified path.

        Args:
            path: File or directory path to search for media files.
            recursive: Whether to search subdirectories recursively. Only applies
                             when path is a directory.

        Returns:
            list[Path]: List of Path objects pointing to valid media files.

        Raises:
            ValueError: If the path is invalid, or if no valid media files are found,
                       or if a single file's mime type is not supported.
        """
        path = Path(path)

        if path.is_file():
            if any(mimetype_guess is not None and mimetype_guess.startswith(mimetype) 
                   for mimetype in self.valid_mimetypes 
                   if (mimetype_guess := mimetypes.guess_type(path)[0])):
                return [path]
            raise ValueError("File's mime type does not match image or video mime type.")

        if not path.is_dir():
            raise ValueError("Invalid path. Please provide a file or directory path.")

        files = []
        if recursive:
            for root, _, filenames in os.walk(path):
                for filename in filenames:
                    file_path = Path(root) / filename
                    files.append(file_path)
        else:
            files = [file for file in path.iterdir() if file.is_file()]

        if len(files) == 0:
            raise ValueError("No files in the directory.")

        media_files = [
            file for file in files 
            if any(mimetype_guess is not None and mimetype_guess.startswith(mimetype) 
                  for mimetype in self.valid_mimetypes 
                  if (mimetype_guess := mimetypes.guess_type(file)[0]))
        ]

        if len(media_files) == 0:
            raise ValueError("No files in the directory matched image or video mime types")

        return media_files

    def _calculate_hash(self, file_path: Path, progress: Progress) -> tuple[Path, bytes]:
        # Verificar si el hash está en cache
        cached_hash = self.metadata_cache.get_cached_hash(file_path)
        if cached_hash:
            self.logger.debug(f"Hash cacheado encontrado para: {file_path.name}")
            return file_path, bytes.fromhex(cached_hash)
        
        # Calcular hash si no está en cache
        hash_calc_progress_id = progress.add_task(description="Calculating hash")
        try:
            hash_bytes, _ = calculate_sha1_hash(file_path, progress, hash_calc_progress_id)
            # Cachear el hash calculado
            hash_hex = hash_bytes.hex()
            self.metadata_cache.cache_file_metadata(file_path, hash_hex)
            self.logger.debug(f"Hash calculado y cacheado para: {file_path.name}")
            return file_path, hash_bytes
        finally:
            progress.update(hash_calc_progress_id, visible=False)

    def _is_permanent_error(self, error: Exception) -> bool:
        """Determina si un error es permanente y no debe ser reintentado."""
        if isinstance(error, requests.exceptions.HTTPError):
            if error.response is not None:
                status_code = error.response.status_code
                # 429 (Too Many Requests) y 5xx son temporales
                if status_code == 429 or 500 <= status_code < 600:
                    return False
                # 401/403 requieren intervención (auth), 400 es error de petición
                if status_code in (400, 401, 403, 404):
                    return True
        
        if isinstance(error, UploadRejected):
            return True
            
        # Errores de conexión, timeouts, etc., se asumen temporales
        return False

    def _upload_file_with_retry(self, file_path: Path, hash_value: bytes | str, progress: Progress, force_upload: bool, use_quota: bool, saver: bool, detailed_tracker: DetailedProgressTracker | None = None) -> dict[str, str]:
        """Sube un archivo con reintentos y backoff exponencial con jitter.
        Clasifica errores permanentes para no reintentar inútilmente.
        """
        max_attempts = 10
        base_delay = 1.0  # segundos
        max_delay = 30.0
        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                result = self._upload_file(file_path, hash_value, progress, force_upload, use_quota, saver, detailed_tracker)
                # Éxito: cache y retorno
                for fp, mk in result.items():
                    self.metadata_cache.update_upload_status(Path(fp), "success", media_key=mk)
                    # Actualizar progreso detallado si está disponible
                    if detailed_tracker:
                        detailed_tracker.update_file_progress(file_path, 100.0)
                return result
            except Exception as e:
                last_error = e
                # Registro detallado del intento
                self.logger.warning(f"Intento {attempt}/{max_attempts} fallido para {file_path}: {e}")
                # Si es error permanente no reintentamos
                if self._is_permanent_error(e):
                    self.metadata_cache.update_upload_status(file_path, "failed")
                    self.logger.error(f"Error permanente para {file_path}: {e}")
                    raise e
                # Backoff exponencial con jitter
                if attempt < max_attempts:
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    jitter = random.uniform(0, delay * 0.25)
                    wait_time = delay + jitter
                    self.logger.info(f"Reintentando {file_path} tras {wait_time:.2f}s (backoff)")
                    time.sleep(wait_time)
                else:
                    break
        # Agotar reintentos: marcar y propagar último error
        self.metadata_cache.update_upload_status(file_path, "failed")
        self.logger.error(f"Fallo definitivo tras {max_attempts} intentos para {file_path}")
        assert last_error is not None
        raise last_error
    def _add_immediate_to_album(self, file_path: Path, media_key: str, target_album: str) -> None:
        """Añade inmediatamente el media a un álbum. Crea el álbum si no existe.
        Maneja límite de elementos por álbum creando sufijos (Album, Album 2, ...).
        """
        base_name = album_validator.sanitize_album_name(utils.sanitize_album_name(target_album))
        state = self._albums_state.get(base_name)
        album_limit = 20000  # límite aproximado por álbum
        if not state:
            # Intentar recuperar ID de álbum existente para evitar duplicados
            saved_id = None
            try:
                with Storage(self.db_path) as storage:
                    mapping = storage.get_album_mapping(file_path.parent.resolve())
                    if mapping and mapping[0] == base_name:
                        saved_id = mapping[1]
            except Exception:
                pass

            if saved_id:
                # Reutilizar álbum existente
                self._albums_state[base_name] = {
                    "album_key": saved_id,
                    "current_album_name": base_name,
                    "count": 1,
                    "suffix_index": 1,
                }
                self.api.add_media_to_album(saved_id, [media_key])
                self.logger.info(f"Agregado {file_path} al álbum existente '{base_name}'")
            else:
                # Crear álbum con el primer elemento
                created_key = self.api.create_album(base_name, [media_key])
                self._albums_state[base_name] = {
                    "album_key": created_key,
                    "current_album_name": base_name,
                    "count": 1,
                    "suffix_index": 1,
                }
                self.logger.info(f"Creado álbum '{base_name}' y agregado {file_path}")
        else:
            count = int(state.get("count", 0))
            if count >= album_limit:
                # Abrir nuevo álbum con sufijo
                suffix_index = int(state.get("suffix_index", 1)) + 1
                new_name = f"{base_name} {suffix_index}"
                created_key = self.api.create_album(new_name, [media_key])
                state.update({
                    "album_key": created_key,
                    "current_album_name": new_name,
                    "count": 1,
                    "suffix_index": suffix_index,
                })
                self.logger.info(f"Límite alcanzado. Creado álbum '{new_name}' y agregado {file_path}")
            else:
                self.api.add_media_to_album(state["album_key"], [media_key])
                state["count"] = count + 1
                self.logger.info(f"Agregado {file_path} al álbum '{state['current_album_name']}'")
        
        # Persistir asociación del directorio
        try:
            with Storage(self.db_path) as storage:
                current_key = self._albums_state[base_name]["album_key"]
                storage.set_album_mapping(str(file_path.parent.resolve()), base_name, current_key)
        except Exception:
            pass
    def _upload_concurrently(
        self,
        path_hash_pairs: Mapping[Path, bytes | str],
        threads: int,
        show_progress: bool,
        force_upload: bool,
        use_quota: bool,
        saver: bool,
        file_album_mapping: dict[Path, str] | None = None,
        detailed_tracker: DetailedProgressTracker | None = None,
    ) -> tuple[dict[str, str], list[Path], list[Path]]:
        """Subida concurrente de archivos.
        Retorna (resultados, fallos_temporales, fallos_permanentes).
        Añade a álbum inmediatamente en cada subida exitosa.
        """
        results: dict[str, str] = {}
        temporary_failures: list[Path] = []
        permanent_failures: list[Path] = []

        # Inicializar progress como None para evitar UnboundLocalError
        progress = None

        # Usar el sistema de progreso detallado si está disponible
        if detailed_tracker and show_progress:
            progress_group = detailed_tracker.get_progress_layout()
        else:
            # Progreso tradicional como fallback
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Subiendo"),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) if show_progress else None

            # Progreso por álbum si se proporciona mapeo
            album_tracker = AlbumProgressTracker(show_progress=True) if (show_progress and file_album_mapping) else None
            if album_tracker:
                album_tracker.initialize_albums(file_album_mapping)

            progress_group = album_tracker.get_progress_group() if album_tracker else Group(progress if progress else Group())

        main_task: TaskID | None = None
        hash_task: TaskID | None = None
        upload_task: TaskID | None = None

        with Live(
            progress_group,
            refresh_per_second=10,
            transient=True,
        ) if show_progress else nullcontext():
            # Configurar progreso tradicional si no hay sistema detallado
            if not detailed_tracker and progress:
                main_task = progress.add_task("Preparando archivos", total=len(path_hash_pairs))
                hash_task = progress.add_task("Calculando hash", total=len(path_hash_pairs))
                upload_task = progress.add_task("Subiendo", total=len(path_hash_pairs))
            
            # Usar Progress nulo si no hay interfaz de progreso visual
            progress_ops = progress if progress is not None else NullProgress()
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for file_path, hash_value in path_hash_pairs.items():
                    # Marcar inicio de subida en el sistema detallado
                    if detailed_tracker:
                        detailed_tracker.start_file_upload(file_path)
                    
                    future = executor.submit(
                        self._upload_file_with_retry,
                        file_path,
                        hash_value,
                        progress_ops,
                        force_upload,
                        use_quota,
                        saver,
                        detailed_tracker,
                    )
                    futures[future] = file_path
                
                for future in as_completed(futures):
                    file_path = futures[future]
                    if not detailed_tracker and progress and main_task is not None:
                        progress.update(main_task, advance=1)
                    
                    try:
                        result = future.result()
                        for fp_str, media_key in result.items():
                            results[fp_str] = media_key
                            if not detailed_tracker and progress and upload_task is not None:
                                progress.update(upload_task, advance=1)
                            
                            # Marcar éxito en el sistema detallado
                            if detailed_tracker:
                                detailed_tracker.complete_file_upload(file_path, success=True)
                            
                            # Añadir a álbum inmediatamente si corresponde
                            if file_album_mapping and file_path in file_album_mapping:
                                try:
                                    self._add_immediate_to_album(file_path, media_key, file_album_mapping[file_path])
                                    if not detailed_tracker and album_tracker:
                                        album_tracker.update_file_progress(file_path, file_album_mapping[file_path], success=True)
                                except Exception as add_err:
                                    # La adición al álbum falló: clasificar para logging, pero no detener
                                    if self._is_permanent_error(add_err):
                                        self.logger.error(f"Error permanente al agregar a álbum: {add_err}")
                                        if not detailed_tracker and album_tracker:
                                            album_tracker.update_file_progress(file_path, file_album_mapping[file_path], success=False)
                                    else:
                                        self.logger.warning(f"Error temporal al agregar a álbum: {add_err}")
                                        if not detailed_tracker and album_tracker:
                                            album_tracker.update_file_progress(file_path, file_album_mapping[file_path], success=False)
                    except Exception as e:
                        # Marcar fallo en el sistema detallado
                        if detailed_tracker:
                            detailed_tracker.complete_file_upload(file_path, success=False, error_message=str(e))
                        
                        # Clasificar tipo de fallo
                        if self._is_permanent_error(e):
                            permanent_failures.append(file_path)
                            self.logger.error(f"Fallo permanente: {file_path} -> {e}")
                            if not detailed_tracker and album_tracker and file_album_mapping and file_path in file_album_mapping:
                                album_tracker.update_file_progress(file_path, file_album_mapping[file_path], success=False)
                        else:
                            temporary_failures.append(file_path)
                            self.logger.warning(f"Fallo temporal: {file_path} -> {e}")
                            if not detailed_tracker and album_tracker and file_album_mapping and file_path in file_album_mapping:
                                album_tracker.update_file_progress(file_path, file_album_mapping[file_path], success=False)
        return results, temporary_failures, permanent_failures
    def _upload_persistently(
        self,
        path_hash_pairs: Mapping[Path, bytes | str],
        threads: int,
        show_progress: bool,
        force_upload: bool,
        use_quota: bool,
        saver: bool,
        file_album_mapping: dict[Path, str] | None = None,
        checkpoint_manager: CheckpointManager | None = None,
        interruption_handler: InterruptionHandler | None = None,
        album_name: str | None = None,
    ) -> dict[str, str]:
        """Orquesta rondas de subida y reintento hasta completar todos los archivos no permanentes."""
        remaining: dict[Path, bytes | str] = dict(path_hash_pairs)
        all_results: dict[str, str] = {}
        round_index = 0
        start_time = time.time()
        try:
            total_size = sum(Path(fp).stat().st_size for fp in path_hash_pairs.keys())
        except Exception:
            total_size = 0
        
        # Crear sistema de progreso detallado si se requiere
        detailed_tracker = None
        if show_progress and file_album_mapping:
            detailed_tracker = DetailedProgressTracker(show_progress=True, compact_mode=True)
            detailed_tracker.initialize_files(file_album_mapping)
        
        # Inicializar checkpoint si se proporciona
        if checkpoint_manager and not checkpoint_manager.current_checkpoint:
            # Crear nuevo checkpoint para esta sesión
            upload_params = {
                'album_name': file_album_mapping.get(list(file_album_mapping.keys())[0]) if file_album_mapping else None,
                'use_quota': use_quota,
                'saver': saver,
                'threads': threads,
                'force_upload': force_upload
            }
            
            target_path = str(list(path_hash_pairs.keys())[0].parent) if path_hash_pairs else ""
            checkpoint_manager.create_checkpoint(
                target_path=target_path,
                album_name=album_name,
                upload_params=upload_params,
                file_paths=list(path_hash_pairs.keys())
            )

            # Optimización: Verificar historial local para saltar archivos ya subidos (Deduplicación local)
            self.logger.info("Verificando historial local para archivos ya subidos...")
            history_map = checkpoint_manager.get_history_map()
            skipped_count = 0
            
            for file_path in list(remaining.keys()):
                abs_path = str(file_path.absolute())
                if abs_path in history_map:
                    media_key, size = history_map[abs_path]
                    try:
                        current_size = file_path.stat().st_size
                        # Verificar tamaño para mayor seguridad (evitar falsos positivos si el archivo cambió)
                        if current_size == size:
                            # Marcar como completado
                            all_results[file_path.absolute().as_posix()] = media_key
                            checkpoint_manager.update_file_progress(file_path, 'completed', media_key=media_key)
                            
                            # Añadir al álbum si es necesario (ya que saltamos la subida)
                            if file_album_mapping and file_path in file_album_mapping:
                                try:
                                    self._add_immediate_to_album(file_path, media_key, file_album_mapping[file_path])
                                except Exception as e:
                                    self.logger.warning(f"Error añadiendo archivo histórico al álbum: {e}")

                            del remaining[file_path]
                            skipped_count += 1
                    except Exception:
                        # Si hay error leyendo archivo (borrado, etc), dejar que el proceso normal lo maneje
                        pass
                        
            if skipped_count > 0:
                self.logger.info(f"✅ Saltados {skipped_count} archivos encontrados en historial local (ya subidos)")
        
        while remaining:
            round_index += 1
            self.logger.info(f"Ronda {round_index}: {len(remaining)} archivos por subir")
            results, temp_failures, perm_failures = self._upload_concurrently(
                remaining,
                threads=threads,
                show_progress=show_progress,
                force_upload=force_upload,
                use_quota=use_quota,
                saver=saver,
                file_album_mapping=file_album_mapping,
                detailed_tracker=detailed_tracker,
            )
            all_results.update(results)
            
            # Actualizar checkpoint con resultados de esta ronda
            if checkpoint_manager:
                for file_path, media_key in results.items():
                    checkpoint_manager.update_file_progress(Path(file_path), 'completed', media_key)
                
                for failed_file in perm_failures:
                    checkpoint_manager.update_file_progress(failed_file, 'failed', error="Fallo permanente")
            
            # Guardar checkpoint de progreso mediante manejador de interrupciones
            if interruption_handler:
                try:
                    round_completed = [Path(fp) for fp in results.keys()]
                    round_failed = list(set(temp_failures + perm_failures))
                    interruption_handler.create_progress_checkpoint(round_completed, round_failed)
                except Exception:
                    pass
            
            # Remover éxitos y fallos permanentes del conjunto restante
            succeeded_paths = {Path(fp) for fp in results.keys()}
            remaining = {fp: hv for fp, hv in remaining.items() if fp not in succeeded_paths and fp not in set(perm_failures)}

            # Feedback claro de ronda
            self.logger.info(
                f"Ronda {round_index} resumen: éxitos={len(results)}, temporales={len(temp_failures)}, permanentes={len(perm_failures)}"
            )

            if not temp_failures:
                break
            
            # Backoff entre rondas para aliviar presión al API
            delay = min(60.0, 2.0 * (2 ** (round_index - 1)))
            jitter = random.uniform(0, delay * 0.25)
            wait_time = delay + jitter
            self.logger.info(f"Esperando {wait_time:.2f}s antes de la siguiente ronda de reintentos")
            time.sleep(wait_time)
            
            # Preparar siguiente ronda con sólo temporales
            remaining = {fp: path_hash_pairs[fp] for fp in temp_failures if fp in path_hash_pairs}
        
        # Mostrar estadísticas finales si hay progreso detallado
        if detailed_tracker:
            detailed_tracker.log_final_summary()
        
        # Finalizar checkpoint si se completó la subida
        if checkpoint_manager:
            if not remaining:  # Todos los archivos procesados
                checkpoint_manager.mark_upload_complete()
                self.logger.info("✅ Subida completada - Checkpoint marcado como finalizado")
            else:
                self.logger.info(f"⏸️  Subida pausada - {len(remaining)} archivos pendientes guardados en checkpoint")
        
        # Logging mejorado de resumen de subida
        try:
            session_id = checkpoint_manager.current_checkpoint.session_id if checkpoint_manager and checkpoint_manager.current_checkpoint else ""
            total_files = len(path_hash_pairs)
            completed = len(all_results)
            failed = max(0, total_files - completed - len(remaining))
            skipped = 0
            total_time = time.time() - start_time
            checkpoint_logger.log_upload_summary(session_id, total_files, completed, failed, skipped, total_time, total_size)
        except Exception:
            pass
        
        return all_results

    def move_to_trash(self, sha1_hashes: str | bytes | Sequence[str | bytes]) -> dict:
        """
        Move remote media files to trash.

        Args:
            sha1_hashes: Single SHA-1 hash or sequence of hashes to move to trash.

        Returns:
            dict: API response containing operation results.

        Raises:
            ValueError: If input hashes are invalid.
        """

        if isinstance(sha1_hashes, (str, bytes)):
            sha1_hashes = [sha1_hashes]

        try:
            # Convert all hashes to Base64 format
            hashes_b64 = [convert_sha1_hash(hash)[1] for hash in sha1_hashes]  # type: ignore
            dedup_keys = [utils.urlsafe_base64(hash) for hash in hashes_b64]
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid SHA-1 hash format") from e

        # Process in batches of 500 to avoid API limits
        batch_size = 500
        response = {}
        for i in range(0, len(dedup_keys), batch_size):
            batch = dedup_keys[i : i + batch_size]
            batch_response = self.api.move_remote_media_to_trash(dedup_keys=batch)
            response.update(batch_response)  # Combine responses if needed

        return response

    def add_to_album(self, media_keys: Sequence[str], album_name: str, show_progress: bool) -> list[str]:
        """
        Add media items to one or more albums with the given name. If the total number of items exceeds the album limit,
        additional albums with numbered suffixes are created. The first album will also have a suffix if there are multiple albums.

        Args:
            media_keys: Media keys of the media items to be added to album.
            album_name: Album name.
            show_progress : Whether to display upload progress in the console.

        Returns:
            list[str]: Album media keys for all created albums.

        Raises:
            requests.HTTPError: If the API request fails.
            ValueError: If media_keys is empty.
        """
        album_limit = 20000  # Maximum number of items per album
        batch_size = 500  # Number of items to process per API call
        album_keys = []
        album_counter = 1

        if len(media_keys) > album_limit:
            self.logger.warning(f"{len(media_keys)} items exceed the album limit of {album_limit}. They will be split into multiple albums.")

        # Initialize progress bar
        progress = Progress(
            TextColumn("{task.description}"),
            SpinnerColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        )
        task = progress.add_task(f"[bold yellow]Adding items to album[/bold yellow] [cyan]{album_name}[/cyan]:", total=len(media_keys))

        context = (show_progress and Live(progress)) or nullcontext()

        with context:
            for i in range(0, len(media_keys), album_limit):
                album_batch = media_keys[i : i + album_limit]
                # Add a suffix if media_keys will not fit into a single album
                current_album_name = f"{album_name} {album_counter}" if len(media_keys) > album_limit else album_name
                current_album_key = None
                for j in range(0, len(album_batch), batch_size):
                    batch = album_batch[j : j + batch_size]
                    if current_album_key is None:
                        # Create the album with the first batch
                        current_album_key = self.api.create_album(album_name=current_album_name, media_keys=batch)
                        album_keys.append(current_album_key)
                    else:
                        # Add to the existing album
                        self.api.add_media_to_album(album_media_key=current_album_key, media_keys=batch)
                    progress.update(task, advance=len(batch))
                album_counter += 1
        return album_keys

    def update_cache(self, show_progress: bool = True):
        """
        Incrementally update local library cache.

        Args:
            show_progress: Whether to display progress in console.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        progress = Progress(
            TextColumn("{task.description}"),
            SpinnerColumn(),
            "Updates: [green]{task.fields[updated]:>8}[/green]",
            "Deletions: [red]{task.fields[deleted]:>8}[/red]",
        )
        task_id = progress.add_task(
            "[bold magenta]Updating local cache[/bold magenta]:",
            updated=0,
            deleted=0,
        )
        context = (show_progress and Live(progress)) or nullcontext()

        with context:
            # Get saved state tokens
            with Storage(self.db_path) as storage:
                init_state = storage.get_init_state()

            if not init_state:
                self.logger.info("Cache Initiation")
                self._cache_init(progress, task_id)
                with Storage(self.db_path) as storage:
                    storage.set_init_state(1)
            self.logger.info("Cache Update")
            self._cache_update(progress, task_id)

    def _cache_update(self, progress, task_id):
        with Storage(self.db_path) as storage:
            state_token, _ = storage.get_state_tokens()
        response = self.api.get_library_state(state_token)
        next_state_token, next_page_token, remote_media, media_keys_to_delete = parse_db_update(response)

        with Storage(self.db_path) as storage:
            storage.update_state_tokens(next_state_token, next_page_token)
            storage.update(remote_media)
            storage.delete(media_keys_to_delete)

        task = progress.tasks[int(task_id)]
        progress.update(
            task_id,
            updated=task.fields["updated"] + len(remote_media),
            deleted=task.fields["deleted"] + len(media_keys_to_delete),
        )

        if next_page_token:
            self._process_pages(progress, task_id, state_token, next_page_token)

    def _cache_init(self, progress, task_id):
        with Storage(self.db_path) as storage:
            state_token, next_page_token = storage.get_state_tokens()

        if next_page_token:
            self._process_pages_init(progress, task_id, next_page_token)

        response = self.api.get_library_state(state_token)
        state_token, next_page_token, remote_media, _ = parse_db_update(response)

        with Storage(self.db_path) as storage:
            storage.update_state_tokens(state_token, next_page_token)
            storage.update(remote_media)

        task = progress.tasks[int(task_id)]
        progress.update(
            task_id,
            updated=task.fields["updated"] + len(remote_media),
        )

        if next_page_token:
            self._process_pages_init(progress, task_id, next_page_token)

    def _process_pages_init(self, progress: Progress, task_id: TaskID, page_token: str):
        """
        Process paginated results during cache update.

        Args:
            progress: Rich Progress object for tracking.
            task_id: ID of the progress task.
            page_token: Token for fetching page of results.
        """
        next_page_token: str | None = page_token
        while True:
            response = self.api.get_library_page_init(next_page_token)
            _, next_page_token, remote_media, media_keys_to_delete = parse_db_update(response)

            with Storage(self.db_path) as storage:
                storage.update_state_tokens(page_token=next_page_token)
                storage.update(remote_media)
                storage.delete(media_keys_to_delete)

            task = progress.tasks[int(task_id)]
            progress.update(
                task_id,
                updated=task.fields["updated"] + len(remote_media),
                deleted=task.fields["deleted"] + len(media_keys_to_delete),
            )
            if not next_page_token:
                break

    def _process_pages(self, progress: Progress, task_id: TaskID, state_token: str, page_token: str):
        """
        Process paginated results during cache update.

        Args:
            progress: Rich Progress object for tracking.
            task_id: ID of the progress task.
            page_token: Token for fetching page of results.
        """
        next_page_token: str | None = page_token
        while True:
            response = self.api.get_library_page(next_page_token, state_token)
            _, next_page_token, remote_media, media_keys_to_delete = parse_db_update(response)

            with Storage(self.db_path) as storage:
                storage.update_state_tokens(page_token=next_page_token)
                storage.update(remote_media)
                storage.delete(media_keys_to_delete)

            task = progress.tasks[int(task_id)]
            progress.update(
                task_id,
                updated=task.fields["updated"] + len(remote_media),
                deleted=task.fields["deleted"] + len(media_keys_to_delete),
            )
            if not next_page_token:
                break
