"""
Validador de nombres de álbum para Google Photos.
Valida que los nombres de álbum cumplan con las restricciones de Google Photos.
"""

import re
import logging
from typing import List, Tuple, Optional


class AlbumNameValidator:
    """
    Validador de nombres de álbum para Google Photos.
    
    Aplica las reglas de nomenclatura de Google Photos y proporciona
    sugerencias de corrección para nombres inválidos.
    """
    
    # Reglas de Google Photos para nombres de álbum
    MIN_LENGTH = 1
    MAX_LENGTH = 500
    
    # Caracteres prohibidos (basado en las restricciones comunes de Google Photos)
    # Permitimos '/' para que se puedan usar rutas como nombres de álbumes
    FORBIDDEN_CHARS = ['<', '>', ':', '"', '|', '?', '*', '\\']
    
    # Nombres reservados del sistema
    RESERVED_NAMES = [
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_album_name(self, name: str) -> Tuple[bool, List[str]]:
        """
        Validar un nombre de álbum.
        
        Args:
            name: Nombre del álbum a validar
            
        Returns:
            Tuple[bool, List[str]]: (es_válido, lista_de_errores)
        """
        errors = []
        
        if not name:
            errors.append("El nombre del álbum no puede estar vacío")
            return False, errors
        
        # Verificar longitud
        if len(name) < self.MIN_LENGTH:
            errors.append(f"El nombre debe tener al menos {self.MIN_LENGTH} carácter")
        
        if len(name) > self.MAX_LENGTH:
            errors.append(f"El nombre no puede exceder {self.MAX_LENGTH} caracteres")
        
        # Verificar caracteres prohibidos
        forbidden_found = [char for char in self.FORBIDDEN_CHARS if char in name]
        if forbidden_found:
            errors.append(f"Caracteres prohibidos encontrados: {', '.join(forbidden_found)}")
        
        # Verificar nombres reservados
        if name.upper() in self.RESERVED_NAMES:
            errors.append(f"'{name}' es un nombre reservado del sistema")
        
        # Verificar que no empiece o termine con espacios
        if name.startswith(' ') or name.endswith(' '):
            errors.append("El nombre no puede empezar o terminar con espacios")
        
        # Verificar que no contenga solo espacios
        if name.strip() == '':
            errors.append("El nombre no puede contener solo espacios")
        
        # Verificar caracteres de control
        if any(ord(char) < 32 for char in name):
            errors.append("El nombre contiene caracteres de control no válidos")
        
        return len(errors) == 0, errors
    
    def sanitize_album_name(self, name: str) -> str:
        """
        Sanitizar un nombre de álbum para hacerlo válido.
        
        Args:
            name: Nombre original del álbum
            
        Returns:
            str: Nombre sanitizado y válido
        """
        if not name:
            return "Album_Sin_Nombre"
        
        # Eliminar espacios al inicio y final
        sanitized = name.strip()
        
        # Reemplazar caracteres prohibidos con guiones bajos
        for char in self.FORBIDDEN_CHARS:
            sanitized = sanitized.replace(char, '_')
        
        # Eliminar caracteres de control
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32)
        
        # Si queda vacío después de la sanitización
        if not sanitized or sanitized.strip() == '':
            sanitized = "Album_Sanitizado"
        
        # Verificar nombres reservados
        if sanitized.upper() in self.RESERVED_NAMES:
            sanitized = f"{sanitized}_Album"
        
        # Truncar si es muy largo
        if len(sanitized) > self.MAX_LENGTH:
            sanitized = sanitized[:self.MAX_LENGTH].rstrip()
        
        # Asegurar que no termine con punto (problema en algunos sistemas)
        sanitized = sanitized.rstrip('.')
        
        # Verificación final
        is_valid, _ = self.validate_album_name(sanitized)
        if not is_valid:
            # Fallback seguro
            sanitized = f"Album_{hash(name) % 10000}"
        
        return sanitized
    
    def validate_album_names_batch(self, names: List[str]) -> dict[str, Tuple[bool, List[str], str]]:
        """
        Validar múltiples nombres de álbum en lote.
        
        Args:
            names: Lista de nombres de álbum a validar
            
        Returns:
            dict: Mapeo de nombre_original -> (es_válido, errores, nombre_sanitizado)
        """
        results = {}
        
        for name in names:
            is_valid, errors = self.validate_album_name(name)
            sanitized = self.sanitize_album_name(name) if not is_valid else name
            results[name] = (is_valid, errors, sanitized)
        
        return results
    
    def get_validation_summary(self, names: List[str]) -> dict:
        """
        Obtener un resumen de validación para múltiples nombres.
        
        Args:
            names: Lista de nombres de álbum
            
        Returns:
            dict: Resumen con estadísticas de validación
        """
        results = self.validate_album_names_batch(names)
        
        valid_count = sum(1 for is_valid, _, _ in results.values() if is_valid)
        invalid_count = len(names) - valid_count
        
        invalid_names = [
            name for name, (is_valid, errors, _) in results.items() 
            if not is_valid
        ]
        
        common_errors = {}
        for _, (is_valid, errors, _) in results.items():
            if not is_valid:
                for error in errors:
                    common_errors[error] = common_errors.get(error, 0) + 1
        
        return {
            'total_names': len(names),
            'valid_count': valid_count,
            'invalid_count': invalid_count,
            'invalid_names': invalid_names,
            'common_errors': common_errors,
            'success_rate': (valid_count / len(names) * 100) if names else 0
        }
    
    def log_validation_results(self, names: List[str]) -> None:
        """Registrar resultados de validación en los logs."""
        summary = self.get_validation_summary(names)
        results = self.validate_album_names_batch(names)
        
        self.logger.info("=== VALIDACIÓN DE NOMBRES DE ÁLBUM ===")
        self.logger.info(f"📊 Total: {summary['total_names']} álbumes")
        self.logger.info(f"✅ Válidos: {summary['valid_count']} ({summary['success_rate']:.1f}%)")
        self.logger.info(f"❌ Inválidos: {summary['invalid_count']}")
        
        if summary['invalid_count'] > 0:
            self.logger.warning("Álbumes con nombres inválidos:")
            for name, (is_valid, errors, sanitized) in results.items():
                if not is_valid:
                    self.logger.warning(f"  📁 '{name}':")
                    for error in errors:
                        self.logger.warning(f"    - {error}")
                    self.logger.info(f"    💡 Sugerencia: '{sanitized}'")
        
        if summary['common_errors']:
            self.logger.info("Errores más comunes:")
            for error, count in sorted(summary['common_errors'].items(), key=lambda x: x[1], reverse=True):
                self.logger.info(f"  - {error}: {count} casos")


# Instancia global para uso conveniente
album_validator = AlbumNameValidator()