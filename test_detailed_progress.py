#!/usr/bin/env python3
"""
Script de prueba para el sistema de progreso detallado.
"""

import os
import sys
from pathlib import Path

# Agregar el directorio del proyecto al path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from gpmc.client import Client
from gpmc.detailed_progress import DetailedProgressTracker

def test_detailed_progress():
    """Prueba básica del sistema de progreso detallado."""
    
    # Crear algunos archivos de prueba temporales
    test_dir = project_root / "test_files"
    test_dir.mkdir(exist_ok=True)
    
    # Crear archivos de prueba pequeños
    test_files = []
    for i in range(3):
        test_file = test_dir / f"test_image_{i}.jpg"
        with open(test_file, "wb") as f:
            # Crear un archivo pequeño con datos de prueba
            f.write(b"fake_image_data" * 100)  # ~1.5KB
        test_files.append(test_file)
    
    print(f"Archivos de prueba creados en: {test_dir}")
    for file in test_files:
        print(f"  - {file.name} ({file.stat().st_size} bytes)")
    
    # Crear mapeo de archivos a álbumes
    file_album_mapping = {
        test_files[0]: "Álbum de Prueba 1",
        test_files[1]: "Álbum de Prueba 1", 
        test_files[2]: "Álbum de Prueba 2"
    }
    
    # Crear tracker de progreso detallado
    tracker = DetailedProgressTracker(show_progress=True, compact_mode=True)
    tracker.initialize_files(file_album_mapping)
    
    print("\n=== Simulando proceso de subida ===")
    
    # Simular inicio de subida para cada archivo
    for file_path in test_files:
        tracker.start_file_upload(file_path)
        print(f"Iniciado: {file_path.name}")
    
    # Simular progreso gradual
    import time
    for i, file_path in enumerate(test_files):
        for progress in [25, 50, 75, 100]:
            tracker.update_file_progress(file_path, progress)
            time.sleep(0.1)  # Pequeña pausa para ver el progreso
        
        # Marcar como completado
        success = i < 2  # Los primeros 2 exitosos, el último falla
        tracker.complete_file_upload(file_path, success=success)
        print(f"{'Completado' if success else 'Fallido'}: {file_path.name}")
    
    # Mostrar estadísticas finales
    print("\n=== Estadísticas Finales ===")
    tracker.log_final_summary()
    
    # Limpiar archivos de prueba
    for file in test_files:
        file.unlink()
    test_dir.rmdir()
    print(f"\nArchivos de prueba eliminados.")

if __name__ == "__main__":
    test_detailed_progress()