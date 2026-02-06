#!/usr/bin/env python3
"""
Script de prueba para plugins de vendor.

USO:
    python test_vendor.py <vendor_name> <ip> <usuario> <password> [puerto]

EJEMPLOS:
    python test_vendor.py mikrotik 192.168.1.1 admin password123
    python test_vendor.py fortigate 10.0.0.1 admin admin123 22
    python test_vendor.py zte_olt 10.0.0.5 root root 23

NOTAS:
    - El nombre del vendor debe coincidir con el nombre del archivo .py
    - Este script SOLO prueba la conexión y backup, no afecta la DB real
"""

import sys
import os
import importlib

# Agregar directorio del proyecto al path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)  # Un nivel arriba de docs/
sys.path.insert(0, project_dir)
os.chdir(project_dir)

def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    
    vendor_name = sys.argv[1]
    ip = sys.argv[2]
    user = sys.argv[3]
    password = sys.argv[4]
    port = int(sys.argv[5]) if len(sys.argv) > 5 else None
    
    print("=" * 60)
    print(f"  PRUEBA DE PLUGIN: {vendor_name}")
    print("=" * 60)
    print(f"  IP:       {ip}")
    print(f"  Usuario:  {user}")
    print(f"  Puerto:   {port or 'default'}")
    print("=" * 60)
    print()
    
    # Cargar el módulo del vendor
    try:
        class_name = "".join(x.title() for x in vendor_name.split('_'))
        module = importlib.import_module(f'vendors.{vendor_name}')
        VendorClass = getattr(module, class_name)
        print(f"✓ Plugin cargado: {class_name}")
    except ImportError as e:
        print(f"✗ No se encontró el plugin: vendors/{vendor_name}.py")
        print(f"  Error: {e}")
        sys.exit(1)
    except AttributeError:
        print(f"✗ No se encontró la clase: {class_name}")
        print(f"  El archivo existe pero la clase debe llamarse '{class_name}'")
        sys.exit(1)
    
    # Mock de managers (no afectan DB real en test)
    from core.db_manager import DBManager
    from core.git_manager import GitManager
    
    db = DBManager()
    git = GitManager()
    
    # Configuración del dispositivo
    device_info = {
        'hostname': f'TEST-{vendor_name.upper()}',
        'sysname': f'TEST-{vendor_name.upper()}',
        'ip': ip,
        'vendor': vendor_name,
    }
    if port:
        device_info['port'] = port
    
    credentials = [
        {'id': 'test', 'user': user, 'pass': password}
    ]
    
    # Crear instancia del plugin
    plugin = VendorClass(device_info, db, git, credentials)
    
    # Callback para ver logs en consola
    def log_callback(msg):
        print(f"  [LOG] {msg}")
    
    plugin.log_callback = log_callback
    
    # Ejecutar backup
    print()
    print("Iniciando backup...")
    print("-" * 60)
    
    try:
        path, size, changed = plugin.backup()
        print("-" * 60)
        print()
        print("=" * 60)
        print("  ✅ BACKUP EXITOSO!")
        print("=" * 60)
        print(f"  Archivo:  {path}")
        print(f"  Tamaño:   {size:,} bytes")
        print(f"  Cambios:  {'Sí' if changed else 'No (idéntico al anterior)'}")
        print("=" * 60)
        
        # Mostrar preview del contenido
        if os.path.exists(path):
            print()
            print("Preview del archivo (primeras 20 líneas):")
            print("-" * 60)
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= 20:
                        print("  ...")
                        break
                    print(f"  {line.rstrip()}")
            print("-" * 60)
        
    except Exception as e:
        print("-" * 60)
        print()
        print("=" * 60)
        print("  ❌ ERROR EN BACKUP")
        print("=" * 60)
        print(f"  {type(e).__name__}: {e}")
        print("=" * 60)
        print()
        print("Traceback completo:")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
