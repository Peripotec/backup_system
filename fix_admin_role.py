#!/usr/bin/env python3
"""
Fix Admin Role Script
=====================
Corrige el rol del usuario "admin" de "superadmin" a "admin".

Uso:
    python3 fix_admin_role.py

Este script:
1. Verifica el estado actual del usuario admin
2. Corrige el rol a "admin" si está mal asignado
3. Muestra confirmación del cambio
"""

import os
import sys

# Agregar path del proyecto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config_manager import get_config_manager


def main():
    print("=" * 50)
    print("Fix Admin Role Script")
    print("=" * 50)
    
    cfg = get_config_manager()
    
    # 1. Verificar estado actual
    user = cfg.get_user('admin')
    if not user:
        print("ERROR: Usuario 'admin' no encontrado en DB")
        sys.exit(1)
    
    current_role = user.get('role', 'unknown')
    print(f"\nEstado actual:")
    print(f"  Usuario: admin")
    print(f"  Rol actual: {current_role}")
    print(f"  Permisos explícitos: {user.get('permissions', [])}")
    
    # 2. Verificar si necesita fix
    if current_role == 'admin':
        print("\n✓ El usuario 'admin' ya tiene el rol correcto ('admin').")
        print("  No se requiere ningún cambio.")
        sys.exit(0)
    
    if current_role != 'superadmin':
        print(f"\n⚠ El usuario 'admin' tiene rol '{current_role}', no 'superadmin'.")
        print("  Revise manualmente si esto es intencional.")
        sys.exit(1)
    
    # 3. Aplicar fix
    print(f"\n⚠ PROBLEMA DETECTADO: Usuario 'admin' tiene rol 'superadmin'")
    print("  Esto causa escalamiento de privilegios.")
    print("\nAplicando fix...")
    
    # Actualizar rol
    user_id = user.get('id')
    success = cfg.update_user(user_id, role='admin')
    
    if not success:
        print("ERROR: No se pudo actualizar el usuario")
        sys.exit(1)
    
    # 4. Verificar cambio
    user_after = cfg.get_user('admin')
    new_role = user_after.get('role', 'unknown')
    
    print(f"\n✓ Fix aplicado exitosamente:")
    print(f"  Usuario: admin")
    print(f"  Rol anterior: superadmin")
    print(f"  Rol nuevo: {new_role}")
    
    if new_role == 'admin':
        print("\n✓ Verificación OK: El rol fue corregido correctamente.")
    else:
        print(f"\n⚠ ADVERTENCIA: El rol es '{new_role}', no 'admin'.")
    
    print("\n" + "=" * 50)
    print("IMPORTANTE: Reinicie el servicio web para aplicar cambios:")
    print("  sudo systemctl restart backup-web")
    print("=" * 50)


if __name__ == '__main__':
    main()
