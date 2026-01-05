#!/usr/bin/env python3
"""
Fix data bug: usuario 'admin' tiene rol incorrecto (superadmin en lugar de admin).

Uso:
    python3 fix_admin_role.py --check    # Solo verificar, no modificar
    python3 fix_admin_role.py --fix      # Aplicar corrección
"""

import sys
import os

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config_manager import get_config_manager


def check_admin_role():
    """Check current role of 'admin' user."""
    cfg = get_config_manager()
    user = cfg.get_user('admin')
    
    if not user:
        print("❌ Usuario 'admin' no encontrado en DB")
        return None
    
    current_role = user.get('role', 'unknown')
    user_id = user.get('id')
    
    print(f"Usuario: admin (ID: {user_id})")
    print(f"Rol actual: {current_role}")
    print(f"Permisos explícitos: {user.get('permissions', [])}")
    
    if current_role == 'superadmin':
        print("\n⚠️  PROBLEMA: 'admin' tiene rol 'superadmin' - debería ser 'admin'")
        return user_id
    elif current_role == 'admin':
        print("\n✅ OK: 'admin' tiene rol 'admin' - sin cambios necesarios")
        return None
    else:
        print(f"\n⚠️  Rol inesperado: {current_role}")
        return user_id


def fix_admin_role(user_id):
    """Fix admin user role to 'admin'."""
    cfg = get_config_manager()
    
    print(f"\nAplicando fix: cambiando rol de user ID {user_id} a 'admin'...")
    
    cfg.update_user(user_id, role='admin')
    
    # Verify
    user = cfg.get_user('admin')
    new_role = user.get('role', 'unknown')
    
    if new_role == 'admin':
        print(f"✅ Fix aplicado correctamente. Nuevo rol: {new_role}")
        return True
    else:
        print(f"❌ Fix falló. Rol actual: {new_role}")
        return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    action = sys.argv[1]
    
    if action == '--check':
        check_admin_role()
    elif action == '--fix':
        user_id = check_admin_role()
        if user_id:
            if fix_admin_role(user_id):
                print("\n✅ Fix completado. Reiniciá el servicio: systemctl restart backup-web")
            else:
                sys.exit(1)
    else:
        print(f"Acción desconocida: {action}")
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
