import yaml
import shutil
import os
from settings import INVENTORY_FILE

def migrate_inventory():
    print(f"Reading inventory from {INVENTORY_FILE}...")
    
    if not os.path.exists(INVENTORY_FILE):
        print("Inventory file not found!")
        return

    # Backup first
    backup_file = INVENTORY_FILE + ".bak"
    shutil.copy2(INVENTORY_FILE, backup_file)
    print(f"Backup created at {backup_file}")

    try:
        with open(INVENTORY_FILE, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Error reading YAML: {e}")
        return

    changed = False
    groups = data.get('groups', [])
    
    total_devices = 0
    updated_devices = 0

    for group in groups:
        for device in group.get('devices', []):
            total_devices += 1
            # Check if sysname is missing
            if 'sysname' not in device:
                # Use hostname as sysname
                if 'hostname' in device:
                    device['sysname'] = device['hostname']
                    changed = True
                    updated_devices += 1
                    print(f"Updated: {device['hostname']} -> added sysname='{device['sysname']}'")
                else:
                    print(f"Warning: Device without hostname in group {group.get('name')}")
            
            # Ensure criticidad exists (default to empty string or None, or just leave it optional)
            # We won't force criticidad yet, just sysname is critical for ID.

    if changed:
        with open(INVENTORY_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"\nMigration successful.")
        print(f"Total devices: {total_devices}")
        print(f"Updated devices: {updated_devices}")
    else:
        print("\nNo changes needed. All devices already have sysname.")

if __name__ == "__main__":
    migrate_inventory()
