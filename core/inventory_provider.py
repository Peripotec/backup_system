"""
Inventory Provider Abstraction Layer.

This module provides an abstract interface for inventory sources, allowing
the Backup System to work with different data sources:
- YAML files (current implementation)
- NetBox API (future integration)
- Webhook receiver (future integration)

Usage:
    provider = get_inventory_provider()
    devices = provider.get_all_devices()

Configuration:
    Set 'inventory_source' in settings:
    - 'yaml': Use local inventory.yaml (default)
    - 'netbox': Query NetBox API (requires netbox_url, netbox_token)
"""

import os
import yaml
import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from core.models import Device

log = logging.getLogger('backup_system')

# Path to inventory file
INVENTORY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'inventory.yaml')


class InventoryProvider(ABC):
    """
    Abstract base class for inventory providers.
    
    All inventory sources must implement this interface to be used
    by the Backup System.
    """
    
    @abstractmethod
    def get_all_devices(self) -> List[Device]:
        """
        Get all devices from the inventory.
        
        Returns:
            List of Device objects with backup_enabled=True
        """
        pass
    
    @abstractmethod
    def get_devices_by_vendor(self, vendor: str) -> List[Device]:
        """
        Get devices filtered by vendor.
        
        Args:
            vendor: Vendor name (case-insensitive)
            
        Returns:
            List of Device objects matching the vendor
        """
        pass
    
    @abstractmethod
    def get_devices_by_group(self, group: str) -> List[Device]:
        """
        Get devices filtered by group.
        
        Args:
            group: Group name
            
        Returns:
            List of Device objects in the group
        """
        pass
    
    @abstractmethod
    def get_unique_vendors(self) -> List[str]:
        """
        Get list of unique vendors in the inventory.
        
        Returns:
            Sorted list of vendor names
        """
        pass
    
    @abstractmethod
    def get_raw_inventory(self) -> Dict[str, Any]:
        """
        Get raw inventory data for backward compatibility.
        
        Returns:
            Dictionary with 'groups' key containing raw group data
        """
        pass


class YamlInventoryProvider(InventoryProvider):
    """
    Inventory provider that reads from a local YAML file.
    
    This is the default provider and maintains backward compatibility
    with the existing inventory.yaml format.
    
    File format:
        groups:
          - name: "Group Name"
            vendor: "Vendor"
            devices:
              - sysname: "device1"
                ip: "192.168.1.1"
                modelo: "Model"
    """
    
    def __init__(self, inventory_path: str = None):
        """
        Initialize the YAML provider.
        
        Args:
            inventory_path: Path to inventory.yaml file (optional)
        """
        self.inventory_path = inventory_path or INVENTORY_PATH
        self._cache = None
        self._cache_mtime = 0
    
    def _load_yaml(self) -> Dict[str, Any]:
        """Load and cache the YAML file, reloading if modified."""
        try:
            mtime = os.path.getmtime(self.inventory_path)
            if self._cache is None or mtime > self._cache_mtime:
                with open(self.inventory_path, 'r', encoding='utf-8') as f:
                    self._cache = yaml.safe_load(f) or {'groups': []}
                self._cache_mtime = mtime
                log.debug(f"Loaded inventory from {self.inventory_path}")
            return self._cache
        except FileNotFoundError:
            log.warning(f"Inventory file not found: {self.inventory_path}")
            return {'groups': []}
        except Exception as e:
            log.error(f"Error loading inventory: {e}")
            return {'groups': []}
    
    def get_all_devices(self) -> List[Device]:
        """Get all devices from YAML inventory."""
        inventory = self._load_yaml()
        devices = []
        
        for group in inventory.get('groups', []):
            group_name = group.get('name', '')
            group_vendor = group.get('vendor', '')
            
            for dev_data in group.get('devices', []):
                # Merge group-level vendor if not specified in device
                if not dev_data.get('vendor'):
                    dev_data['vendor'] = group_vendor
                if not dev_data.get('grupo'):
                    dev_data['grupo'] = group_name
                
                device = Device.from_dict(dev_data)
                
                # Only include devices with backup enabled
                if device.backup_enabled:
                    devices.append(device)
        
        return devices
    
    def get_devices_by_vendor(self, vendor: str) -> List[Device]:
        """Get devices filtered by vendor."""
        all_devices = self.get_all_devices()
        return [d for d in all_devices if d.vendor.lower() == vendor.lower()]
    
    def get_devices_by_group(self, group: str) -> List[Device]:
        """Get devices filtered by group."""
        all_devices = self.get_all_devices()
        return [d for d in all_devices if d.grupo.lower() == group.lower()]
    
    def get_unique_vendors(self) -> List[str]:
        """Get list of unique vendors."""
        inventory = self._load_yaml()
        vendors = set()
        for group in inventory.get('groups', []):
            vendor = group.get('vendor', '')
            if vendor:
                vendors.add(vendor)
        return sorted(list(vendors))
    
    def get_raw_inventory(self) -> Dict[str, Any]:
        """Get raw YAML data for backward compatibility."""
        return self._load_yaml()


class NetBoxInventoryProvider(InventoryProvider):
    """
    Inventory provider that queries NetBox API.
    
    This is a stub implementation for future integration.
    When NetBox is available, implement the API calls here.
    
    Required configuration:
        - netbox_url: NetBox API URL (e.g., 'https://netbox.example.com')
        - netbox_token: API authentication token
        - netbox_filter_tag: Tag to filter devices (e.g., 'backup-enabled')
    
    NetBox custom fields needed:
        - backup_schedule: HH:MM CSV schedule
        - backup_enabled: Boolean
    """
    
    def __init__(self, url: str, token: str, filter_tag: str = 'backup-enabled'):
        """
        Initialize the NetBox provider.
        
        Args:
            url: NetBox API URL
            token: API authentication token
            filter_tag: Tag to filter devices for backup
        """
        self.url = url
        self.token = token
        self.filter_tag = filter_tag
        self._api = None
        log.info(f"NetBox provider initialized for {url}")
    
    def _get_api(self):
        """Lazy-load pynetbox API client."""
        if self._api is None:
            try:
                import pynetbox
                self._api = pynetbox.api(self.url, token=self.token)
            except ImportError:
                raise RuntimeError(
                    "pynetbox is not installed. "
                    "Install with: pip install pynetbox"
                )
        return self._api
    
    def _map_netbox_device(self, nb_device) -> Device:
        """
        Map a NetBox device to our Device model.
        
        NetBox fields mapping:
            device.name -> sysname
            device.primary_ip4.address -> ip (without /mask)
            device.device_type.manufacturer.slug -> vendor
            device.device_type.model -> modelo
            device.site.name or device.rack.name -> grupo
            device.device_type.slug -> tipo
            device.custom_fields.backup_schedule -> schedule
            device.custom_fields.backup_enabled -> backup_enabled
            device.tags -> tags
        """
        # Extract IP without mask
        ip = ''
        if nb_device.primary_ip4:
            ip = str(nb_device.primary_ip4.address).split('/')[0]
        
        # Get vendor from manufacturer
        vendor = ''
        if nb_device.device_type and nb_device.device_type.manufacturer:
            vendor = nb_device.device_type.manufacturer.name
        
        # Get model
        modelo = ''
        if nb_device.device_type:
            modelo = nb_device.device_type.model
        
        # Get group from site or rack
        grupo = ''
        if nb_device.site:
            grupo = nb_device.site.name
        elif nb_device.rack:
            grupo = nb_device.rack.name
        
        # Get custom fields
        cf = nb_device.custom_fields or {}
        
        return Device(
            sysname=nb_device.name,
            ip=ip,
            vendor=vendor,
            modelo=modelo,
            grupo=grupo,
            tipo=nb_device.device_type.slug if nb_device.device_type else '',
            criticidad=cf.get('criticidad', 'media'),
            schedule=cf.get('backup_schedule', ''),
            backup_enabled=cf.get('backup_enabled', True),
            tags=[str(t) for t in (nb_device.tags or [])],
        )
    
    def get_all_devices(self) -> List[Device]:
        """Get all devices from NetBox with backup tag."""
        api = self._get_api()
        devices = []
        
        try:
            # Query devices with backup tag and active status
            nb_devices = api.dcim.devices.filter(
                status='active',
                tag=self.filter_tag,
                has_primary_ip=True
            )
            
            for nb_device in nb_devices:
                try:
                    device = self._map_netbox_device(nb_device)
                    if device.backup_enabled and device.ip:
                        devices.append(device)
                except Exception as e:
                    log.warning(f"Error mapping NetBox device {nb_device.name}: {e}")
            
            log.info(f"Loaded {len(devices)} devices from NetBox")
            
        except Exception as e:
            log.error(f"Error querying NetBox: {e}")
        
        return devices
    
    def get_devices_by_vendor(self, vendor: str) -> List[Device]:
        """Get devices filtered by vendor."""
        all_devices = self.get_all_devices()
        return [d for d in all_devices if d.vendor.lower() == vendor.lower()]
    
    def get_devices_by_group(self, group: str) -> List[Device]:
        """Get devices filtered by group/site."""
        all_devices = self.get_all_devices()
        return [d for d in all_devices if d.grupo.lower() == group.lower()]
    
    def get_unique_vendors(self) -> List[str]:
        """Get list of unique vendors."""
        devices = self.get_all_devices()
        vendors = set(d.vendor for d in devices if d.vendor)
        return sorted(list(vendors))
    
    def get_raw_inventory(self) -> Dict[str, Any]:
        """
        Get inventory in legacy format for backward compatibility.
        
        Converts flat device list to grouped format.
        """
        devices = self.get_all_devices()
        
        # Group devices by grupo
        groups_dict = {}
        for device in devices:
            group_name = device.grupo or 'Ungrouped'
            if group_name not in groups_dict:
                groups_dict[group_name] = {
                    'name': group_name,
                    'vendor': device.vendor,
                    'devices': []
                }
            groups_dict[group_name]['devices'].append(device.to_dict())
        
        return {'groups': list(groups_dict.values())}


# -----------------------------------------------------------------------------
# Factory function
# -----------------------------------------------------------------------------

_provider_instance: Optional[InventoryProvider] = None


def get_inventory_provider() -> InventoryProvider:
    """
    Get the configured inventory provider.
    
    Uses 'inventory_source' setting to determine which provider to use:
        - 'yaml' (default): YamlInventoryProvider
        - 'netbox': NetBoxInventoryProvider
    
    Returns:
        InventoryProvider instance (cached singleton)
    """
    global _provider_instance
    
    if _provider_instance is not None:
        return _provider_instance
    
    # Get config - import here to avoid circular imports
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    
    source = cfg.get_setting('inventory_source') or 'yaml'
    
    if source == 'netbox':
        netbox_url = cfg.get_setting('netbox_url')
        netbox_token = cfg.get_setting('netbox_token')
        netbox_tag = cfg.get_setting('netbox_filter_tag') or 'backup-enabled'
        
        if not netbox_url or not netbox_token:
            log.warning("NetBox config incomplete, falling back to YAML")
            source = 'yaml'
        else:
            _provider_instance = NetBoxInventoryProvider(
                url=netbox_url,
                token=netbox_token,
                filter_tag=netbox_tag
            )
            log.info(f"Using NetBox inventory provider: {netbox_url}")
            return _provider_instance
    
    # Default: YAML provider
    _provider_instance = YamlInventoryProvider()
    log.info("Using YAML inventory provider")
    return _provider_instance


def reset_inventory_provider():
    """
    Reset the cached provider instance.
    
    Call this when settings change to force re-initialization.
    """
    global _provider_instance
    _provider_instance = None
    log.debug("Inventory provider cache reset")
