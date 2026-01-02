"""
Device model and related data structures for the Backup System.

This module defines the canonical Device class used throughout the system,
providing a consistent interface regardless of the inventory source (YAML, NetBox, etc.).
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Device:
    """
    Canonical device representation for the Backup System.
    
    This model abstracts the source of device information, allowing seamless
    integration with different inventory providers (YAML, NetBox, etc.).
    
    Attributes:
        sysname: Unique identifier for the device (immutable, used for directory names)
        ip: Primary IP address for management access
        vendor: Device vendor/manufacturer (e.g., 'Huawei', 'Cisco', 'HP', 'ZTE')
        modelo: Device model (e.g., 'S5720', 'C9200L')
        grupo: Logical grouping (e.g., 'Core', 'Acceso', 'OLT')
        tipo: Device type (e.g., 'switch', 'router', 'olt')
        criticidad: Criticality level (e.g., 'alta', 'media', 'baja')
        schedule: Device-specific backup schedule (HH:MM CSV), empty = inherit
        backup_enabled: Whether backups are enabled for this device
        tags: Additional tags for filtering/grouping
    """
    sysname: str
    ip: str
    vendor: str
    modelo: str = ''
    grupo: str = ''
    tipo: str = ''
    criticidad: str = 'media'
    schedule: str = ''  # Empty = inherit from model/vendor/global
    backup_enabled: bool = True
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'sysname': self.sysname,
            'ip': self.ip,
            'vendor': self.vendor,
            'modelo': self.modelo,
            'grupo': self.grupo,
            'tipo': self.tipo,
            'criticidad': self.criticidad,
            'schedule': self.schedule,
            'backup_enabled': self.backup_enabled,
            'tags': self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Device':
        """Create Device from dictionary."""
        return cls(
            sysname=data.get('sysname', data.get('hostname', '')),
            ip=data.get('ip', ''),
            vendor=data.get('vendor', ''),
            modelo=data.get('modelo', data.get('model', '')),
            grupo=data.get('grupo', data.get('group', '')),
            tipo=data.get('tipo', data.get('type', '')),
            criticidad=data.get('criticidad', 'media'),
            schedule=data.get('schedule', ''),
            backup_enabled=data.get('backup_enabled', True),
            tags=data.get('tags', []),
        )
    
    def __str__(self) -> str:
        return f"Device({self.sysname}@{self.ip}, vendor={self.vendor})"
