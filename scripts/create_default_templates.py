#!/usr/bin/env python3
"""
Create predefined vendor templates for HP and Huawei.
These templates use vault variables ({{ user }}, {{ password }}) instead of hardcoded credentials.

Run once after deploying to create initial templates:
    python create_default_templates.py
"""
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_manager import get_config_manager

TEMPLATES = [
    {
        "name": "hp_1920",
        "description": "HP 1920 Series - Telnet + TFTP backup",
        "protocol": "telnet",
        "port": 23,
        "result_filename": "{{ hostname }}.cfg",
        "is_text": True,
        "timeout": 60,
        "steps": [
            {"expect": "Username:", "send": "{{ user }}", "hide": False, "timeout": 10},
            {"expect": "Password:", "send": "{{ password }}", "hide": True, "timeout": 10},
            {"expect": ">", "send": "", "hide": False, "timeout": 10},
            {"expect": "", "send": "_cmdline-mode on", "hide": False, "timeout": 10},
            {"expect": "Y/N]", "send": "Y", "hide": False, "timeout": 10},
            {"expect": "word:", "send": "{{ extra_pass }}", "hide": True, "timeout": 10},
            {"expect": ">", "send": "", "hide": False, "timeout": 10},
            {"expect": "", "send": "tftp {{ tftp_server }} put startup.cfg {{ hostname }}.cfg", "hide": False, "timeout": 60},
            {"expect": ">", "send": "", "hide": False, "timeout": 60},
            {"expect": "", "send": "quit", "hide": False, "timeout": 5},
        ]
    },
    {
        "name": "huawei_vrp",
        "description": "Huawei VRP (S5700, AR, etc) - Telnet + FTP backup",
        "protocol": "telnet",
        "port": 23,
        "result_filename": "{{ hostname }}.zip",
        "is_text": False,  # Huawei exports ZIP
        "timeout": 120,
        "steps": [
            {"expect": "Username:", "send": "{{ user }}", "hide": False, "timeout": 10},
            {"expect": "Password:", "send": "{{ password }}", "hide": True, "timeout": 10},
            {"expect": ">", "send": "", "hide": False, "timeout": 10},
            {"expect": "", "send": "system-view", "hide": False, "timeout": 5},
            {"expect": "]", "send": "", "hide": False, "timeout": 5},
            {"expect": "", "send": "ftp {{ ftp_server }}", "hide": False, "timeout": 10},
            {"expect": "User", "send": "{{ ftp_user }}", "hide": False, "timeout": 10},
            {"expect": "Password", "send": "{{ ftp_password }}", "hide": True, "timeout": 10},
            {"expect": "ftp>", "send": "binary", "hide": False, "timeout": 5},
            {"expect": "ftp>", "send": "put flash:/vrpcfg.zip {{ hostname }}.zip", "hide": False, "timeout": 60},
            {"expect": "ftp>", "send": "bye", "hide": False, "timeout": 5},
            {"expect": "", "send": "quit", "hide": False, "timeout": 5},
            {"expect": "", "send": "quit", "hide": False, "timeout": 5},
        ]
    },
    {
        "name": "cisco_ios",
        "description": "Cisco IOS - Telnet + TFTP backup",
        "protocol": "telnet",
        "port": 23,
        "result_filename": "{{ hostname }}.cfg",
        "is_text": True,
        "timeout": 60,
        "steps": [
            {"expect": "Username:", "send": "{{ user }}", "hide": False, "timeout": 10},
            {"expect": "Password:", "send": "{{ password }}", "hide": True, "timeout": 10},
            {"expect": ">", "send": "", "hide": False, "timeout": 10},
            {"expect": "", "send": "enable", "hide": False, "timeout": 5},
            {"expect": "Password:", "send": "{{ extra_pass }}", "hide": True, "timeout": 10},
            {"expect": "#", "send": "", "hide": False, "timeout": 5},
            {"expect": "", "send": "copy running-config tftp://{{ tftp_server }}/{{ hostname }}.cfg", "hide": False, "timeout": 10},
            {"expect": "Address", "send": "{{ tftp_server }}", "hide": False, "timeout": 10},
            {"expect": "filename", "send": "{{ hostname }}.cfg", "hide": False, "timeout": 10},
            {"expect": "#", "send": "", "hide": False, "timeout": 60},
            {"expect": "", "send": "exit", "hide": False, "timeout": 5},
        ]
    },
    {
        "name": "mikrotik_ros",
        "description": "MikroTik RouterOS - SSH + SCP/SFTP backup",
        "protocol": "ssh",
        "port": 22,
        "result_filename": "{{ hostname }}.rsc",
        "is_text": True,
        "timeout": 60,
        "steps": [
            {"expect": "", "send": "/export file={{ hostname }}", "hide": False, "timeout": 30},
            {"expect": ">", "send": "", "hide": False, "timeout": 10},
            # Note: MikroTik requires SCP/SFTP to retrieve the file
            # This template is a starting point
        ]
    },
]


def main():
    config = get_config_manager()
    
    print("Creating predefined vendor templates...")
    print("=" * 50)
    
    for template in TEMPLATES:
        name = template['name']
        existing = config.get_vendor_template_by_name(name)
        
        if existing:
            print(f"⚠ Template '{name}' already exists (ID: {existing['id']}), skipping...")
            continue
        
        template_id = config.create_vendor_template(
            name=name,
            description=template.get('description', ''),
            protocol=template.get('protocol', 'telnet'),
            port=template.get('port', 23),
            steps=template.get('steps', []),
            result_filename=template.get('result_filename', '{{ hostname }}.cfg'),
            is_text=template.get('is_text', True),
            timeout=template.get('timeout', 60)
        )
        
        if template_id:
            print(f"✓ Created template '{name}' (ID: {template_id})")
        else:
            print(f"✗ Failed to create template '{name}'")
    
    print("=" * 50)
    print("Done! Templates are available in Administración → Vendor Templates")


if __name__ == '__main__':
    main()
