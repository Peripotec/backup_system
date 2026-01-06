"""
Generic Vendor - Executes backup using configurable templates.

Templates define a sequence of expect/send steps that are executed via Telnet/SSH.
Variables like {{ user }}, {{ password }}, {{ hostname }} are resolved at runtime.
"""
import time
import os
import re
from vendors.base_vendor import BackupVendor
from settings import TFTP_ROOT
from core.logger import log
from core.vault import save_preferred_credential_for_device
from core.config_manager import get_config_manager


class GenericVendor(BackupVendor):
    """
    Executes backup based on a vendor template.
    
    Template format:
    {
        "name": "hp_1920",
        "protocol": "telnet",
        "port": 23,
        "steps": [
            {"expect": "Username:", "send": "{{ user }}"},
            {"expect": "Password:", "send": "{{ password }}", "hide": true},
            {"expect": ">", "send": "_cmdline-mode on"},
            ...
        ],
        "result_filename": "{{ hostname }}.cfg",
        "is_text": true,
        "timeout": 60
    }
    """
    
    def __init__(self, device_info, db_manager, git_manager, credentials=None, template=None):
        super().__init__(device_info, db_manager, git_manager, credentials)
        self.template = template
        
        # Override port from template if specified
        if template and template.get('port'):
            self.port = template['port']
    
    def _resolve_variable(self, text, credential=None):
        """
        Resolve template variables to actual values.
        
        Supported variables:
        - {{ user }} - Username from credential
        - {{ password }} - Password from credential
        - {{ extra_pass }} - Extra password from credential
        - {{ hostname }} - Device hostname
        - {{ ip }} - Device IP
        - {{ tftp_server }} - TFTP server from settings
        """
        if not text:
            return text
        
        config = get_config_manager()
        
        # Build variable map
        variables = {
            'hostname': self.hostname,
            'ip': self.ip,
            'tftp_server': config.get_setting('tftp_server') or '127.0.0.1',
        }
        
        # Add credential variables if provided
        if credential:
            variables['user'] = credential.get('user', '')
            variables['password'] = credential.get('pass', '')
            variables['extra_pass'] = credential.get('extra_pass', '')
        else:
            variables['user'] = self.user
            variables['password'] = self.password
            variables['extra_pass'] = self.extra_pass
        
        # Replace {{ variable }} patterns
        def replace_var(match):
            var_name = match.group(1).strip()
            return str(variables.get(var_name, match.group(0)))
        
        return re.sub(r'\{\{\s*(\w+)\s*\}\}', replace_var, text)
    
    def _execute_step(self, tn, step, credential=None):
        """
        Execute a single step from the template.
        
        Step format:
        {
            "expect": "pattern to wait for",
            "send": "command to send",
            "hide": false,      # Hide in logs (for passwords)
            "timeout": 10,      # Override default timeout
            "fallbacks": []     # Alternative values to try if first fails
        }
        """
        expect_pattern = step.get('expect')
        send_command = step.get('send')
        hide = step.get('hide', False)
        timeout = step.get('timeout', 10)
        fallbacks = step.get('fallbacks', [])
        
        # Step 1: Wait for expected pattern (if specified)
        if expect_pattern:
            resolved_pattern = self._resolve_variable(expect_pattern, credential)
            self._debug_log(f"Esperando: {resolved_pattern}")
            idx, response = self.read_until(tn, [resolved_pattern], timeout=timeout)
            if idx < 0:
                self._debug_log(f"⚠ Timeout esperando: {resolved_pattern}")
                return False, response
        
        # Step 2: Send command (if specified)
        if send_command:
            resolved_command = self._resolve_variable(send_command, credential)
            self.send_command(tn, resolved_command, hide=hide)
            
            # If fallbacks exist and next expect fails, try alternatives
            if fallbacks and expect_pattern:
                # This is for things like multiple cmdline passwords
                pass  # Fallback logic handled at higher level
        
        return True, ""
    
    def backup(self):
        """
        Execute backup using the configured template.
        """
        if not self.template:
            raise ValueError("No template configured for GenericVendor")
        
        template = self.template
        steps = template.get('steps', [])
        
        if not steps:
            raise ValueError(f"Template '{template.get('name')}' has no steps defined")
        
        # Get TFTP server
        config = get_config_manager()
        tftp_server = config.get_setting('tftp_server') or '127.0.0.1'
        
        # Guardrail
        if tftp_server in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError(f"TFTP server is '{tftp_server}' - configure correct IP in Settings.")
        
        self._debug_log(f"Template: {template.get('name')}")
        self._debug_log(f"TFTP Server: {tftp_server}")
        self._debug_log(f"Steps: {len(steps)}")
        
        # Connect
        tn = self.connect_telnet()
        
        # Try credentials
        credentials_to_try = self.credentials_pool if self.credentials_pool else [
            {"user": self.user, "pass": self.password, "extra_pass": self.extra_pass, "id": None}
        ]
        
        logged_in = False
        successful_cred = None
        
        for cred_idx, cred in enumerate(credentials_to_try):
            self._debug_log(f"Probando credencial {cred_idx+1}/{len(credentials_to_try)}...")
            
            try:
                # Execute all steps with this credential
                all_steps_ok = True
                for step_idx, step in enumerate(steps):
                    self._debug_log(f"Paso {step_idx+1}/{len(steps)}")
                    success, response = self._execute_step(tn, step, cred)
                    
                    if not success:
                        # Check if this looks like an auth failure
                        if any(x in response.lower() for x in ['failed', 'invalid', 'denied', 'error']):
                            self._debug_log(f"✗ Autenticación falló")
                            all_steps_ok = False
                            break
                
                if all_steps_ok:
                    logged_in = True
                    successful_cred = cred
                    self._debug_log(f"✓ Secuencia completada con credencial {cred_idx+1}")
                    break
                    
            except Exception as e:
                self._debug_log(f"✗ Error en credencial {cred_idx+1}: {e}")
                continue
        
        if not logged_in:
            tn.close()
            raise Exception(f"Failed to complete backup sequence with all {len(credentials_to_try)} credentials")
        
        # Save successful credential
        if successful_cred and successful_cred.get('id'):
            save_preferred_credential_for_device(self.hostname, successful_cred['id'])
            self._debug_log(f"📝 Credencial guardada como preferida")
        
        # Close connection
        tn.close()
        
        # Verify file
        result_filename = self._resolve_variable(template.get('result_filename', '{{ hostname }}.cfg'), successful_cred)
        tftp_path = os.path.join(TFTP_ROOT, result_filename)
        
        self._debug_log(f"Verificando archivo: {tftp_path}")
        
        for i in range(10):
            if os.path.exists(tftp_path) and os.path.getsize(tftp_path) > 0:
                self._debug_log(f"✓ Archivo encontrado ({os.path.getsize(tftp_path)} bytes)")
                break
            self._debug_log(f"Esperando archivo... ({i+1}/10)")
            time.sleep(1)
        
        if not os.path.exists(tftp_path) or os.path.getsize(tftp_path) == 0:
            raise FileNotFoundError(f"Backup file not found or empty: {tftp_path}")
        
        # Process file
        is_text = template.get('is_text', True)
        return self.process_file(tftp_path, is_text=is_text)
