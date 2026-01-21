import smtplib
import shutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from settings import BACKUP_ROOT_DIR
from core.logger import log
from core.config_manager import get_config_manager


class Notifier:
    """Enterprise-ready email notifier. Reads all config from DB."""
    
    def __init__(self):
        self.config = get_config_manager()
    
    def _get_config(self):
        """Load current SMTP config from DB."""
        return {
            'enabled': self.config.get_setting('smtp_enabled') == 'true',
            'host': self.config.get_setting('smtp_host') or '',
            'port': int(self.config.get_setting('smtp_port') or 25),
            'from_addr': self.config.get_setting('smtp_from') or 'Sistema de Backup <backup@localhost>',
            'transport': self.config.get_setting('smtp_transport') or 'plain',
            'auth_required': self.config.get_setting('smtp_auth') == 'true',
            'user': self.config.get_setting('smtp_user') or '',
            'password': self.config.get_setting('smtp_pass') or '',
            'timeout': int(self.config.get_setting('smtp_timeout') or 15),
            'recipients': self._parse_recipients(self.config.get_setting('email_recipients') or ''),
            'notify_on_error': self.config.get_setting('notify_on_error') == 'true',
            'notify_on_success': self.config.get_setting('notify_on_success') == 'true',
        }
    
    def _parse_recipients(self, recipients_str):
        """Parse CSV recipients into list."""
        if not recipients_str:
            return []
        return [r.strip() for r in recipients_str.split(',') if r.strip()]

    def send_summary(self, total, success, errors, failed_hosts, diff_summary, duration, disabled_devices=None):
        """Envía un resumen HTML del trabajo de backup."""
        cfg = self._get_config()
        
        if not cfg['enabled']:
            log.info("Notificaciones por email deshabilitadas.")
            return False
        
        # Check if we should send based on result
        has_errors = errors > 0
        if has_errors and not cfg['notify_on_error']:
            log.info("Saltando email: notify_on_error deshabilitado")
            return False
        if not has_errors and not cfg['notify_on_success']:
            log.info("Saltando email: notify_on_success deshabilitado")
            return False
        
        if not cfg['host'] or not cfg['recipients']:
            log.warning("Email no configurado: falta host o destinatarios")
            return False

        # Count disabled devices
        disabled_count = len(disabled_devices) if disabled_devices else 0

        # Asunto en español
        subject = f"📊 Reporte de Backup: {success}/{total} Exitosos"
        if errors > 0:
            subject = f"⚠️ Reporte de Backup: {success}/{total} - {errors} ERRORES"
        if disabled_count > 0:
            subject += f" ({disabled_count} omitidos)"

        # Get Disk Usage
        try:
            total_d, used_d, free_d = shutil.disk_usage(BACKUP_ROOT_DIR)
            disk_percent = (used_d / total_d) * 100
            disk_usage_str = f"{disk_percent:.1f}% Usado ({free_d // (2**30)} GB Libre)"
        except Exception:
            disk_usage_str = "Desconocido"

        # Build HTML en español
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #333;">📊 Resumen de Ejecución de Backup</h2>
            <table style="border-collapse: collapse; margin-bottom: 20px;">
                <tr><td style="padding: 5px 15px;"><b>Total Dispositivos:</b></td><td>{total}</td></tr>
                <tr><td style="padding: 5px 15px;"><b>Exitosos:</b></td><td style="color:green; font-weight:bold;">{success}</td></tr>
                <tr><td style="padding: 5px 15px;"><b>Errores:</b></td><td style="color:red; font-weight:bold;">{errors}</td></tr>
                <tr><td style="padding: 5px 15px;"><b>Deshabilitados:</b></td><td style="color:orange; font-weight:bold;">{disabled_count}</td></tr>
                <tr><td style="padding: 5px 15px;"><b>Duración:</b></td><td>{duration:.2f} segundos</td></tr>
                <tr><td style="padding: 5px 15px;"><b>Uso de Disco ({BACKUP_ROOT_DIR}):</b></td><td>{disk_usage_str}</td></tr>
            </table>
        """

        if failed_hosts:
            html += """
            <h3 style="color:red;">❌ Dispositivos con Error</h3>
            <ul style="color: #666;">
            """
            for host, reason in failed_hosts.items():
                html += f"<li><b>{host}</b>: {reason}</li>"
            html += "</ul>"

        if disabled_devices:
            html += """
            <h3 style="color:orange;">⏸️ Dispositivos Deshabilitados (no se respaldaron)</h3>
            <table style="border-collapse: collapse; font-size: 14px;">
                <tr style="background: #f5f5f5;">
                    <th style="padding: 5px 10px; text-align: left;">Dispositivo</th>
                    <th style="padding: 5px 10px; text-align: left;">Grupo</th>
                    <th style="padding: 5px 10px; text-align: left;">Motivo</th>
                    <th style="padding: 5px 10px; text-align: left;">Deshabilitado por</th>
                    <th style="padding: 5px 10px; text-align: left;">Fecha</th>
                </tr>
            """
            for dev in disabled_devices:
                sysname = dev.get('sysname') or dev.get('hostname', 'Unknown')
                group = dev.get('_group_name', '-')
                reason = dev.get('disabled_reason', 'Sin motivo especificado')
                disabled_by = dev.get('disabled_by', '-')
                disabled_at = dev.get('disabled_at', '-')
                if disabled_at and len(disabled_at) > 16:
                    disabled_at = disabled_at[:16]  # Truncate to YYYY-MM-DD HH:MM
                html += f"""
                <tr>
                    <td style="padding: 5px 10px; border-bottom: 1px solid #eee;"><b>{sysname}</b></td>
                    <td style="padding: 5px 10px; border-bottom: 1px solid #eee;">{group}</td>
                    <td style="padding: 5px 10px; border-bottom: 1px solid #eee;">{reason}</td>
                    <td style="padding: 5px 10px; border-bottom: 1px solid #eee;">{disabled_by}</td>
                    <td style="padding: 5px 10px; border-bottom: 1px solid #eee;">{disabled_at}</td>
                </tr>
                """
            html += "</table>"

        if diff_summary:
            html += """
            <h3 style="color: #0066cc;">🔄 Cambios de Configuración Detectados</h3>
            <ul>
            """
            for host, diff in diff_summary.items():
                short_diff = diff[:500] + "..." if len(diff) > 500 else diff
                html += f"<li><b>{host}</b>:<br><pre style='background:#f5f5f5;padding:10px;font-size:12px;'>{short_diff}</pre></li>"
            html += "</ul>"

        html += """
            <hr style="border: 1px solid #eee;">
            <p style="color: #999; font-size: 12px;"><i>Generado automáticamente por el Sistema de Backup</i></p>
        </body>
        </html>
        """

        return self._send_email(subject, html, cfg)

    def send_test_email(self):
        """Envía un email de prueba para verificar configuración SMTP."""
        cfg = self._get_config()
        
        if not cfg['host']:
            return False, "Host SMTP no configurado"
        if not cfg['recipients']:
            return False, "No hay destinatarios configurados"
        
        subject = "🔧 Sistema de Backup - Email de Prueba"
        html = """
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #28a745;">✅ Prueba de Configuración de Email</h2>
            <p>Este es un email de prueba del Sistema de Backup.</p>
            <p>Si recibiste este mensaje, tu configuración SMTP está funcionando correctamente.</p>
            <hr style="border: 1px solid #eee;">
            <p style="color: #999; font-size: 12px;"><i>Generado automáticamente por el Sistema de Backup</i></p>
        </body>
        </html>
        """
        
        success = self._send_email(subject, html, cfg)
        if success:
            return True, "Email de prueba enviado correctamente"
        else:
            return False, "Error al enviar email - revisar logs"

    def _send_email(self, subject, body_html, cfg):
        """Send email using enterprise SMTP config."""
        try:
            msg = MIMEMultipart()
            msg['From'] = cfg['from_addr']
            msg['To'] = ", ".join(cfg['recipients'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body_html, 'html'))

            transport = cfg['transport']
            host = cfg['host']
            port = cfg['port']
            timeout = cfg['timeout']
            
            log.debug(f"Conectando a SMTP {host}:{port} (transporte={transport})")
            
            if transport == 'ssl':
                server = smtplib.SMTP_SSL(host, port, timeout=timeout)
            else:
                server = smtplib.SMTP(host, port, timeout=timeout)
                if transport == 'starttls':
                    server.starttls()
            
            if cfg['auth_required'] and cfg['user'] and cfg['password']:
                log.debug(f"Autenticando como {cfg['user']}")
                server.login(cfg['user'], cfg['password'])
            
            server.sendmail(cfg['from_addr'], cfg['recipients'], msg.as_string())
            server.quit()
            
            log.info(f"Email enviado: {subject}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            log.error(f"Error de autenticación SMTP: {e}")
            return False
        except smtplib.SMTPConnectError as e:
            log.error(f"Error de conexión SMTP: {e}")
            return False
        except smtplib.SMTPException as e:
            log.error(f"Error SMTP: {e}")
            return False
        except Exception as e:
            log.error(f"Error al enviar email: {e}")
            return False
