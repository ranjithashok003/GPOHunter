from ldap3 import SUBTREE
import re
from datetime import datetime
import os
import configparser
from .smb_connector import SMBConnector
import xml.etree.ElementTree as ET
from base64 import b64decode
import binascii
from io import BytesIO

class GPOAnalyzer:
    def __init__(self, ldap_conn, gpo_finder):
        # Initialize GPOAnalyzer with LDAP connection and GPO finder
        self.ldap_conn = ldap_conn
        self.gpo_finder = gpo_finder
        self.conn = ldap_conn
        self.smb = SMBConnector(ldap_conn)
        
    def analyze_gpo(self, gpo_guid, detail_level='basic', show_xml=False):
        """Analyze specific GPO"""
        try:
            # Get basic information about GPO
            gpo_info = self.gpo_finder.get_gpo_info(gpo_guid)
            if not gpo_info:
                return None

            # Check GPO status flags
            flags = int(gpo_info.get('flags', 0))
            # GPO is disabled only if the disable flag is explicitly set (usually 1)
            # By default, consider GPO enabled
            is_enabled = flags != 1

            basic_info = {
                'name': gpo_info.get('displayName', 'Unknown'),
                'enabled': is_enabled,  # Changed logic for determining status
                'created': gpo_info.get('whenCreated', 'Unknown'),
                'modified': gpo_info.get('whenChanged', 'Unknown'),
                'path': gpo_info.get('gPCFileSysPath', '')
            }

            gpo_details = {
                'basic_info': basic_info,
                'scope': self._get_scope_info(gpo_guid)
            }
            
            if detail_level in ['full', 'custom']:
                gpo_details.update({
                    'security_settings': self._get_security_settings(gpo_guid),
                    'mapped_drives': self._get_mapped_drives(gpo_guid),
                    'scheduled_tasks': self._get_scheduled_tasks(gpo_guid),
                    'scripts': self._get_scripts(gpo_guid),
                    'software_installation': self._get_software_settings(gpo_guid),
                    'registry_settings': self._get_registry_settings(gpo_guid)
                })
                
            # Add XML file content if requested
            if show_xml:
                gpo_details['xml_content'] = self._get_gpo_xml_content(gpo_guid)
                
            return gpo_details
            
        except Exception as e:
            raise Exception(f"Error analyzing GPO {gpo_guid}: {str(e)}")
    
    def _get_basic_info(self, gpo_guid):
        """Get basic information about GPO"""
        gpo_dn = f"CN={{{gpo_guid}}},CN=Policies,CN=System,{self.gpo_finder.base_dn}"
        attributes = [
            'displayName', 'description', 'flags', 'whenCreated', 
            'whenChanged', 'versionNumber', 'gPCUserExtensionNames',
            'gPCMachineExtensionNames'
        ]
        
        try:
            self.conn.search(
                search_base=gpo_dn,
                search_filter='(objectClass=groupPolicyContainer)',
                attributes=attributes
            )
            
            if not self.conn.entries:
                raise Exception(f"GPO with GUID {gpo_guid} not found")
                
            entry = self.conn.entries[0]
            return {
                'name': entry.displayName.value if hasattr(entry, 'displayName') else None,
                'description': entry.description.value if hasattr(entry, 'description') else None,
                'enabled': bool(int(entry.flags.value) & 1) if hasattr(entry, 'flags') else True,
                'created': entry.whenCreated.value if hasattr(entry, 'whenCreated') else None,
                'modified': entry.whenChanged.value if hasattr(entry, 'whenChanged') else None,
                'version': entry.versionNumber.value if hasattr(entry, 'versionNumber') else None
            }
            
        except Exception as e:
            raise Exception(f"Error getting basic information: {str(e)}")
    
    def _get_scope_info(self, gpo_guid):
        """Get information about GPO scope"""
        try:
            return {
                'linked_ous': self.gpo_finder.get_gpo_links(gpo_guid),
                'security_groups': self._get_security_groups(gpo_guid),
                'wmi_filters': self._get_wmi_filters(gpo_guid)
            }
        except Exception as e:
            raise Exception(f"Error getting scope information: {str(e)}")
    
    def _get_security_groups(self, gpo_guid):
        """Get security groups applied to GPO"""
        gpo_dn = f"CN={{{gpo_guid}}},CN=Policies,CN=System,{self.gpo_finder.base_dn}"
        try:
            self.ldap_conn.search(
                search_base=gpo_dn,
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor']
            )
            
            security_groups = []
            if self.ldap_conn.entries:
                # Parse ACL and extract groups
                # TODO: Implement ACL parsing
                pass
                
            return security_groups
            
        except Exception as e:
            raise Exception(f"Error getting security groups: {str(e)}")
    
    def _get_wmi_filters(self, gpo_guid):
        """Get WMI filters linked to GPO"""
        try:
            wmi_filter_container = f"CN=SOM,CN=WMIPolicy,CN=System,{self.gpo_finder.base_dn}"
            self.conn.search(
                search_base=wmi_filter_container,
                search_filter=f'(gpLink=*{gpo_guid}*)',
                attributes=['msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2']
            )
            
            wmi_filters = []
            for entry in self.conn.entries:
                if hasattr(entry, 'msWMI-Name'):
                    wmi_filters.append({
                        'name': entry['msWMI-Name'].value,
                        'query': entry['msWMI-Parm2'].value if hasattr(entry, 'msWMI-Parm2') else None
                    })
                    
            return wmi_filters
            
        except Exception as e:
            raise Exception(f"Error getting WMI filters: {str(e)}")
    
    def _get_security_settings(self, gpo_guid):
        """Get security settings from GptTmpl.inf"""
        try:
            share_path = f"{self.smb.get_sysvol_path()}\\{{{gpo_guid}}}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
            share_path = share_path.replace(f"\\\\{self.ldap_conn.server.host}\\SYSVOL\\", '')
            
            if not self.smb.check_file_exists(share_path):
                return {}
                
            content = self.smb.get_file_content(share_path)
            if not content:
                return {}
                
            # Try different encodings to decode content
            decoded_content = None
            for encoding in ['utf-16', 'utf-8', 'latin1', 'utf-16le']:
                try:
                    decoded_content = content.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue
                    
            if not decoded_content:
                return {}
                
            # Create a temporary file for configparser
            temp_file = 'temp_gpt.inf'
            try:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(decoded_content)
                
                config = configparser.ConfigParser()
                config.read(temp_file, encoding='utf-8')
                
                security_settings = {}
                sections_to_parse = [
                    'System Access',
                    'Event Audit',
                    'Registry Values',
                    'Privilege Rights',
                    'Service General Setting'
                ]
                
                for section in sections_to_parse:
                    if config.has_section(section):
                        security_settings[section] = dict(config.items(section))
                
                if 'System Access' in security_settings:
                    self._parse_system_access(security_settings['System Access'])
                
                if 'Event Audit' in security_settings:
                    self._parse_event_audit(security_settings['Event Audit'])
                
                if 'Privilege Rights' in security_settings:
                    self._parse_privilege_rights(security_settings['Privilege Rights'])
                
                return security_settings
                
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                
        except Exception as e:
            raise Exception(f"Error reading security settings: {str(e)}")
    
    def _parse_system_access(self, settings):
        """Parse System Access section"""
        # Convert numeric values to understandable settings
        boolean_settings = [
            'ClearTextPassword',
            'RequireLogonToChangePassword',
            'ForceLogoffWhenHourExpire'
        ]
        
        for setting in boolean_settings:
            if setting in settings:
                settings[setting] = settings[setting] == '1'
        
        # Convert time values
        time_settings = [
            'MaximumPasswordAge',
            'MinimumPasswordAge',
            'LockoutDuration',
            'ResetLockoutCount'
        ]
        
        for setting in time_settings:
            if setting in settings:
                try:
                    value = int(settings[setting])
                    if value == -1:
                        settings[setting] = "Never"
                    elif value > 0:
                        settings[setting] = f"{value} days"
                except ValueError:
                    pass
    
    def _parse_event_audit(self, settings):
        """Parse Event Audit section"""
        audit_values = {
            '0': 'No Auditing',
            '1': 'Success',
            '2': 'Failure',
            '3': 'Success, Failure'
        }
        
        for setting, value in settings.items():
            if value in audit_values:
                settings[setting] = audit_values[value]
    
    def _parse_privilege_rights(self, settings):
        """Parse Privilege Rights section"""
        for privilege, sids in settings.items():
            # Convert SIDs to account names
            sid_list = sids.split(',')
            account_names = []
            
            for sid in sid_list:
                try:
                    # Get account name by SID
                    self.conn.search(
                        search_base=self.gpo_finder.base_dn,
                        search_filter=f'(objectSid={sid.strip()})',
                        attributes=['sAMAccountName']
                    )
                    
                    if self.conn.entries:
                        account_names.append(
                            self.conn.entries[0].sAMAccountName.value
                        )
                    else:
                        account_names.append(sid.strip())
                        
                except Exception:
                    account_names.append(sid.strip())
            
            settings[privilege] = account_names
    
    def _get_mapped_drives(self, gpo_guid):
        """Get mapped drive settings"""
        # TODO: Implement reading Drive Maps
        return []
    
    def _get_scheduled_tasks(self, gpo_guid):
        """Get scheduled task settings"""
        try:
            tasks = {
                'immediate': [],
                'scheduled': []
            }
            
            # Paths to task files
            paths = [
                f"\\{{{gpo_guid}}}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
                f"\\{{{gpo_guid}}}\\User\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
            ]
            
            for path in paths:
                share_path = path.replace('\\', '/', 1)  # Convert path for SMB
                if self.smb.check_file_exists(share_path):
                    content = self.smb.get_file_content(share_path)
                    if content:
                        # Parse XML and add tasks
                        try:
                            root = ET.fromstring(content.decode('utf-16'))
                            for task in root.findall(".//TaskV2"):
                                task_info = {
                                    'name': task.get('name', ''),
                                    'action': self._parse_task_action(task),
                                    'triggers': self._parse_task_triggers(task),
                                    'principal': self._parse_task_principal(task),
                                    'settings': self._parse_task_settings(task),
                                    'enabled': task.get('disabled', '0') != '1'
                                }
                                tasks['scheduled'].append(task_info)
                        except ET.ParseError:
                            print(f"[-] Error parsing XML task file: {path}")
            
            return tasks
            
        except Exception as e:
            raise Exception(f"Error reading scheduled tasks: {str(e)}")
    
    def _get_immediate_tasks(self, gpo_guid):
        """Get immediate tasks"""
        immediate_tasks = []
        tasks_path = f"{self.sysvol_path}\\{{{gpo_guid}}}\\Machine\\Preferences\\Tasks\\Immediate"
        
        try:
            if not os.path.exists(tasks_path):
                return immediate_tasks
                
            for file in os.listdir(tasks_path):
                if file.endswith('.xml'):
                    task_path = os.path.join(tasks_path, file)
                    tree = ET.parse(task_path)
                    root = tree.getroot()
                    
                    for task in root.findall(".//ImmediateTask"):
                        task_info = {
                            'name': task.get('name', ''),
                            'action': self._parse_task_action(task),
                            'principal': self._parse_task_principal(task),
                            'enabled': task.get('disabled', '0') != '1'
                        }
                        immediate_tasks.append(task_info)
                        
            return immediate_tasks
            
        except Exception as e:
            raise Exception(f"Error reading immediate tasks: {str(e)}")
    
    def _get_scheduled_task_files(self, gpo_guid):
        """Get scheduled tasks"""
        scheduled_tasks = []
        tasks_path = f"{self.sysvol_path}\\{{{gpo_guid}}}\\Machine\\Preferences\\ScheduledTasks"
        
        try:
            if not os.path.exists(tasks_path):
                return scheduled_tasks
                
            for root, dirs, files in os.walk(tasks_path):
                for file in files:
                    if file.endswith('.xml'):
                        task_path = os.path.join(root, file)
                        tree = ET.parse(task_path)
                        root = tree.getroot()
                        
                        for task in root.findall(".//TaskV2"):
                            task_info = {
                                'name': task.get('name', ''),
                                'action': self._parse_task_action(task),
                                'triggers': self._parse_task_triggers(task),
                                'principal': self._parse_task_principal(task),
                                'settings': self._parse_task_settings(task),
                                'enabled': task.get('disabled', '0') != '1'
                            }
                            scheduled_tasks.append(task_info)
                            
            return scheduled_tasks
            
        except Exception as e:
            raise Exception(f"Error reading scheduled tasks: {str(e)}")
    
    def _parse_task_action(self, task):
        """Parse task actions"""
        actions = []
        for action in task.findall(".//Exec"):
            action_info = {
                'type': 'Exec',
                'command': action.get('command', ''),
                'arguments': action.get('arguments', ''),
                'working_dir': action.get('workingDirectory', '')
            }
            
            # Decode encoded commands
            if action_info['command'].startswith('##'):
                try:
                    decoded = b64decode(action_info['command'][2:]).decode('utf-16le')
                    action_info['command'] = decoded
                except (binascii.Error, UnicodeDecodeError):
                    pass
                    
            actions.append(action_info)
        return actions
    
    def _parse_task_principal(self, task):
        """Parse task user information"""
        principal = task.find(".//Principal")
        if principal is not None:
            return {
                'user_id': principal.get('userId', ''),
                'run_level': principal.get('runLevel', ''),
                'logon_type': principal.get('logonType', '')
            }
        return {}
    
    def _parse_task_triggers(self, task):
        """Parse task triggers"""
        triggers = []
        for trigger in task.findall(".//Trigger"):
            trigger_info = {
                'type': trigger.get('type', ''),
                'start_boundary': trigger.get('startBoundary', ''),
                'end_boundary': trigger.get('endBoundary', ''),
                'enabled': trigger.get('enabled', 'true') == 'true'
            }
            
            # Additional parameters depending on trigger type
            if trigger.get('type') == 'TASK_TRIGGER_DAILY':
                trigger_info['interval_days'] = trigger.get('intervalDays', '1')
            elif trigger.get('type') == 'TASK_TRIGGER_WEEKLY':
                trigger_info['days_of_week'] = trigger.get('daysOfWeek', '')
                trigger_info['weeks_interval'] = trigger.get('weeksInterval', '1')
                
            triggers.append(trigger_info)
        return triggers
    
    def _parse_task_settings(self, task):
        """Parse task settings"""
        settings = task.find(".//Settings")
        if settings is not None:
            return {
                'allow_hard_terminate': settings.get('allowHardTerminate', 'true') == 'true',
                'restart_on_failure': settings.get('restartOnFailure', 'false') == 'true',
                'run_only_if_idle': settings.get('runOnlyIfIdle', 'false') == 'true',
                'hidden': settings.get('hidden', 'false') == 'true',
                'run_only_if_network_available': settings.get('runOnlyIfNetworkAvailable', 'false') == 'true'
            }
        return {}
    
    def _get_scripts(self, gpo_guid):
        """Get script settings"""
        # TODO: Implement reading Scripts
        return {
            'startup': [],
            'shutdown': [],
            'logon': [],
            'logoff': []
        }
    
    def _get_software_settings(self, gpo_guid):
        """Get software installation settings"""
        # TODO: Implement reading Software Installation
        return []
    
    def _get_registry_settings(self, gpo_guid):
        """Get registry settings"""
        # TODO: Implement reading Registry Settings
        return [] 
    
    def _connect_to_sysvol(self):
        """Connect to SYSVOL via SMB"""
        if not self.sysvol_path:
            try:
                # Get full domain name from DN
                domain_parts = []
                dn_parts = self.gpo_finder.base_dn.split(',')
                for part in dn_parts:
                    if part.startswith('DC='):
                        domain_parts.append(part.split('=')[1])
                
                domain = '.'.join(domain_parts)  # Now it will be roasting.lab instead of lab
                
                print(f"[*] Connecting to SYSVOL on {self.ldap_conn.server.host}")
                print(f"[*] Domain: {domain}")
                
                # Get credentials from LDAP connection
                if hasattr(self.ldap_conn, 'user'):
                    username = self.ldap_conn.user
                    if '\\' in username:
                        username = username.split('\\')[1]
                    password = self.ldap_conn.password
                else:
                    # If unable to get credentials directly
                    connection_string = str(self.ldap_conn)
                    if 'user=' in connection_string:
                        username = connection_string.split('user=')[1].split(',')[0]
                        if '\\' in username:
                            username = username.split('\\')[1]
                        password = connection_string.split('password=')[1].split(',')[0]
                    else:
                        raise Exception("Failed to get credentials from LDAP connection")

                print(f"[*] Attempting login as: {username}")
                
                smb = SMBConnection(
                    self.ldap_conn.server.host,
                    self.ldap_conn.server.host,
                    timeout=30
                )
                
                smb.login(
                    username,
                    password,
                    domain
                )
                
                self.sysvol_path = f"\\\\{self.ldap_conn.server.host}\\SYSVOL\\{domain}\\Policies"
                print(f"[*] SYSVOL path: {self.sysvol_path}")
                return smb
                
            except Exception as e:
                print(f"[!] Error connecting to SYSVOL: {str(e)}")
                return None
    
    def _get_gpo_xml_content(self, gpo_guid):
        """Get GPO XML file content"""
        try:
            xml_content = {}
            
            if not self.smb.connect():
                return xml_content
            
            gpo_path = f"{self.smb.get_sysvol_path()}\\{{{gpo_guid}}}"
            
            paths = [
                '\\Machine\\Preferences\\Groups\\Groups.xml',
                '\\User\\Preferences\\Groups\\Groups.xml',
                '\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
                '\\GPT.INI',
                '\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
                '\\User\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
                '\\Machine\\Registry.pol',
                '\\User\\Registry.pol'
            ]
            
            for path in paths:
                try:
                    share_path = gpo_path.replace(f"\\\\{self.ldap_conn.server.host}\\SYSVOL\\", '') + path
                    
                    if self.smb.check_file_exists(share_path):
                        content = self.smb.get_file_content(share_path)
                        if content:
                            for encoding in ['utf-16', 'utf-8', 'latin1']:
                                try:
                                    decoded = content.decode(encoding)
                                    xml_content[path] = decoded
                                    break
                                except UnicodeDecodeError:
                                    continue
                            else:
                                xml_content[path] = content.hex()
                        
                except Exception:
                    continue
                    
            return xml_content
            
        except Exception as e:
            return {}