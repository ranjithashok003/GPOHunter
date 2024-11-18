from enum import Enum
from colorama import init, Fore, Style
import ldap3
from base64 import b64decode
import re
from Crypto.Cipher import AES

init()  # Инициализация colorama для Windows

class SecurityLevel(Enum):
    HIGH = (Fore.RED + "HIGH" + Style.RESET_ALL)
    MEDIUM = (Fore.YELLOW + "MEDIUM" + Style.RESET_ALL)
    LOW = (Fore.BLUE + "LOW" + Style.RESET_ALL)
    INFO = (Fore.GREEN + "INFO" + Style.RESET_ALL)

class SecurityCheck:
    def __init__(self, name, description, level, affected_gpo=None, details=None):
        self.name = name
        self.description = description
        self.level = level
        self.affected_gpo = affected_gpo or []
        self.details = details or {}
        self.affected_objects = {}  # Словарь для хранения затронутых объектов по каждому GPO

    def analyze_scope(self, ldap_conn, base_dn):
        """Анализ области применения GPO"""
        for gpo in self.affected_gpo:
            ou_links = gpo.get('linked_ous', [])
            self.affected_objects[gpo['guid']] = {
                'name': gpo['name'],
                'scope': self._analyze_gpo_scope(ldap_conn, base_dn, ou_links)
            }

    def _analyze_gpo_scope(self, ldap_conn, base_dn, ou_links):
        """Анализ области применения конкретной GPO"""
        scope_info = {
            'domain_wide': False,
            'affected_ous': [],
        }

        if any(ou == base_dn for ou in ou_links):
            scope_info['domain_wide'] = True
            return scope_info

        for ou in ou_links:
            ou_info = self._get_ou_info(ldap_conn, ou)
            scope_info['affected_ous'].append(ou_info)

        return scope_info

    def _get_ou_info(self, ldap_conn, ou_dn):
        """Get information about OU and nested objects"""
        ou_info = {
            'dn': ou_dn,
            'objects': [],
            'sub_ous': []
        }

        try:
            # Search for subordinate OUs
            ldap_conn.search(
                search_base=ou_dn,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=ldap3.LEVEL,
                attributes=['distinguishedName']
            )

            for entry in ldap_conn.entries:
                sub_ou_info = self._get_ou_info(ldap_conn, entry.distinguishedName.value)
                ou_info['sub_ous'].append(sub_ou_info)

            # Search for objects in OU
            ldap_conn.search(
                search_base=ou_dn,
                search_filter='(|(objectClass=user)(objectClass=computer)(objectClass=group))',
                search_scope=ldap3.LEVEL,
                attributes=['distinguishedName', 'objectClass', 'name']
            )

            for entry in ldap_conn.entries:
                # Determine object type based on objectClass
                obj_classes = [cls.lower() for cls in entry.objectClass.value]
                
                if 'computer' in obj_classes:
                    obj_type = 'computer'
                elif 'group' in obj_classes:
                    obj_type = 'group'
                elif 'user' in obj_classes or 'person' in obj_classes:
                    obj_type = 'user'
                else:
                    obj_type = obj_classes[-1]  # take the last class as type

                ou_info['objects'].append({
                    'name': entry.name.value,
                    'type': obj_type,
                    'dn': entry.distinguishedName.value
                })

        except Exception as e:
            print(f"[!] Error analyzing OU {ou_dn}: {str(e)}")

        return ou_info

    def print_findings(self, verbose=False):
        """Print information about findings"""
        print(f"\n[{self.level.value}] {self.name}")
        print(f"├── Description: {self.description}")
        print("├── Affected Objects:")

        for gpo_guid, info in self.affected_objects.items():
            print(f"│   ├── GPO: {info['name']} ({gpo_guid})")
            scope = info['scope']

            if scope['domain_wide']:
                print(f"│   │   └── {Fore.RED}Applies to entire domain!{Style.RESET_ALL}")
            else:
                for ou_info in scope['affected_ous']:
                    self._print_ou_info(ou_info, level=3)

        if verbose:
            print("├── Details:")
            for key, value in self.details.items():
                print(f"│   ├── {key}: {value}")

    def _print_ou_info(self, ou_info, level):
        """Recursive output of OU information and nested objects"""
        indent = "│   " * level
        print(f"{indent}├── OU: {ou_info['dn']}")
        for obj in ou_info['objects']:
            color = self._get_object_type_color(obj['type'])
            # Define correct object type for display
            display_type = {
                'user': 'User',
                'computer': 'Computer',
                'group': 'Group'
            }.get(obj['type'].lower(), obj['type'])
            print(f"{indent}│   ├── {color}{display_type}: {obj['name']}{Style.RESET_ALL}")
        for sub_ou in ou_info['sub_ous']:
            self._print_ou_info(sub_ou, level + 1)

    @staticmethod
    def _get_object_type_color(obj_type):
        """Get color for object type"""
        obj_type = obj_type.lower()
        colors = {
            'user': Fore.YELLOW,
            'computer': Fore.CYAN,
            'group': Fore.GREEN,
            'person': Fore.YELLOW,  # In case type is defined as person
            'computerobject': Fore.CYAN  # In case type is defined as computerObject
        }
        return colors.get(obj_type, Fore.WHITE)

class GPOSecurityChecker:
    def __init__(self, gpo_analyzer):
        self.gpo_analyzer = gpo_analyzer
        self.findings = []
        self.ldap_conn = gpo_analyzer.ldap_conn
        self.base_dn = gpo_analyzer.gpo_finder.base_dn
        # Key for decrypting GPP passwords (publicly known)
        self.gpp_key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'

    def check_all(self, gpos):
        """Perform all security checks"""
        for gpo in gpos:
            self._check_clear_text_password(gpo)
            self._check_gpp_password(gpo)
            self._check_lm_compatibility(gpo)
        
        # Analyze scope for each finding
        for finding in self.findings:
            finding.analyze_scope(self.ldap_conn, self.base_dn)

    def _check_lm_compatibility(self, gpo):
        """Checks for insecure LmCompatibilityLevel settings in GPO"""
        try:
            details = self.gpo_analyzer.analyze_gpo(gpo['guid'], detail_level='full', show_xml=True)
            xml_content = details.get('xml_content', {})

            for file_path, content in xml_content.items():
                if 'GptTmpl.inf' in file_path:
                    if 'LmCompatibilityLevel=4,0' in content or 'LmCompatibilityLevel=4,1' in content:
                        finding = SecurityCheck(
                            name="NetNTLMv1 Authentication Enabled",
                            description=(
                                "NetNTLMv1 authentication protocol is enabled in GPO. "
                                "NetNTLMv1 is an insecure authentication protocol that "
                                "can be exploited in conjunction with Coerce for Relay attacks, "
                                "and also allows password cracking using rainbow tables."
                            ),
                            level=SecurityLevel.HIGH,
                            affected_gpo=[{
                                'name': gpo['name'],
                                'guid': gpo['guid'],
                                'linked_ous': self.gpo_analyzer.gpo_finder.get_gpo_links(gpo['guid'])
                            }],
                            details={
                                'file': file_path,
                                'setting': re.search(r'LmCompatibilityLevel=4,[01]', content).group(0)
                            }
                        )
                        self.findings.append(finding)
                break
        except Exception as e:
            print(f"[ERROR] Error checking LM compatibility for GPO {gpo['name']}: {str(e)}")
                        

    def _check_clear_text_password(self, gpo):
        """Checks for ClearTextPassword = 1 setting"""
        try:
            details = self.gpo_analyzer.analyze_gpo(gpo['guid'], detail_level='full', show_xml=True)
            xml_content = details.get('xml_content', {})
            
            for file_path, content in xml_content.items():
                if 'SecEdit\\GptTmpl.inf' in file_path:
                    if 'ClearTextPassword = 1' in content:
                        finding = SecurityCheck(
                            name="Clear Text Password Storage Enabled",
                            description=(
                                "Clear text password storage is enabled. "
                                "The 'ClearTextPassword = 1' setting allows storing "
                                "passwords in unencrypted form, which is a critical "
                                "security vulnerability."
                            ),
                            level=SecurityLevel.HIGH,
                            affected_gpo=[{
                                'name': gpo['name'],
                                'guid': gpo['guid'],
                                'linked_ous': self.gpo_analyzer.gpo_finder.get_gpo_links(gpo['guid'])
                            }],
                            details={
                                'file': file_path,
                                'setting': 'ClearTextPassword = 1'
                            }
                        )
                        self.findings.append(finding)
                        break
                        
        except Exception as e:
            print(f"[!] Error checking ClearTextPassword for GPO {gpo['name']}: {str(e)}")

    def _check_gpp_password(self, gpo):
        """
        Checks for encrypted passwords in GPP (MS14-025)
        Examines various GPP files for encrypted passwords
        """
        try:
            details = self.gpo_analyzer.analyze_gpo(gpo['guid'], detail_level='full', show_xml=True)
            xml_content = details.get('xml_content', {})
            
            gpp_files = [
                '\\Groups\\Groups.xml',          # Local groups
                '\\Services\\Services.xml',      # Services
                '\\ScheduledTasks\\*.xml',       # Scheduled Tasks
                '\\DataSources\\DataSources.xml',# Data Sources
                '\\Printers\\Printers.xml',      # Printers
                '\\Drives\\Drives.xml'           # Drive Maps
            ]
            
            encrypted_passwords = []
            
            for file_path, content in xml_content.items():
                for gpp_file in gpp_files:
                    if gpp_file.replace('*', '') in file_path:
                        cpasswords = re.findall(r'cpassword="([^"]+)"', content)
                        for cpassword in cpasswords:
                            try:
                                decrypted = self._decrypt_cpassword(cpassword)
                                encrypted_passwords.append({
                                    'file': file_path,
                                    'encrypted': cpassword,
                                    'decrypted': decrypted
                                })
                            except Exception:
                                continue
            
            if encrypted_passwords:
                finding = SecurityCheck(
                    name="GPP Encrypted Passwords (MS14-025)",
                    description=(
                        "Encrypted passwords found in Group Policy Preferences. "
                        "These passwords are encrypted with a known key and can be easily decrypted. "
                        "This is a critical security vulnerability (MS14-025)."
                    ),
                    level=SecurityLevel.HIGH,
                    affected_gpo=[{
                        'name': gpo['name'],
                        'guid': gpo['guid'],
                        'linked_ous': self.gpo_analyzer.gpo_finder.get_gpo_links(gpo['guid'])
                    }],
                    details={
                        'passwords': encrypted_passwords,
                        'recommendation': (
                            "1. Immediately remove passwords from GPP\n"
                            "2. Change all discovered passwords\n"
                            "3. Use group policies without storing passwords"
                        )
                    }
                )
                self.findings.append(finding)
                        
        except Exception as e:
            print(f"[!] Error checking GPP passwords for GPO {gpo['name']}: {str(e)}")

    def _decrypt_cpassword(self, cpassword):
        """Decrypt GPP password"""
        if not cpassword:
            return ""

        # Add padding to encrypted password
        mod = len(cpassword) % 4
        if mod:
            cpassword += '=' * (4 - mod)

        # Decode base64 and decrypt AES
        encrypted = b64decode(cpassword)
        cipher = AES.new(self.gpp_key, AES.MODE_CBC, IV=b'\00' * 16)
        decrypted = cipher.decrypt(encrypted)

        # Remove padding
        try:
            padding = decrypted[-1]
            if padding > 16:
                return decrypted.decode('utf-16le')
            if all(x == padding for x in decrypted[-padding:]):
                decrypted = decrypted[:-padding]
            return decrypted.decode('utf-16le')
        except Exception:
            return decrypted.decode('utf-16le')

    def print_findings(self, verbose=False):
        """Print security check results"""
        if not self.findings:
            print(f"\n{Fore.GREEN}[+] No security issues found{Style.RESET_ALL}")
            return

        print(f"\n{Fore.RED}[!] Security issues found:{Style.RESET_ALL}")
        for finding in self.findings:
            finding.print_findings(verbose)