from impacket.smbconnection import SMBConnection
from io import BytesIO

class SMBConnector:
    def __init__(self, ldap_conn):
        self.ldap_conn = ldap_conn
        self.smb_conn = None
        self.sysvol_path = None
        self._domain = self._get_domain()
        
    def _get_domain(self):
        """Get full domain name from DN"""
        domain_parts = []
        dn_parts = self.ldap_conn.server.info.other['defaultNamingContext'][0].split(',')
        for part in dn_parts:
            if part.startswith('DC='):
                domain_parts.append(part.split('=')[1])
        return '.'.join(domain_parts)
    
    def connect(self):
        """Establish SMB connection"""
        if self.smb_conn:
            return self.smb_conn
            
        try:
            # Get credentials from LDAP connection
            if hasattr(self.ldap_conn, 'user'):
                username = self.ldap_conn.user
                if '\\' in username:
                    username = username.split('\\')[1]
                password = self.ldap_conn.password
            else:
                connection_string = str(self.ldap_conn)
                if 'user=' in connection_string:
                    username = connection_string.split('user=')[1].split(',')[0]
                    if '\\' in username:
                        username = username.split('\\')[1]
                    password = connection_string.split('password=')[1].split(',')[0]
                else:
                    raise Exception("Failed to get credentials from LDAP connection")
            
            self.smb_conn = SMBConnection(
                self.ldap_conn.server.host,
                self.ldap_conn.server.host,
                timeout=30
            )
            
            if ':' in password:
                # Assuming password is in the format lm:nt
                lm_hash, nt_hash = password.split(':')
                self.smb_conn.login(
                    username,
                    '',
                    self._domain,
                    lmhash=lm_hash,
                    nthash=nt_hash
                )
            else:
                self.smb_conn.login(
                    username,
                    password,
                    self._domain
                )
            
            self.sysvol_path = f"\\\\{self.ldap_conn.server.host}\\SYSVOL\\{self._domain}\\Policies"
            return self.smb_conn
            
        except Exception as e:
            print(f"[!] SMB connection error: {str(e)}")
            return None
    
    def get_file_content(self, share_path):
        """Read file through SMB"""
        try:
            if not self.smb_conn:
                if not self.connect():
                    return None
                    
            file_obj = BytesIO()
            self.smb_conn.getFile('SYSVOL', share_path, file_obj.write)
            return file_obj.getvalue()
            
        except Exception as e:
            if 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e) or 'STATUS_OBJECT_PATH_NOT_FOUND' in str(e):
                return None
            raise e
    
    def check_file_exists(self, share_path):
        """Check if file exists"""
        try:
            if not self.smb_conn:
                if not self.connect():
                    return False
                    
            self.smb_conn.listPath('SYSVOL', share_path)
            return True
            
        except Exception:
            return False
    
    def get_sysvol_path(self):
        """Get path to SYSVOL"""
        if not self.sysvol_path:
            self.connect()
        return self.sysvol_path