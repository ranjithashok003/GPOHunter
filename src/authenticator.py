from ldap3 import Server, Connection, NTLM, SIMPLE, SASL, KERBEROS, ALL, LEVEL
from ldap3.core.exceptions import LDAPException
import ssl

class ADAuthenticator:
    def __init__(self, username=None, password=None, domain=None, 
                 dc_host=None, ntlm_hash=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_host = dc_host
        self.ntlm_hash = ntlm_hash
        self.conn = None
        
    def connect(self):
        """Establish connection to Active Directory"""
        try:
            # Create server without SSL/TLS
            server = Server(
                self.dc_host,
                get_info=ALL,
                use_ssl=False
            )
            
            # Format username as domain\username
            user = None
            if self.username:
                # Change format to domain\username for NTLM authentication
                user = f"{self.domain}\\{self.username}" if self.domain else self.username
            
            # Always use NTLM authentication instead of SIMPLE
            self.conn = Connection(
                server,
                user=user,
                password=self.password,
                authentication=NTLM
            )
            
            # Try to connect
            if not self.conn.bind():
                raise LDAPException(f"Authentication error: {self.conn.result}")
                
            return True
            
        except Exception as e:
            print(f"[!] Connection error: {str(e)}")
            return False
            
    def disconnect(self):
        """Close connection"""
        if self.conn:
            self.conn.unbind()
            
    def get_connection(self):
        """Get current connection"""
        return self.conn