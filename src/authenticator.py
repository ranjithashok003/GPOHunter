import ldap3
from ldap3 import Server, Connection, NTLM, ALL
from ldap3.core.exceptions import LDAPException

class ADAuthenticator:
    def __init__(self, username=None, password=None, domain=None, 
                 dc_host=None, ntlm_hash=None, aes_key=None, do_kerberos=False, kdc_host=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_host = dc_host
        self.ntlm_hash = ntlm_hash
        self.aes_key = aes_key
        self.do_kerberos = do_kerberos
        self.kdc_host = kdc_host
        self.conn = None
        
    def connect(self):
        """Establish connection to Active Directory"""
        try:
            server = Server(self.dc_host, get_info=ALL, use_ssl=False)
            user_domain = f"{self.domain}\\{self.username}"
            self.conn = self.get_ldap_client(
                self.aes_key, self.do_kerberos, self.domain, self.ntlm_hash, 
                self.kdc_host, server, user_domain, self.username, self.password
            )
            
            if not self.conn.bind():
                raise LDAPException(f"Authentication error: {self.conn.result}")
                
            return True
            
        except Exception as e:
            print(f"[!] Connection error: {str(e)}")
            return False
            
    def get_ldap_client(self, aes_key, do_kerberos, domain, hashes, kdc_host, server, user_domain, username, password):
        """Get LDAP client connection"""
        try:
            if do_kerberos:
                connection = Connection(server)
                bind_result = connection.bind()
                if not bind_result:
                    raise LDAPException(f"Failed to perform LDAP bind to {server} with user {user_domain}")
                # Implement login_ldap3_kerberos if needed
                # login_ldap3_kerberos(connection, username, password, domain, lmhash, nthash, aes_key, kdc_host)
            elif hashes is not None:
                formatted_hashes = f"aad3b435b51404eeaad3b435b51404ee:{hashes}"
                connection = Connection(server, user=user_domain, password=formatted_hashes, authentication=NTLM)
                bind_result = connection.bind()
                if not bind_result:
                    raise LDAPException(f"Failed to perform LDAP bind to {server} with user {user_domain}")
            else:
                connection = Connection(server, user=user_domain, password=password, authentication=NTLM)
                bind_result = connection.bind()
                if not bind_result:
                    raise LDAPException(f"Failed to perform LDAP bind with user {user_domain}")

            return connection
        except Exception as e:
            raise

    def disconnect(self):
        """Close connection"""
        if self.conn:
            self.conn.unbind()
            
    def get_connection(self):
        """Get current connection"""
        return self.conn