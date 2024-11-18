from ldap3 import SUBTREE
from datetime import datetime
import re

class GPOFinder:
    def __init__(self, ldap_connection):
        self.conn = ldap_connection
        self.base_dn = self._get_base_dn()
        
    def _get_base_dn(self):
        """Get base DN of the domain"""
        if not self.conn or not self.conn.server.info:
            raise Exception("No connection to server or domain information")
        return self.conn.server.info.other['defaultNamingContext'][0]
    
    def _convert_windows_time(self, windows_time):
        """Convert Windows timestamp to readable format"""
        if windows_time == '0':
            return None
        timestamp = int(windows_time) / 10000000 - 11644473600
        return datetime.fromtimestamp(timestamp)
    
    def find_all_gpos(self):
        """Find all GPOs in domain"""
        gpo_container = f"CN=Policies,CN=System,{self.base_dn}"
        search_filter = "(objectClass=groupPolicyContainer)"
        attributes = [
            'displayName',
            'description',
            'flags',
            'gPCFunctionalityVersion',
            'whenCreated',
            'whenChanged',
            'versionNumber'
        ]
        
        try:
            self.conn.search(
                search_base=gpo_container,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            
            gpos = []
            for entry in self.conn.entries:
                gpo = {
                    'name': entry.displayName.value if hasattr(entry, 'displayName') else None,
                    'description': entry.description.value if hasattr(entry, 'description') else None,
                    'enabled': bool(int(entry.flags.value) & 1) if hasattr(entry, 'flags') else True,
                    'created': entry.whenCreated.value if hasattr(entry, 'whenCreated') else None,
                    'modified': entry.whenChanged.value if hasattr(entry, 'whenChanged') else None,
                    'guid': self._extract_guid(entry.entry_dn),
                    'version': entry.versionNumber.value if hasattr(entry, 'versionNumber') else None
                }
                gpos.append(gpo)
                
            return gpos
            
        except Exception as e:
            raise Exception(f"Error during GPO search: {str(e)}")
    
    def _extract_guid(self, dn):
        """Extract GUID from GPO object DN"""
        guid_pattern = re.compile(r'\{([^}]+)\}')
        match = guid_pattern.search(dn)
        return match.group(1) if match else None
    
    def find_gpo_by_name(self, name):
        """Find GPO by name"""
        gpo_container = f"CN=Policies,CN=System,{self.base_dn}"
        search_filter = f"(&(objectClass=groupPolicyContainer)(displayName={name}))"
        
        try:
            self.conn.search(
                search_base=gpo_container,
                search_filter=search_filter,
                search_scope=SUBTREE
            )
            return self.conn.entries[0] if self.conn.entries else None
        except Exception as e:
            raise Exception(f"Error during GPO search by name: {str(e)}")
    
    def get_gpo_links(self, gpo_guid):
        """Get list of OUs where GPO is linked"""
        search_filter = f"(gPLink=*{gpo_guid}*)"
        
        try:
            self.conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            
            linked_ous = []
            for entry in self.conn.entries:
                linked_ous.append(entry.distinguishedName.value)
                
            return linked_ous
            
        except Exception as e:
            raise Exception(f"Error during GPO link search: {str(e)}")
    
    def get_gpo_security_filtering(self, gpo_dn):
        """Get security groups applied to GPO"""
        try:
            self.conn.search(
                search_base=gpo_dn,
                search_filter='(objectClass=*)',
                search_scope=SUBTREE,
                attributes=['nTSecurityDescriptor']
            )
            
            # TODO: Parse ACL to get list of security groups
            return []
            
        except Exception as e:
            raise Exception(f"Error during security filtering search: {str(e)}")
    
    def get_gpo_info(self, gpo_guid):
        """Get information about specific GPO"""
        try:
            gpo_dn = f"CN={{{gpo_guid}}},CN=Policies,CN=System,{self.base_dn}"
            attributes = [
                'displayName', 
                'flags', 
                'whenCreated', 
                'whenChanged',
                'gPCFileSysPath',
                'versionNumber',
                'gPCUserExtensionNames',
                'gPCMachineExtensionNames'
            ]

            self.conn.search(
                search_base=gpo_dn,
                search_filter='(objectClass=groupPolicyContainer)',
                attributes=attributes
            )

            if not self.conn.entries:
                return None

            entry = self.conn.entries[0]
            return {
                'displayName': entry.displayName.value if hasattr(entry, 'displayName') else None,
                'flags': entry.flags.value if hasattr(entry, 'flags') else 0,
                'whenCreated': entry.whenCreated.value if hasattr(entry, 'whenCreated') else None,
                'whenChanged': entry.whenChanged.value if hasattr(entry, 'whenChanged') else None,
                'gPCFileSysPath': entry.gPCFileSysPath.value if hasattr(entry, 'gPCFileSysPath') else None,
                'versionNumber': entry.versionNumber.value if hasattr(entry, 'versionNumber') else None,
                'gPCUserExtensionNames': entry.gPCUserExtensionNames.value if hasattr(entry, 'gPCUserExtensionNames') else None,
                'gPCMachineExtensionNames': entry.gPCMachineExtensionNames.value if hasattr(entry, 'gPCMachineExtensionNames') else None
            }

        except Exception as e:
            raise Exception(f"Error during GPO information retrieval for {gpo_guid}: {str(e)}")