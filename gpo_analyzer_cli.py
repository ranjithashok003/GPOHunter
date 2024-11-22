#!/usr/bin/env python3

import argparse
import sys
from src.authenticator import ADAuthenticator
from src.gpo_finder import GPOFinder
from src.gpo_analyzer import GPOAnalyzer
from src.gpo_security_checker import GPOSecurityChecker

def parse_args():
    parser = argparse.ArgumentParser(description='GPOHunter - a tool for analyzing GPO security in Active Directory')
    
    # Authentication parameters
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', '--username', help='Username')
    auth_group.add_argument('-p', '--password', help='Password')
    auth_group.add_argument('-d', '--domain', required=True, help='Domain')
    auth_group.add_argument('-dc', '--dc-host', required=True, help='Domain controller host')
    auth_group.add_argument('-H', '--hash', help='NTLM hash for Pass-the-Hash')
    auth_group.add_argument('--dc-ip', help='IP address of the domain controller to avoid DNS resolution issues')
    
    # Output parameters
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Verbose output')
    
    parser.add_argument(
        '--show-xml',
        action='store_true',
        help='Show raw XML content of GPO files'
    )
    
    # If no arguments are provided, show help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Check for required authentication parameters
    if not args.hash and not (args.username and args.password):
        parser.error("Either NTLM hash (-H) or username and password (-u and -p) must be provided")
    
    return args

def main():
    args = parse_args()
    
    try:
        # Initialize authenticator
        auth = ADAuthenticator(
            username=args.username,
            password=args.password,
            domain=args.domain,
            dc_host=args.dc_ip or args.dc_host,  # Use IP if provided, otherwise use host
            ntlm_hash=args.hash
        )
        
        # Connect to AD
        if not auth.connect():
            print("[!] Error connecting to Active Directory")
            sys.exit(1)
            
        print("[+] Successfully connected to Active Directory")
        
        # Initialize components
        gpo_finder = GPOFinder(auth.get_connection())
        gpo_analyzer = GPOAnalyzer(auth.get_connection(), gpo_finder)
        security_checker = GPOSecurityChecker(gpo_analyzer)
        
        # Get GPO list
        try:
            gpos = gpo_finder.find_all_gpos()
            print(f"[+] Found GPOs: {len(gpos)}")
            
            # Separate logic for XML output, independent of verbose
            if args.show_xml:
                print("\n=== GPO XML Files Output ===")
                for gpo in gpos:
                    print(f"\n[+] GPO: {gpo['name']} ({gpo['guid']})")
                    details = gpo_analyzer.analyze_gpo(
                        gpo['guid'],
                        detail_level='full',
                        show_xml=True
                    )
                    
                    if 'xml_content' in details:
                        for file_path, content in details['xml_content'].items():
                            if content:  # Only output if content exists
                                print(f"\n=== {file_path} ===")
                                print(content)
                                print("="*50)
                    else:
                        print("No XML files found")
            
            # Existing verbose logic
            if args.verbose:
                for gpo in gpos:
                    print(f"\nAnalyzing GPO: {gpo['name']}")
                    details = gpo_analyzer.analyze_gpo(
                        gpo['guid'],
                        detail_level='full',
                        show_xml=False  # XML already output above if needed
                    )
            
            # Perform security checks
            security_checker.check_all(gpos)
            security_checker.print_findings(args.verbose)
            
        except Exception as e:
            print(f"[!] Error analyzing GPO: {str(e)}")
            
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)
    finally:
        auth.disconnect()

if __name__ == '__main__':
    main() 