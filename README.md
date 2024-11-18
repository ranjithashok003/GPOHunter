GPOHunter - Active Directory Group Policy Security Analyzer
===========================================================

GPOHunter is a comprehensive tool designed to analyze and identify security misconfigurations in Active Directory Group Policy Objects (GPOs). It automates security checks and provides detailed reports on potential vulnerabilities, helping administrators secure their environments.

Features
--------
- Connects to Active Directory using LDAP/LDAPS protocols.
- Supports NTLM authentication and Pass-the-Hash techniques.
- Analyzes all GPOs within the domain.
- Identifies and reports security misconfigurations.
- Displays affected organizational units (OUs) and objects.
- Offers multiple output formats: JSON, CSV, and HTML.
- Provides an option to view detailed XML content of GPO files.

Security Checks
---------------
Currently, GPOHunter implements the following security checks:

1. **Clear Text Password Storage**
   - Detects the "ClearTextPassword = 1" setting in GPOs.
   - This setting allows passwords to be stored in unencrypted form, posing a critical security risk by exposing credentials.

2. **GPP Passwords (MS14-025)**
   - Identifies encrypted passwords within Group Policy Preferences.
   - Examines various GPP files such as Groups.xml, Services.xml, and others.
   - These passwords are encrypted with a known key and can be easily decrypted using public information.

3. **NetNTLMv1 Authentication Enabled**
   - Detects insecure LmCompatibilityLevel settings.
   - Identifies GPOs that enable NetNTLMv1, which is vulnerable to:
     * Relay attacks when combined with Coerce.
     * Password cracking using rainbow tables.

Future Development
------------------
The list of security checks will be continuously expanded with additional checks and verifications.

Usage
-----
To run GPOHunter, use the following command:

```python gpo_analyzer_cli.py -u USERNAME -p PASSWORD -d DOMAIN -dc DC_HOST [options]```


Options:
- `-H`, `--hash`: NTLM hash for Pass-the-Hash.
- `-o`, `--output`: Path to the output file.
- `-f`, `--format`: Output format (json, csv, html).
- `-v`, `--verbose`: Verbose output.
- `--show-xml`: Show raw XML content of GPO files.

Requirements
------------
- Python 3.7+
- ldap3
- impacket
- colorama
- pycryptodome

Installation
------------
1. Clone the repository.
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

Example
-------
To analyze GPOs and generate an HTML report:

```python gpo_analyzer_cli.py -u USERNAME -p PASSWORD -d DOMAIN -dc DC_HOST -o output.html -f html```


License
-------
This project is licensed under the MIT License - see the LICENSE file for details.

Author
------
* [Riocool](https://t.me/riocool)

Disclaimer
----------
This tool is intended for security assessment purposes only. Ensure you have proper authorization before scanning Active Directory environments.

