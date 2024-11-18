import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Any

class OutputFormatter:
    def __init__(self, output_file: str = None, format_type: str = 'json'):
        """
        Initialize formatter
        
        Args:
            output_file: Path to output file
            format_type: Format type (json, csv, html)
        """
        self.output_file = output_file
        self.format_type = format_type.lower()
        
    def format_and_save(self, gpo_data: List[Dict[str, Any]]) -> None:
        """
        Format and save data in chosen format
        
        Args:
            gpo_data: List of dictionaries with GPO data
        """
        if not self.output_file:
            return
            
        try:
            if self.format_type == 'json':
                self._save_json(gpo_data)
            elif self.format_type == 'csv':
                self._save_csv(gpo_data)
            elif self.format_type == 'html':
                self._save_html(gpo_data)
            else:
                raise ValueError(f"Unsupported format: {self.format_type}")
                
        except Exception as e:
            raise Exception(f"Error during report saving: {str(e)}")
    
    def _save_json(self, gpo_data: List[Dict[str, Any]]) -> None:
        """Save in JSON format"""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(
                    gpo_data,
                    f,
                    ensure_ascii=False,
                    indent=4,
                    default=str  # For serialization of datetime
                )
        except Exception as e:
            raise Exception(f"Error during JSON saving: {str(e)}")
    
    def _save_csv(self, gpo_data: List[Dict[str, Any]]) -> None:
        """Save in CSV format"""
        try:
            # Get all possible fields from all GPOs
            fields = set()
            for gpo in gpo_data:
                self._get_all_fields(gpo, fields)
            
            fields = sorted(list(fields))
            
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(fields)  # Headers
                
                # Data
                for gpo in gpo_data:
                    row = []
                    for field in fields:
                        value = self._get_nested_value(gpo, field.split('.'))
                        row.append(self._format_value(value))
                    writer.writerow(row)
                    
        except Exception as e:
            raise Exception(f"Error during CSV saving: {str(e)}")
    
    def _save_html(self, gpo_data: List[Dict[str, Any]]) -> None:
        """Save in HTML format"""
        try:
            html = self._generate_html(gpo_data)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(html)
                
        except Exception as e:
            raise Exception(f"Error during HTML saving: {str(e)}")
    
    def _generate_html(self, gpo_data: List[Dict[str, Any]]) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>GPO Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .gpo {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; }}
        .gpo-header {{ background: #f5f5f5; padding: 10px; margin-bottom: 10px; }}
        .section {{ margin: 10px 0; }}
        .section-title {{ font-weight: bold; margin: 5px 0; }}
        .task {{ margin-left: 20px; }}
        .security-setting {{ margin-left: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>GPO Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""
        
        for gpo in gpo_data:
            html += self._generate_gpo_html(gpo)
            
        html += """
</body>
</html>
"""
        return html
    
    def _generate_gpo_html(self, gpo: Dict[str, Any]) -> str:
        """Generate HTML for a single GPO"""
        basic_info = gpo.get('basic_info', {})
        html = f"""
    <div class="gpo">
        <div class="gpo-header">
            <h2>{basic_info.get('name', 'Unnamed GPO')}</h2>
            <p>GUID: {gpo.get('guid', 'N/A')}</p>
        </div>
        
        <div class="section">
            <div class="section-title">Basic Information</div>
            <table>
                <tr><td>Status</td><td>{'Enabled' if basic_info.get('enabled') else 'Disabled'}</td></tr>
                <tr><td>Created</td><td>{basic_info.get('created', 'N/A')}</td></tr>
                <tr><td>Modified</td><td>{basic_info.get('modified', 'N/A')}</td></tr>
            </table>
        </div>
"""
        
        # Add sections based on the presence of data
        if 'security_settings' in gpo:
            html += self._generate_security_settings_html(gpo['security_settings'])
            
        if 'scheduled_tasks' in gpo:
            html += self._generate_tasks_html(gpo['scheduled_tasks'])
            
        html += """
    </div>
"""
        return html
    
    def _generate_security_settings_html(self, settings: Dict[str, Any]) -> str:
        """Generate HTML for security settings"""
        html = """
        <div class="section">
            <div class="section-title">Security Settings</div>
"""
        
        for section, values in settings.items():
            if values:
                html += f"""
            <h3>{section}</h3>
            <table>
                <tr><th>Setting</th><th>Value</th></tr>
"""
                for setting, value in values.items():
                    html += f"""
                <tr><td>{setting}</td><td>{value}</td></tr>
"""
                html += """
            </table>
"""
                
        html += """
        </div>
"""
        return html
    
    def _generate_tasks_html(self, tasks: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate HTML for scheduled tasks"""
        html = """
        <div class="section">
            <div class="section-title">Scheduled Tasks</div>
"""
        
        for task_type, task_list in tasks.items():
            if task_list:
                html += f"""
            <h3>{task_type.title()} Tasks</h3>
            <table>
                <tr><th>Name</th><th>Command</th><th>User</th><th>Status</th></tr>
"""
                for task in task_list:
                    action = task.get('action', [{}])[0]
                    html += f"""
                <tr>
                    <td>{task.get('name', 'N/A')}</td>
                    <td>{action.get('command', 'N/A')}</td>
                    <td>{task.get('principal', {}).get('user_id', 'N/A')}</td>
                    <td>{'Enabled' if task.get('enabled') else 'Disabled'}</td>
                </tr>
"""
                html += """
            </table>
"""
                
        html += """
        </div>
"""
        return html
    
    def _get_all_fields(self, data: Dict[str, Any], fields: set, prefix: str = '') -> None:
        """Recursive retrieval of all fields from a dictionary"""
        for key, value in data.items():
            field = f"{prefix}{key}" if prefix else key
            
            if isinstance(value, dict):
                self._get_all_fields(value, fields, f"{field}.")
            elif isinstance(value, list):
                if value and isinstance(value[0], dict):
                    self._get_all_fields(value[0], fields, f"{field}.")
                else:
                    fields.add(field)
            else:
                fields.add(field)
    
    def _get_nested_value(self, data: Dict[str, Any], keys: List[str]) -> Any:
        """Retrieve value from a nested dictionary by a list of keys"""
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, '')
            else:
                return ''
        return data
    
    def _format_value(self, value: Any) -> str:
        """Format value for CSV"""
        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False, default=str)
        return str(value) 