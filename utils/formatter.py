import json
import csv
from datetime import datetime
from typing import Any, List, Dict

def format_output(data: List[Dict[str, Any]], format_type: str = 'json', output_file: str = None) -> str:
    """
    Formats data into JSON, CSV, or TXT and optionally writes to a file.
    """
    format_type = format_type.lower()
    timestamp = datetime.now().isoformat()
    
    formatted_data = ""
    
    if format_type == 'json':
        # JSON output must be machine-readable
        output_obj = {
            "timestamp": timestamp,
            "results": data
        }
        formatted_data = json.dumps(output_obj, indent=4)
        
    elif format_type == 'csv':
        if not data:
            return ""
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        formatted_data = output.getvalue()
        
    elif format_type == 'txt':
        lines = []
        lines.append(f"NOX REPORT - {timestamp}")
        lines.append("-" * 40)
        for entry in data:
            for k, v in entry.items():
                lines.append(f"{k}: {v}")
            lines.append("-" * 20)
        formatted_data = "\n".join(lines)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(formatted_data)
            
    return formatted_data
