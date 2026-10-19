"""
JSON utility functions
"""

import json
from typing import Any, Dict, List, Union


def safe_json_load(data: Any, default: Any = None) -> Any:
    """Safely load JSON data, returning default on failure"""
    if data is None:
        return default if default is not None else {}
    
    if isinstance(data, (dict, list)):
        return data
    
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


def safe_json_load_list(data: Any) -> List:
    """Safely load JSON data as a list"""
    result = safe_json_load(data, [])
    return result if isinstance(result, list) else []


def safe_json_load_dict(data: Any) -> Dict:
    """Safely load JSON data as a dictionary"""
    result = safe_json_load(data, {})
    return result if isinstance(result, dict) else {}
