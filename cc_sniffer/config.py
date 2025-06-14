import yaml
from pathlib import Path
from typing import Dict, Any

def validate_config(config: Dict[str, Any]):
    """Validate configuration parameters"""
    required_keys = [
        'interface', 'bpf_filter', 'log_path', 
        'max_log_size_mb', 'backup_count', 'card_types'
    ]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")
    
    if not isinstance(config['card_types'], dict):
        raise TypeError("card_types must be a dictionary")
    
    if config.get('prometheus_port') and not (1024 <= config['prometheus_port'] <= 65535):
        raise ValueError("Invalid prometheus_port")

def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    cfg_file = Path(path)
    if not cfg_file.exists():
        raise FileNotFoundError(f"Missing config file: {path}")
    
    config = yaml.safe_load(cfg_file.read_text())
    validate_config(config)
    return config
