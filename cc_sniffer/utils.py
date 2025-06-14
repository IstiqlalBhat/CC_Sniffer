import re
from datetime import datetime

def luhn_valid(number: str) -> bool:
    try:
        digits = [int(d) for d in number]
        # Double every second digit starting from right
        total = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0
    except (ValueError, TypeError):
        return False

def compile_patterns(card_map: dict):
    return {name: re.compile(regex) for name, regex in card_map.items()}

def timestamp():
    return datetime.utcnow().isoformat() + "Z"

def mask_cc_number(number: str) -> str:
    """Mask credit card number for logging"""
    if len(number) < 8:
        return "****"  # Invalid number format
    return number[:4] + "****" + number[-4:]
