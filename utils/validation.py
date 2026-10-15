"""Input validation / sanitisation for activity data sent to /api/predict."""
import ipaddress
import math

from utils.preprocessing import PROTOCOLS, SERVICES

# field: (type, minimum, maximum)
NUMERIC_RULES = {
    "duration": (float, 0, 86400),
    "src_bytes": (int, 0, 10**11),
    "dst_bytes": (int, 0, 10**11),
    "packet_count": (int, 0, 10**8),
    "connection_count": (int, 0, 10**7),
    "failed_logins": (int, 0, 10**5),
    "logged_in": (int, 0, 1),
    "error_rate": (float, 0, 1),
}


def _parse_number(value, kind):
    if isinstance(value, bool) or value is None or value == "":
        raise ValueError("is required")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError("must be a number")
    if not math.isfinite(number):
        raise ValueError("must be a finite number")
    if kind is int:
        if number != int(number):
            raise ValueError("must be a whole number")
        return int(number)
    return number


def _parse_ip(value):
    value = (str(value).strip() if value is not None else "")
    if not value:
        return "unknown"
    return str(ipaddress.ip_address(value))   # raises ValueError if invalid


def validate_activity(data):
    """Returns (clean_dict, errors_dict). Only whitelisted fields are kept."""
    clean, errors = {}, {}

    for field, (kind, low, high) in NUMERIC_RULES.items():
        try:
            number = _parse_number(data.get(field), kind)
            if not low <= number <= high:
                raise ValueError(f"must be between {low} and {high}")
            clean[field] = number
        except ValueError as exc:
            errors[field] = f"{field} {exc}"

    for field, allowed in (("protocol", PROTOCOLS), ("service", SERVICES)):
        value = str(data.get(field, "")).strip().lower()
        if value in allowed:
            clean[field] = value
        else:
            errors[field] = f"{field} must be one of: {', '.join(allowed)}"

    for field in ("source_ip", "destination_ip"):
        try:
            clean[field] = _parse_ip(data.get(field))
        except ValueError:
            errors[field] = f"{field} is not a valid IP address"

    return clean, errors
