"""Bounded projection of an observed Huawei device-info uptime, never a session."""

import math

MAX_UPTIME = 10 * 365 * 24 * 3600
MAX_TTL = 3600


def finite(value, maximum):
    # Bound integers before math.isfinite: converting an arbitrary int can overflow.
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and 0 <= value <= maximum and math.isfinite(value))


def bounded_ttl(value, maximum=MAX_TTL):
    return min(value, maximum) if finite(value, 253402300799) and value > 0 else None


def sample(device, observed_at, now, ttl):
    """Keep the raw reading and its own timestamp; never refresh it on reuse."""
    raw = device.get('uptime_seconds') if isinstance(device, dict) else None
    fields = {'uptime_seconds': raw if finite(raw, MAX_UPTIME) else None,
              'uptime_reported_seconds': raw if finite(raw, MAX_UPTIME) else None,
              'uptime_observed_at': observed_at if finite(observed_at, 253402300799) else None,
              'uptime_ttl_seconds': ttl if finite(ttl, MAX_TTL) else None}
    diagnostic = project(fields, now)
    fields['uptime_unavailable_reason'] = diagnostic['unavailable_reason']
    if diagnostic['estimated_seconds'] is None:
        fields['uptime_seconds'] = None
    return fields


def project(stats, now):
    """Stateless estimate: a newer, lower hardware sample always wins (reboot)."""
    stats = stats if isinstance(stats, dict) else {}
    raw, seen, ttl = (stats.get(k) for k in (
        'uptime_seconds', 'uptime_observed_at', 'uptime_ttl_seconds'))
    reported = stats.get('uptime_reported_seconds', raw)
    result = {'reported_seconds': reported if finite(reported, MAX_UPTIME) else None,
              'observed_at': seen if finite(seen, 253402300799) else None,
              'estimated_seconds': None, 'age_seconds': None,
              'source': 'huawei-web:deviceinfo',
              'unavailable_reason': stats.get('uptime_unavailable_reason') or 'invalid-sample'}
    if (not finite(raw, MAX_UPTIME) or not finite(seen, 253402300799)
            or not finite(now, 253402300799) or not finite(ttl, MAX_TTL) or ttl <= 0):
        return result
    age = now - seen
    result['age_seconds'] = age
    if age < 0 or age > ttl:
        result['unavailable_reason'] = 'future-sample' if age < 0 else 'expired-sample'
        return result
    # Use the same integer UTC clock as native `time`. Independently flooring
    # raw+age would make time-uptime oscillate by one second between informs
    # when deviceinfo arrived at a fractional second.
    result.update(estimated_seconds=int(raw) + int(now) - int(seen), unavailable_reason=None)
    return result
