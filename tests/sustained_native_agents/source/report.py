"""Synthetic expense ledger. Numeric cross-currency totals do not convert FX."""
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
import re


def _amount(row):
    return Decimal(str(row.get("amount") or 0))


def _money(value):
    rounded = Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return 0.0 if not rounded else float(rounded)


def _text(row, key, default=""):
    value = row.get(key)
    result = "" if value is None else str(value).strip()
    return result or default


def _date(row):
    value = _text(row, "date")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def summarize(rows, budgets=None):
    rows = list(rows)
    amounts = [_amount(row) for row in rows]
    return {
        "count": len(rows),
        "total": _money(sum(amounts, Decimal(0))),
    }
