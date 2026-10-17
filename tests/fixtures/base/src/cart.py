from pricing import quote

def total(lines):
    return sum(quote(cents, qty) for cents, qty in lines)
