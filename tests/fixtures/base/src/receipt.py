from pricing import quote

def receipt(cents, qty):
    return {"total_cents": quote(cents, qty)}
