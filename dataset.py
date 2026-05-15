"""
data/dataset.py
Builds and saves the SQLi classification dataset.
Labels: 0 = safe,  1 = sql_injection
"""

import json, random, os

SAFE = [
    # Parameterized queries — all safe
    ('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', 0),
    ('cursor.execute("SELECT * FROM users WHERE username = ?", (username,))', 0),
    ('db.execute("INSERT INTO logs (msg) VALUES (?)", (message,))', 0),
    ('cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, uid))', 0),
    ('cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))', 0),
    ('stmt = db.prepare("SELECT id FROM products WHERE sku = $1"); stmt.execute(sku)', 0),
    ('cursor.execute("SELECT * FROM orders WHERE status = %s AND user_id = %s", (status, uid))', 0),
    ('db.execute("SELECT name FROM categories WHERE id = ?", [cat_id])', 0),
    ('cursor.execute("SELECT * FROM items WHERE price < ?", (max_price,))', 0),
    ('db.execute("SELECT * FROM reviews WHERE product_id = ?", (pid,))', 0),
    ('cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))', 0),
    ('cursor.execute("SELECT role FROM users WHERE token = ?", (session_token,))', 0),
    ('db.execute("SELECT * FROM events WHERE date = ?", (event_date,))', 0),
    ('cursor.execute("SELECT * FROM files WHERE owner_id = ?", (current_user,))', 0),
    ('db.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))', 0),
    ('cursor.execute("SELECT * FROM audit WHERE action = ?", (action_type,))', 0),
    ('cursor.execute("SELECT * FROM messages WHERE recipient = ?", (user_id,))', 0),
    ('db.execute("SELECT * FROM configs WHERE key = ?", (config_key,))', 0),
    ('cursor.execute("SELECT * FROM tokens WHERE value = ? AND expired = 0", (tok,))', 0),
    ('db.execute("SELECT * FROM products WHERE category_id = ?", (category,))', 0),
]

VULN = [
    # String concatenation
    ("query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"", 1),
    ("db.execute(\"SELECT * FROM users WHERE id = \" + user_id)", 1),
    ("cursor.execute(\"DELETE FROM logs WHERE id = \" + record_id)", 1),
    ("query = \"UPDATE users SET role = '\" + role + \"' WHERE id = \" + uid", 1),
    ("db.execute(\"SELECT * FROM orders WHERE status = '\" + status + \"'\")", 1),
    # f-strings
    ('db.execute(f"SELECT * FROM users WHERE name = \'{username}\'")', 1),
    ('cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")', 1),
    ('db.execute(f"SELECT * FROM orders WHERE user_id = {uid} AND status = \'{status}\'")', 1),
    ('cursor.execute(f"DELETE FROM sessions WHERE user = \'{username}\'")', 1),
    ('db.execute(f"INSERT INTO logs (event) VALUES (\'{event}\')")', 1),
    ('cursor.execute(f"SELECT * FROM reviews WHERE product = {pid} AND rating > {min_rating}")', 1),
    ('db.execute(f"UPDATE accounts SET balance = {amount} WHERE id = {acct_id}")', 1),
    # % formatting
    ("cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)", 1),
    ("db.execute(\"SELECT name FROM items WHERE category = '%s'\" % category)", 1),
    ("cursor.execute(\"SELECT * FROM logs WHERE user = '%s'\" % username)", 1),
    ("query = \"SELECT * FROM products WHERE sku = '%s'\" % sku; db.execute(query)", 1),
    # .format()
    ('db.execute("SELECT * FROM users WHERE role = \'{}\'".format(role))', 1),
    ('cursor.execute("SELECT * FROM orders WHERE id = {}".format(order_id))', 1),
    ('db.execute("DELETE FROM items WHERE name = \'{}\'".format(item_name))', 1),
    ('cursor.execute("SELECT * FROM events WHERE type = \'{}\'".format(event_type))', 1),
    # Raw string building
    ("query = 'SELECT * FROM users WHERE email = \\'' + email + '\\''; db.execute(query)", 1),
    ("sql = 'UPDATE users SET password = \\'' + new_pass + '\\' WHERE id = ' + str(uid)", 1),
    ("db.execute('SELECT * FROM files WHERE name = \\'' + filename + '\\'')", 1),
    # Table/column injection
    ("db.execute('SELECT * FROM ' + table_name + ' WHERE id = ' + record_id)", 1),
    ("cursor.execute('SELECT ' + col + ' FROM users WHERE id = ' + uid)", 1),
]

def build_dataset(out_path: str, val_split: float = 0.2, seed: int = 42):
    random.seed(seed)
    all_samples = SAFE + VULN
    random.shuffle(all_samples)

    split = int(len(all_samples) * (1 - val_split))
    train = all_samples[:split]
    val   = all_samples[split:]

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    base = os.path.splitext(out_path)[0]

    for name, subset in [("train", train), ("val", val)]:
        path = f"{base}_{name}.jsonl"
        with open(path, "w") as f:
            for text, label in subset:
                f.write(json.dumps({"text": text, "label": label}) + "\n")
        print(f"Saved {len(subset)} samples → {path}")

if __name__ == "__main__":
    build_dataset("data/sqli_dataset")
