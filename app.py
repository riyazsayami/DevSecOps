# insecure_bigbomb.py
# Intentionally insecure: for static analysis only. Do NOT execute in production.

import os
import sys
import subprocess
import hashlib
import random
import secrets
import pickle
import marshal
import tempfile
import sqlite3
import socket
import ssl
import http.server
import threading
import json
import urllib.parse
import xml.etree.ElementTree as ET
import requests    # requires requests lib if you run; used to demonstrate insecure TLS verify
import yaml        # PyYAML
import base64
import hmac
import time

# -------------------------
# 1) Hardcoded secrets
# -------------------------
AWS_KEY = "AKIAEXAMPLEKEY123"
AWS_SECRET = "verysecretkey1234567890"
DB_ADMIN = "admin"
DB_PASSWORD = "P@ssw0rd1234"     # hardcoded password

# -------------------------
# 2) Weak crypto + bad key handling
# -------------------------
def weak_hash(password):
    # MD5 is weak
    return hashlib.md5(password.encode()).hexdigest()

def weak_hmac(key, msg):
    # HMAC with MD5 (weak)
    return hmac.new(key.encode(), msg.encode(), hashlib.md5).hexdigest()

# -------------------------
# 3) Weak randomness for tokens
# -------------------------
def predictable_token():
    # random module is not cryptographically secure
    return ''.join(str(random.randint(0,9)) for _ in range(16))

def bad_secret_token():
    # using predictable seed from time
    random.seed(int(time.time()))
    return predictable_token()

# -------------------------
# 4) Insecure TLS usage
# -------------------------
def fetch_insecure(url):
    # disabling verification is insecure
    return requests.get(url, verify=False).text

# -------------------------
# 5) Arbitrary code execution
# -------------------------
def run_eval(user):
    # eval of user input -> RCE
    return eval(user)

def run_exec(user):
    # exec of user input -> RCE
    exec(user)

# -------------------------
# 6) Command injection and unsafe subprocess
# -------------------------
def list_dir(user_input):
    # dangerous string-concatenation + shell=True
    return subprocess.check_output("ls " + user_input, shell=True)

def unsafe_system(user_input):
    # os.system with unsanitized input
    os.system("cp " + user_input + " /tmp/backup/")

# -------------------------
# 7) Insecure deserialization
# -------------------------
def load_pickle(blob):
    # pickle.loads on untrusted input
    return pickle.loads(blob)

def load_marshal(blob):
    # marshal can execute arbitrary code objects
    return marshal.loads(blob)

# -------------------------
# 8) Insecure temporary file handling
# -------------------------
def write_secret_to_tmp(secret):
    # insecure temp file creation (predictable name and weak perms)
    path = "/tmp/secret-" + predictable_token() + ".txt"
    with open(path, "w") as f:
        f.write(secret)
    os.chmod(path, 0o666)   # world-readable/writable (bad)
    return path

def use_tempfile_bad(secret):
    # using tempfile.NamedTemporaryFile without delete=False but using insecure mode
    tmp = tempfile.NamedTemporaryFile(prefix="tmp", delete=False)
    tmp.write(secret.encode())
    tmp.flush()
    os.chmod(tmp.name, 0o644)
    return tmp.name

# -------------------------
# 9) SQL injection
# -------------------------
def vulnerable_sql(conn, username):
    # unparameterized SQL
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "';"
    cur.execute(query)
    return cur.fetchall()

# -------------------------
# 10) Path traversal
# -------------------------
def read_user_file(path):
    # naive join allows ../ traversal
    base = "/var/data/"
    full = os.path.join(base, path)
    with open(full, "r") as f:
        return f.read()

# -------------------------
# 11) XML External Entity (XXE) risk
# -------------------------
def parse_xml(raw):
    # default ElementTree is vulnerable to certain external entities depending on parser
    # (this is intentionally unsafe to trigger static checks)
    root = ET.fromstring(raw)
    return root.tag

# -------------------------
# 12) YAML unsafe loader
# -------------------------
def load_yaml_untrusted(raw):
    # using yaml.load (unsafe) instead of safe_load
    return yaml.load(raw)   # no Loader -> unsafe

# -------------------------
# 13) Logging secrets (leak)
# -------------------------
def log_credentials():
    # logging secrets to stdout (leak)
    print(f"AWS_KEY={AWS_KEY} AWS_SECRET={AWS_SECRET}")

# -------------------------
# 14) Weak password storage: base64 + low iteration PBKDF imitation
# -------------------------
def store_password_weak(pwd):
    # imitation of weak storage: base64 (not a hash) and trivial salt
    salt = "salt"
    blob = base64.b64encode((salt + pwd).encode()).decode()
    return blob

# -------------------------
# 15) Insecure JWT handling / signature skipping
# -------------------------
def verify_jwt_skip_alg(token):
    # naive split and skip signature verification (vulnerable)
    header, payload, signature = token.split('.')
    decoded = base64.urlsafe_b64decode(payload + "==")
    return json.loads(decoded)

# -------------------------
# 16) Open admin endpoint with no auth
# -------------------------
class AdminHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            # exposes secret config with no auth
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"secret config: " + DB_PASSWORD.encode())
        else:
            super().do_GET()

def start_admin_server():
    srv = http.server.HTTPServer(("0.0.0.0", 8081), AdminHandler)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv

# -------------------------
# 17) Insecure socket with no TLS
# -------------------------
def start_plain_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 9000))
    s.listen(1)
    return s

# -------------------------
# 18) Exposed config file with credentials (writes to repo-style file)
# -------------------------
def write_creds_file():
    with open("aws-credentials.json", "w") as f:
        json.dump({
            "aws_access_key_id": AWS_KEY,
            "aws_secret_access_key": AWS_SECRET,
            "region": "us-east-1"
        }, f)

# -------------------------
# 19) Unsafe S3 CLI usage via os.system exposing creds in process env
# -------------------------
def push_to_s3_bad():
    os.system(f"AWS_ACCESS_KEY_ID={AWS_KEY} AWS_SECRET_ACCESS_KEY={AWS_SECRET} aws s3 cp file s3://public-bucket --acl public-read")

# -------------------------
# 20) Example main that wires everything (static analysis will see all patterns)
# -------------------------
def main():
    # create insecure DB
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);")
    conn.execute("INSERT INTO users (username) VALUES ('alice');")
    conn.commit()

    # call many insecure functions to ensure Sonar sees them in the same file
    _ = weak_hash("password")
    _ = weak_hmac("key", "msg")
    token1 = predictable_token()
    token2 = bad_secret_token()
    try:
        fetch_insecure("https://expired.badssl.com/")
    except Exception:
        pass
    try:
        # purposely calling eval/exec on a benign string
        run_eval("__import__('os').getcwd()")
    except Exception:
        pass
    try:
        run_exec("print('hello')")
    except Exception:
        pass
    try:
        list_dir("; cat /etc/passwd")
    except Exception:
        pass
    try:
        unsafe_system("; rm -rf /tmp/maybe")
    except Exception:
        pass
    try:
        load_pickle(pickle.dumps({"x":1}))
    except Exception:
        pass
    try:
        load_marshal(marshal.dumps(42))
    except Exception:
        pass
    tmp_path = write_secret_to_tmp("topsecret")
    tmp2 = use_tempfile_bad("topsecret2")
    try:
        vulnerable_sql(conn, "admin' OR '1'='1")
    except Exception:
        pass
    try:
        read_user_file("../etc/passwd")
    except Exception:
        pass
    try:
        parse_xml("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo>")
    except Exception:
        pass
    try:
        load_yaml_untrusted("!!python/object/apply:os.system ['echo vulnerable']")
    except Exception:
        pass
    log_credentials()
    _ = store_password_weak("mypwd")
    try:
        verify_jwt_skip_alg("a.b.c")
    except Exception:
        pass
    srv = start_admin_server()
    s = start_plain_socket()
    write_creds_file()
    push_to_s3_bad()

    print("Done. Created insecure artifacts:", tmp_path, tmp2)
    # intentionally not closing socket/server to show resource leaks (bad)
    return 0

if __name__ == "__main__":
    main()
