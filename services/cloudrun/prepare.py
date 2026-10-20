"""Create a separate cloud authority from verified public history, plus private device profiles."""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REMOTE = Path("/srv/wipstash-parent/authority")


def write(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--public-history", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.directory.exists():
        raise SystemExit("Use a fresh private preparation directory; existing credentials are never replaced.")
    args.directory.mkdir(mode=0o700, parents=True)
    seed = args.directory / "seed"
    seed.mkdir(mode=0o700)
    verification_source = args.directory / "verification-source"
    verification_source.mkdir()
    subprocess.run([str(args.binary), "--state", str(args.directory/"verification"),
        json.dumps({"op":"init","source":str(verification_source)})],check=True,capture_output=True)
    checked = json.loads(subprocess.check_output([str(args.binary), "--state", str(args.directory/"verification"),
        json.dumps({"op":"backup_verify_restore","destination":str(args.public_history)})]))
    if checked.get("ok") is not True:
        raise SystemExit("Public history verification failed")
    head = checked["integration"]
    shutil.copytree(args.public_history, seed / "public.git")
    source = seed / "source"
    source.mkdir()
    archive = subprocess.check_output(["git","--git-dir",str(args.public_history),"archive",head])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter="data")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Wipstash cloud demo")])
    ca = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(
        now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (args.directory/"ca.pem").write_bytes(ca_pem)
    (args.directory/"ca-key.pem").write_bytes(ca_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    peers = {}
    names = ["codex","opencode","claude","pi"]
    for device in names:
        directory = args.directory / "devices" / device
        directory.mkdir(mode=0o700, parents=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,device)])
        certificate = x509.CertificateBuilder().subject_name(name).issuer_name(subject).public_key(key.public_key()).serial_number(
            x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(
            now+datetime.timedelta(days=14)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False).sign(ca_key,hashes.SHA256())
        identity = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
        peers[identity] = {"device":device,"project":"wipstash-demo","role":"client","revoked":False}
        (directory/"ca.pem").write_bytes(ca_pem)
        (directory/"certificate.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (directory/"key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        state = directory / "state"
        staging = directory / "staging"
        state.mkdir(mode=0o700)
        staging.mkdir(mode=0o700)
        write(directory/"client.json", {
            "engine":str(args.binary),"state":str(state),"staging":str(staging),
            "ca":str(directory/"ca.pem"),"certificate":str(directory/"certificate.pem"),"key":str(directory/"key.pem"),
            "server_name":"localhost","authority_fingerprint":hashlib.sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest(),
            "address":"127.0.0.1:1","https_endpoint":args.endpoint,
            "project":"wipstash-demo","authority":"cloudrun-demo-20261019","epoch":1,"device":device,"authority_device":"cloud-authority"
        })
    write(seed/"acl.json", {"peers":peers})
    write(seed/"bootstrap.json", {
        "project":"wipstash-demo","authority":"cloudrun-demo-20261019","device":"cloud-authority","devices":names,
        "source_head":head,
        "policy":{"checks":[
            {"id":"python-tests","argv":["/usr/local/bin/python","-B","-m","unittest","discover","-s","tests","-p","test_*.py"],"preset":"python","required":True,"timeout_seconds":60},
            {"id":"javascript-syntax","argv":["/usr/bin/node","--check","website/app.js"],"required":True,"timeout_seconds":30},
            {"id":"javascript-tests","argv":["/usr/bin/node","--test","tests/test_walkthrough.cjs"],"required":True,"timeout_seconds":30}
        ]}
    })
    write(seed/"service.json",{
        "engine":"/usr/local/bin/wipstash","state":str(REMOTE/"state"),"staging":str(REMOTE/"staging"),
        "project":"wipstash-demo","authority":"cloudrun-demo-20261019","epoch":1,"device":"cloud-authority",
        "acl":str(REMOTE/"acl.json"),"ca":str(REMOTE/"unused-ca"),"certificate":str(REMOTE/"unused-certificate"),
        "key":str(REMOTE/"unused-key"),"listen":"127.0.0.1:7443",
        "limits":{"max_storage_bytes":2*1024**3,"max_storage_entries":200000,"free_space_reserve_bytes":64*1024**2,
                  "requests_per_minute":120,"request_burst":30}
    })
    print(json.dumps({"prepared":str(args.directory),"source_head":head,"devices":names}))


if __name__ == "__main__":
    main()
