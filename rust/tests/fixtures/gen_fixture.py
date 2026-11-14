#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Regenerates the synthetic fixtures (requires the `openssl` CLI):

strongbox_leaf.der   self-signed P-256 cert whose key attestation extension
                     (1.3.6.1.4.1.11129.2.1.17) claims a StrongBox-generated,
                     user-auth-bound key with challenge b"hwbp-test-challenge".
chain_ec/            root (P-384) > intermediate (P-256) > attestation key > leaf
chain_rsa/           root (RSA-2048) > intermediate (P-256) > attestation key > leaf
forged/              chain_ec with an extra "leaf" signed by the real leaf key

NOT real device attestations."""
import os, subprocess, tempfile
def tlv(first, v):
    n = len(v)
    l = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xff]))
    return bytes(first) + l + v
seq = lambda *p: tlv([0x30], b"".join(p))
integer = lambda v: tlv([0x02], bytes([v]) if v < 0x80 else v.to_bytes((v.bit_length() + 8) // 8, "big"))
enum = lambda v: tlv([0x0a], bytes([v]))
octets = lambda v: tlv([0x04], v)
def ctx(tag, inner):
    if tag < 31:
        return tlv([0xa0 | tag], inner)
    b = [tag & 0x7f]; tag >>= 7
    while tag: b.append(0x80 | (tag & 0x7f)); tag >>= 7
    return tlv([0xbf] + b[::-1], inner)
hw = seq(ctx(1, tlv([0x31], integer(2))), ctx(2, integer(3)), ctx(10, integer(1)),
         ctx(504, integer(3)), ctx(702, integer(0)),
         ctx(704, seq(octets(bytes(32)), tlv([0x01], b"\xff"), enum(0), octets(bytes(32)))))
kd = seq(integer(300), enum(2), integer(300), enum(2), octets(b"hwbp-test-challenge"), octets(b""), seq(), hw)
here = os.path.dirname(os.path.abspath(__file__))

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def genkey(path, kind):
    if kind == "rsa":
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path)
    else:
        run("openssl", "ecparam", "-name", kind, "-genkey", "-noout", "-out", path)

def issue(d, name, key, issuer_name, issuer_key, serial, digest, ext):
    """Issue a cert for `key` signed by issuer; returns PEM path."""
    ext_path = os.path.join(d, name + ".ext")
    with open(ext_path, "w") as f:
        f.write(ext)
    csr = os.path.join(d, name + ".csr")
    run("openssl", "req", "-new", "-key", key, "-subj", "/CN=" + name, "-out", csr)
    pem = os.path.join(d, name + ".pem")
    run("openssl", "x509", "-req", "-in", csr, "-CA", os.path.join(d, issuer_name + ".pem"),
        "-CAkey", issuer_key, "-set_serial", serial, "-days", "3650", "-" + digest,
        "-extfile", ext_path, "-out", pem)
    return pem

def to_der(pem, out):
    run("openssl", "x509", "-in", pem, "-outform", "DER", "-out", out)

LEAF_EXT = "1.3.6.1.4.1.11129.2.1.17=DER:" + kd.hex() + "\n"
CA_EXT = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n"

def chain(d, out_dir, root_kind, root_digest):
    os.makedirs(out_dir, exist_ok=True)
    keys = {n: os.path.join(d, n + ".key") for n in ("root", "inter", "attkey", "leaf")}
    genkey(keys["root"], root_kind)
    for n in ("inter", "attkey", "leaf"):
        genkey(keys[n], "prime256v1")
    run("openssl", "req", "-x509", "-new", "-key", keys["root"], "-subj", "/CN=root", "-days", "3650",
        "-" + root_digest, "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign", "-out", os.path.join(d, "root.pem"))
    inter = issue(d, "inter", keys["inter"], "root", keys["root"], "0x1001", root_digest, CA_EXT)
    att = issue(d, "attkey", keys["attkey"], "inter", keys["inter"], "0x2002", "sha256", CA_EXT)
    leaf = issue(d, "leaf", keys["leaf"], "attkey", keys["attkey"], "0x1", "sha256", LEAF_EXT)
    for i, pem in enumerate((leaf, att, inter, os.path.join(d, "root.pem"))):
        to_der(pem, os.path.join(out_dir, f"{i}.der"))
    return keys, leaf

with tempfile.TemporaryDirectory() as d:
    key = os.path.join(d, "k.pem")
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key], check=True)
    subprocess.run(["openssl", "req", "-x509", "-new", "-key", key, "-subj", "/CN=Android Keystore Key",
                    "-days", "3650", "-outform", "DER", "-out", os.path.join(here, "strongbox_leaf.der"),
                    "-addext", "1.3.6.1.4.1.11129.2.1.17=DER:" + kd.hex()], check=True)

for name, kind, digest in (("chain_ec", "secp384r1", "sha384"), ("chain_rsa", "rsa", "sha256")):
    with tempfile.TemporaryDirectory() as d:
        keys, leaf_pem = chain(d, os.path.join(here, name), kind, digest)
        if name == "chain_ec":
            # The real leaf key signs a forged leaf claiming whatever it likes.
            out = os.path.join(here, "forged")
            os.makedirs(out, exist_ok=True)
            os.rename(leaf_pem, os.path.join(d, "realleaf.pem"))
            genkey(os.path.join(d, "fake.key"), "prime256v1")
            fake = issue(d, "fake", os.path.join(d, "fake.key"), "realleaf", keys["leaf"], "0x3", "sha256", LEAF_EXT)
            to_der(fake, os.path.join(out, "0.der"))
            for i in range(4):
                with open(os.path.join(here, name, f"{i}.der"), "rb") as src, \
                        open(os.path.join(out, f"{i + 1}.der"), "wb") as dst:
                    dst.write(src.read())
