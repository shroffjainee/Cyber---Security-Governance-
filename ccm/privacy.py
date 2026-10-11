"""Privacy and data-leak-prevention helpers.

Answers the internal review comment "Privacy issues & DLP":
  * hostnames / IPs are replaced by a keyed pseudonym (HMAC-SHA256) before storage,
    so a leaked database does not reveal which real machine is vulnerable;
  * free text from scanners is scrubbed of IPv4 addresses, e-mail ids and
    long digit strings (phone / account numbers) before it is stored;
  * the key lives in an environment variable, never in the database.
"""
import hashlib
import hmac
import os
import re

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
_LONGNUM = re.compile(r"\b\d{8,}\b")


def _key(env_var):
    key = os.environ.get(env_var)
    if not key:
        # Development fallback only; set the env var in real deployments.
        key = "ccm-dev-key-change-me"
    return key.encode()


def pseudonym(name, env_var="CCM_PSEUDO_KEY"):
    digest = hmac.new(_key(env_var), name.encode(), hashlib.sha256).hexdigest()
    return "asset-" + digest[:10]


def scrub(text):
    if not text:
        return text
    text = _IP.sub("[ip]", text)
    text = _EMAIL.sub("[email]", text)
    return _LONGNUM.sub("[number]", text)
