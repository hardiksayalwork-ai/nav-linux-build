"""Offline evidence identity prototype. No network or command execution.
The caller supplies a transport and a durable journal. Not wired into CI.
"""
import hashlib
import re
from urllib.parse import urlsplit, urlencode

REPO = "hardiksayalwork-ai/nav-linux-build"
API = "https://api.github.com/repos/" + REPO
WEB = "https://github.com/" + REPO
UPLOAD = "https://uploads.github.com/repos/" + REPO


def positive_id(value):
    if type(value) is not int or value <= 0:
        raise ValueError("non-positive or non-integer identity")
    return value


def check_url(value, prefix):
    if type(value) is not str or not value.startswith(prefix):
        raise ValueError("unexpected URL")
    p = urlsplit(value)
    if p.scheme != "https" or p.username or p.password or p.fragment or p.query:
        raise ValueError("unsafe URL")
    return value


def release_identity(r, name, requested_tag, expected_id=None):
    rid = positive_id(r["id"])
    if expected_id is not None and rid != expected_id:
        raise ValueError("release identity changed")
    if r["draft"] is not True or r["published_at"] is not None or r["name"] != name:
        raise ValueError("not the expected unpublished draft")
    tag = r["tag_name"]
    if tag != requested_tag and not re.fullmatch(r"untagged-[0-9a-f]{20}", tag):
        raise ValueError("unexpected stored tag")
    if r["url"] != API + "/releases/" + str(rid):
        raise ValueError("wrong release API URL")
    html = check_url(r["html_url"], WEB + "/releases/tag/")
    if not re.fullmatch(re.escape(WEB) + r"/releases/tag/[A-Za-z0-9_.-]+", html):
        raise ValueError("unexpected release page URL")
    upload = r["upload_url"]
    wanted = UPLOAD + "/releases/" + str(rid) + "/assets{?name,label}"
    if upload != wanted:
        raise ValueError("wrong upload host, repo or identity")
    return rid


def asset_identity(a, name, data, expected_id=None):
    aid = positive_id(a["id"])
    if expected_id is not None and aid != expected_id:
        raise ValueError("asset identity changed")
    if a["name"] != name or a["state"] != "uploaded":
        raise ValueError("asset upload incomplete or wrong name")
    if type(a["size"]) is not int or a["size"] != len(data):
        raise ValueError("asset size mismatch")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if a["digest"] != digest:
        raise ValueError("asset digest missing or mismatched")
    if a["url"] != API + "/releases/assets/" + str(aid):
        raise ValueError("wrong asset API URL")
    check_url(a["browser_download_url"], WEB + "/releases/download/")
    return aid


def retain(transport, journal, name, requested_tag, commit, asset_name, data):
    """One create, one upload, ID-based readback. No listing, tag lookup or retry.
    transport.download must request API asset bytes and enforce normal trusted
    GitHub redirect handling without forwarding credentials to other hosts.
    No transport implementation or credential handling is included here.
    """
    if not isinstance(data, bytes) or not data:
        raise ValueError("empty or non-byte evidence")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", asset_name):
        raise ValueError("unsafe asset name")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("not an exact commit")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", requested_tag):
        raise ValueError("unsafe requested tag")
    r = transport.create(API + "/releases", {
        "name": name, "tag_name": requested_tag, "target_commitish": commit,
        "draft": True, "prerelease": True, "generate_release_notes": False,
        "body": "Unpublished receipt-only fixed inert host test. No NAV, QEMU, bwrap, private inputs, guest execution, boot or installation. Not OS readiness proof. Do not publish.",
    })
    rid = release_identity(r, name, requested_tag)
    if r["target_commitish"] != commit:
        raise ValueError("wrong create-response target")
    receipt = {"phase": "created", "release_id": rid,
               "release_url": r["html_url"], "stored_tag": r["tag_name"]}
    journal(dict(receipt))
    url = r["upload_url"].split("{", 1)[0] + "?" + urlencode({"name": asset_name})
    a = transport.upload(url, data, "application/gzip")
    aid = asset_identity(a, asset_name, data)
    receipt.update(phase="uploaded", asset_id=aid,
                   asset_url=a["browser_download_url"], bytes=len(data),
                   sha256=hashlib.sha256(data).hexdigest())
    journal(dict(receipt))
    # IDs come from the write responses, not guessed tags or paginated lists.
    final = transport.get(API + "/releases/" + str(rid))
    release_identity(final, name, requested_tag, rid)
    if final["tag_name"] != r["tag_name"] or final["target_commitish"] != commit:
        raise ValueError("release tag or target changed")
    assets = final["assets"]
    found = [x for x in assets if x["id"] == aid]
    if len(found) != 1 or len(assets) != 1:
        raise ValueError("unexpected asset set")
    asset_identity(found[0], asset_name, data, aid)
    meta = transport.get(API + "/releases/assets/" + str(aid))
    asset_identity(meta, asset_name, data, aid)
    downloaded = transport.download(meta["url"])
    if downloaded != data:
        raise ValueError("downloaded bytes differ")
    final_again = transport.get(API + "/releases/" + str(rid))
    release_identity(final_again, name, requested_tag, rid)
    if final_again["tag_name"] != r["tag_name"] or final_again["target_commitish"] != commit:
        raise ValueError("release tag or target changed after download")
    if len(final_again["assets"]) != 1:
        raise ValueError("asset set changed after download")
    asset_identity(final_again["assets"][0], asset_name, data, aid)
    receipt["phase"] = "download_verified"
    journal(dict(receipt))
    return receipt

"""Scoped HTTP transport for draft evidence. No retries and no subprocesses."""
import json
import urllib.request
import urllib.error
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    def __init__(self, token, opener=None):
        if not token:
            raise ValueError("missing host-only token")
        self.token = token
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def request(self, url, method="GET", payload=None, content_type=None,
                binary=False, credentials=True, allow_asset_redirect=False):
        p = urlsplit(url)
        if p.scheme != "https" or p.username or p.password or p.fragment:
            raise ValueError("unsafe request URL")
        if credentials:
            if not (url.startswith(API + "/releases") and p.netloc == "api.github.com"
                    or url.startswith(UPLOAD + "/releases/") and p.netloc == "uploads.github.com"):
                raise ValueError("credential destination rejected")
        elif p.netloc not in {"release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com"}:
            raise ValueError("download destination rejected")
        headers = {"Accept": "application/octet-stream" if binary else "application/vnd.github+json",
                   "User-Agent": "NAV-scoped-evidence-retention", "X-GitHub-Api-Version": "2022-11-28"}
        if credentials:
            headers["Authorization"] = "Bearer " + self.token
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=180) as response:
                body = response.read(64 * 1024 * 1024 + 1)
                if len(body) > 64 * 1024 * 1024:
                    raise ValueError("response exceeds evidence cap")
                return body if binary else json.loads(body)
        except urllib.error.HTTPError as e:
            if allow_asset_redirect and e.code in {301, 302, 303, 307, 308}:
                location = e.headers.get("Location", "")
                # Signed download URLs carry their own scoped access. Never forward
                # the host token or permit another redirect from the asset host.
                return self.request(location, binary=True, credentials=False)
            raise RuntimeError("scoped evidence HTTP status " + str(e.code)) from None
        except urllib.error.URLError:
            raise RuntimeError("scoped evidence network failure; no retry") from None

    def create(self, url, payload):
        if url != API + "/releases" or payload.get("draft") is not True:
            raise ValueError("create scope rejected")
        return self.request(url, "POST", json.dumps(payload).encode(), "application/json")

    def upload(self, url, data, content_type):
        p = urlsplit(url)
        if p.netloc != "uploads.github.com" or not p.path.startswith("/repos/" + REPO + "/releases/"):
            raise ValueError("upload scope rejected")
        return self.request(url, "POST", data, content_type)

    def get(self, url):
        if not url.startswith(API + "/releases/"):
            raise ValueError("read scope rejected")
        return self.request(url)

    def download(self, url):
        if not url.startswith(API + "/releases/assets/"):
            raise ValueError("asset download scope rejected")
        return self.request(url, binary=True, allow_asset_redirect=True)

