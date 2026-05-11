"""
TP-Link Archer AX72 / AX5400 web-UI adapter.

This module talks to the router's built-in web interface. It is not using a
stable vendor API. The request signing/encryption logic is reproduced from the
router JavaScript that the browser loads.

Current scope:
    - password-only login
    - encrypted request/response handling
    - read DHCP settings
    - read DHCP live client list
    - read DHCP reservation list
    - add, update, and delete DHCP reservations

Write operations use the encrypted TP-Link web-UI workflow captured from
the router. Callers should still validate user intent before changing
router configuration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus

import requests
from Crypto.Cipher import AES as CryptoAES
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Util.Padding import pad, unpad


class TPLinkAX72Error(RuntimeError):
    """Raised when the TP-Link router adapter cannot complete an operation."""


@dataclass
class CryptoFeatures:
    sha256_login: bool = True
    replace_hash: bool = True
    # SG CLS L1 Stage 2 firmware enables RSA PKCS#1 OAEP for the
    # request-signature encryption path.  The JavaScript RSA library chunks
    # long plaintext internally, so this still works with the router's
    # 512-bit auth key.
    rsa_oaep: bool = True


class TPLinkAX72Router:
    def __init__(
        self,
        base_url: str,
        password: str,
        timeout: float = 10.0,
        features: CryptoFeatures | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.timeout = timeout
        self.features = features or CryptoFeatures()

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/x-www-form-urlencoded",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/webpages/index.html",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/147.0.0.0 Safari/537.36"
                ),
            }
        )

        self.stok = ""
        self.auth_rsa_n = ""
        self.auth_rsa_e = ""
        self.password_rsa_n = ""
        self.password_rsa_e = ""
        self.seq = 0
        self.aes_key = ""
        self.aes_iv = ""
        self.hash_value = ""
        self.last_encrypted_sign_len = 0
        self.last_encrypted_data_len = 0
        self.last_plaintext_len = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def login(self) -> bool:
        """Log in and store sysauth cookie + stok token."""
        self._bootstrap_session()
        self._load_crypto_feature_hints()
        self._prelogin_probe_sequence()
        self._read_password_key()
        self._read_auth_params()

        self._generate_aes_key()
        self.hash_value = self._password_hash(self.password)

        # The router JS encrypts the visible login password with RSA PKCS#1
        # v1.5, even on firmware that uses OAEP for the request signature.
        # The captured AX72 firmware also uses PKCS#1 v1.5 for the
        # withAesKey signature chunks because its auth key is 512-bit.
        encrypted_password = self._rsa_encrypt_hex(
            self.password,
            self.password_rsa_n,
            self.password_rsa_e,
            use_oaep=False,
        )

        # The JS call path is:
        #   serviceAdapter.write(url, {password, operation: "login"})
        # which becomes:
        #   {operation: "write", ...payload}
        # The duplicate operation value is overwritten to "login", but the
        # original property order is retained.  Therefore the plaintext
        # querystring is operation first, then password.  TP-Link appears
        # sensitive to this exact serialisation during login.
        response = self._post_encrypted(
            "/login?form=login",
            {
                "operation": "login",
                "password": encrypted_password,
            },
            include_aes_key=True,
            allow_no_token=True,
        )

        data = response.get("data", response)
        stok = data.get("stok") if isinstance(data, dict) else None

        if not stok:
            raise TPLinkAX72Error(
                "Login response decrypted, but no stok token was found. "
                f"Response summary: {self._safe_debug_value(response)}. "
                f"Session cookie names: "
                f"{sorted(cookie.name for cookie in self.session.cookies)}"
            )

        self.stok = str(stok)
        return True

    def logout(self) -> None:
        if not self.stok:
            return
        try:
            self._post_encrypted(
                "/login?form=logout",
                {"operation": "logout"},
            )
        except Exception:
            pass
        finally:
            self.stok = ""

    def get_dhcp_settings(self) -> dict[str, Any]:
        response = self._post_encrypted(
            "/admin/dhcps?form=setting",
            {"operation": "read"},
        )
        return self._response_data(response)

    def get_dhcp_clients(self) -> Any:
        # Browser-captured DHCP client-list request uses operation=load.
        response = self._post_encrypted(
            "/admin/dhcps?form=client",
            {"operation": "load"},
        )
        return self._response_data(response)

    def get_dhcp_reservations(self) -> Any:
        # Browser-captured reservation-list request also uses operation=load.
        response = self._post_encrypted(
            "/admin/dhcps?form=reservation",
            {"operation": "load"},
        )
        return self._response_data(response)

    def add_dhcp_reservation(
        self,
        mac: str,
        ip: str,
        hostname: str = "",
        index: int = 0,
        enable: str = "on",
    ) -> dict[str, Any]:
        """Add one DHCP reservation through the TP-Link web UI workflow."""
        mac = self._normalise_mac(mac)
        ip = self._normalise_ip(ip)
        hostname = str(hostname or "")
        enable = "on" if str(enable).lower() in {"on", "true", "1", "yes"} else "off"

        self._assert_no_duplicate_reservation(mac=mac, ip=ip)

        key = self._generate_table_key()
        new_entry = {
            "enable": enable,
            "key": key,
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
        }

        response = self._post_encrypted(
            "/admin/dhcps?form=reservation",
            {
                "operation": "insert",
                "new": new_entry,
                "index": int(index),
            },
        )
        return self._response_data(response)

    def update_dhcp_reservation(
        self,
        *,
        match_mac: str | None = None,
        match_ip: str | None = None,
        new_mac: str | None = None,
        new_ip: str | None = None,
        new_hostname: str | None = None,
        enable: str | None = None,
    ) -> dict[str, Any]:
        """Update one existing DHCP reservation.

        The current row is found from a fresh reservation load by MAC first,
        then IP.  TP-Link's captured update request uses a transient random
        21-character table key in the top-level key, old object, and new
        object.  The router's loaded reservation list does not persist that
        key, so this method generates one per update operation.
        """
        current, _index = self._find_reservation(match_mac=match_mac, match_ip=match_ip)
        key = self._generate_table_key()

        old_entry = self._reservation_payload_from_loaded(current, key)
        next_mac = self._normalise_mac(new_mac) if new_mac else old_entry["mac"]
        next_ip = self._normalise_ip(new_ip) if new_ip else old_entry["ip"]
        next_hostname = old_entry["hostname"] if new_hostname is None else str(new_hostname)
        next_enable = old_entry["enable"] if enable is None else (
            "on" if str(enable).lower() in {"on", "true", "1", "yes"} else "off"
        )

        self._assert_no_duplicate_reservation(
            mac=next_mac,
            ip=next_ip,
            exclude=current,
        )

        # Captured new object order: key, enable, hostname, ip, mac.
        new_entry = {
            "key": key,
            "enable": next_enable,
            "hostname": next_hostname,
            "ip": next_ip,
            "mac": next_mac,
        }

        response = self._post_encrypted(
            "/admin/dhcps?form=reservation",
            {
                "operation": "update",
                "key": key,
                "new": new_entry,
                "old": old_entry,
            },
        )
        return self._response_data(response)

    def delete_dhcp_reservation(
        self,
        *,
        match_mac: str | None = None,
        match_ip: str | None = None,
    ) -> dict[str, Any]:
        """Delete one existing DHCP reservation.

        The current row index is calculated from a fresh reservation load just
        before deletion, reducing the risk of deleting a different row after a
        table reorder.
        """
        _current, index = self._find_reservation(match_mac=match_mac, match_ip=match_ip)
        key = self._generate_table_key()
        response = self._post_encrypted(
            "/admin/dhcps?form=reservation",
            {
                "operation": "remove",
                "key": key,
                "index": int(index),
            },
        )
        return self._response_data(response)

    # ------------------------------------------------------------------
    # Login preparation
    # ------------------------------------------------------------------

    def _bootstrap_session(self) -> None:
        """Load the web UI once so the router can issue its initial cookie.

        The browser has a sysauth cookie already present when it sends the
        encrypted login request.  Some TP-Link firmware rejects login attempts
        that do not carry the initial cookie created while loading the web UI.
        """
        urls = [
            f"{self.base_url}/",
            f"{self.base_url}/webpages/index.html",
        ]

        for url in urls:
            try:
                self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                # The API endpoints may still work even if one page fetch fails.
                pass

    def _load_crypto_feature_hints(self) -> None:
        """
        Read device_config where possible and infer crypto feature flags.

        The user's router reports SG CLS L1 STAGE2 and EU CE RED, which means
        SHA256 login, GDPR encryption, replace-hash, and RSA OAEP are expected.
        This function keeps defaults if the unauthenticated config read fails.
        """
        try:
            response = self._post_plain(
                "/device_config?form=config",
                {"operation": "read"},
                allow_no_token=True,
            )
            data = response.get("data", {})
            certifications = set(data.get("certification", []))
        except Exception:
            return

        if not certifications:
            return

        sg = "SG CLS L1 STAGE2" in certifications
        ce_red = "EU CE RED" in certifications
        rg = "IMDA TS RG-SEC" in certifications
        anatel = "Brazil ANATEL" in certifications

        self.features.sha256_login = sg or ce_red or rg or anatel
        self.features.replace_hash = sg
        # Feature 13 in the router JavaScript maps RSA PKCS#1 OAEP support
        # to SG CLS L1 STAGE2 certification.  The NodeRSA library used by
        # the browser chunks long OAEP plaintext internally.
        self.features.rsa_oaep = sg


    @staticmethod
    def _normalise_rsa_key_pair(key: Any, label: str) -> tuple[str, str]:
        """Return an RSA key pair as (modulus_hex, exponent_hex).

        TP-Link firmware usually returns [modulus, exponent], but some
        endpoints/firmware builds return objects or reversed lists.  A reversed
        pair makes Python construct a tiny RSA modulus and then encryption fails
        with "Plaintext is too long".  Normalising here makes the adapter more
        tolerant and gives a useful error if the response shape changes.
        """
        if isinstance(key, dict):
            n = key.get("n") or key.get("nn") or key.get("modulus")
            e = key.get("e") or key.get("ee") or key.get("exponent")
            key = [n, e]

        if isinstance(key, str):
            parts: dict[str, str] = {}
            for item in key.split("&"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    parts[k] = v
            if parts:
                key = [
                    parts.get("n") or parts.get("nn") or parts.get("modulus"),
                    parts.get("e") or parts.get("ee") or parts.get("exponent"),
                ]

        if not isinstance(key, list) or len(key) < 2:
            raise TPLinkAX72Error(f"Could not parse {label} RSA key pair.")

        a = str(key[0] or "").strip()
        b = str(key[1] or "").strip()

        if not a or not b:
            raise TPLinkAX72Error(f"Incomplete {label} RSA key pair.")

        # Public exponent is normally 010001 and much shorter than the modulus.
        if len(a) <= 8 and len(b) > len(a):
            n, e = b, a
        else:
            n, e = a, b

        n = n.lower().removeprefix("0x")
        e = e.lower().removeprefix("0x")

        try:
            int(n, 16)
            int(e, 16)
        except ValueError as exc:
            raise TPLinkAX72Error(f"Invalid hex in {label} RSA key pair.") from exc

        if len(n) < 128:
            raise TPLinkAX72Error(
                f"{label} RSA modulus looks too short: {len(n)} hex chars. "
                "The key pair may still be in an unexpected format."
            )

        return n, e

    def _prelogin_probe_sequence(self) -> None:
        """Mimic the router web UI's pre-login read sequence.

        Chrome shows these POST reads before the visible login request. They do
        not set cookies on the captured AX72, but they may still initialise
        router-side state or feature flags before /login?form=login is accepted.
        Failures are non-fatal because firmware variants may omit some forms.
        """
        paths = [
            "/locale?form=lang",
            "/locale?form=country",
            "/device_config?form=config",
            "/login?form=check_factory_default",
            "/login?form=list",
            "/login?form=sysmode",
            "/domain_login?form=dlogin",
        ]
        for path in paths:
            try:
                self._post_plain(path, {"operation": "read"}, allow_no_token=True)
            except Exception:
                pass

    def _read_password_key(self) -> None:
        response = self._post_plain(
            "/login?form=keys",
            {"operation": "read"},
            allow_no_token=True,
        )
        data = response.get("data", {})

        key = (
            data.get("password")
            or data.get("key")
            or data.get("keys")
            or data.get("rsa")
        )

        if key is None:
            raise TPLinkAX72Error(
                "Could not find password RSA key in /login?form=keys response. "
                f"Response data keys: {list(data.keys())}"
            )

        self.password_rsa_n, self.password_rsa_e = self._normalise_rsa_key_pair(
            key,
            "password",
        )

    def _read_auth_params(self) -> None:
        response = self._post_plain(
            "/login?form=auth",
            {"operation": "read"},
            allow_no_token=True,
        )
        data = response.get("data", {})
        key = data.get("key")
        seq = data.get("seq")

        if key is None or seq is None:
            raise TPLinkAX72Error(
                "Could not find auth RSA key + seq in /login?form=auth response."
            )

        self.auth_rsa_n, self.auth_rsa_e = self._normalise_rsa_key_pair(
            key,
            "auth",
        )
        self.seq = int(seq)

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _url(self, path: str, allow_no_token: bool = False) -> str:
        token = self.stok if self.stok else ""
        if not token and not allow_no_token:
            raise TPLinkAX72Error("Router is not logged in; stok token missing.")
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}/cgi-bin/luci/;stok={token}{path}"

    def _post_plain(
        self,
        path: str,
        payload: dict[str, Any],
        allow_no_token: bool = False,
    ) -> dict[str, Any]:
        url = self._url(path, allow_no_token=allow_no_token)
        body = self._serialize(payload)
        response = self.session.post(
            url,
            data=body,
            timeout=self.timeout,
        )
        self._raise_for_status_with_context(response, path, body)
        return response.json()

    def _post_encrypted(
        self,
        path: str,
        payload: dict[str, Any],
        include_aes_key: bool = False,
        allow_no_token: bool = False,
    ) -> dict[str, Any]:
        encrypted = self._encrypt_payload(payload, include_aes_key=include_aes_key)
        url = self._url(path, allow_no_token=allow_no_token)
        body_text = self._serialize(encrypted)
        response = self.session.post(
            url,
            data=body_text,
            timeout=self.timeout,
        )
        self._raise_for_status_with_context(response, path, body_text)
        body = response.json()

        if "data" not in body:
            return body

        decrypted = self._aes_decrypt_to_text(str(body["data"]))
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise TPLinkAX72Error(
                "Router response decrypted, but it was not valid JSON."
            ) from exc

    def _raise_for_status_with_context(
        self,
        response: requests.Response,
        path: str,
        request_body: str,
    ) -> None:
        if response.status_code < 400:
            return

        cookie_names = sorted(cookie.name for cookie in self.session.cookies)
        response_text = response.text[:500].replace("\r", " ").replace("\n", " ")
        debug = (
            f"HTTP {response.status_code} from router for {path}. "
            f"Request body length={len(request_body)}. "
            f"Session cookie names={cookie_names}. "
            f"Auth key bits={len(self.auth_rsa_n) * 4 if self.auth_rsa_n else 0}. "
            f"Password key bits={len(self.password_rsa_n) * 4 if self.password_rsa_n else 0}. "
            f"Plaintext len={self.last_plaintext_len}. "
            f"sign len={self.last_encrypted_sign_len}. "
            f"data len={self.last_encrypted_data_len}. "
            f"Response body prefix={response_text!r}"
        )
        raise TPLinkAX72Error(debug)

    # ------------------------------------------------------------------
    # Crypto helpers matching router JS
    # ------------------------------------------------------------------

    def _generate_aes_key(self) -> None:
        self.aes_key = "".join(str(secrets.randbelow(10)) for _ in range(16))
        self.aes_iv = "".join(str(secrets.randbelow(10)) for _ in range(16))

    def _aes_formatted_key(self) -> str:
        return f"k={self.aes_key}&i={self.aes_iv}"

    def _password_hash(self, password: str) -> str:
        material = f"admin{password}".encode("utf-8")
        if self.features.sha256_login:
            return hashlib.sha256(material).hexdigest()
        return hashlib.md5(material).hexdigest()

    def _encrypt_payload(
        self,
        payload: dict[str, Any],
        include_aes_key: bool = False,
    ) -> dict[str, str]:
        plaintext = self._serialize(payload)
        data = self._aes_encrypt_to_base64(plaintext)

        if self.features.replace_hash and self.stok and not include_aes_key:
            self.hash_value = hashlib.sha256(data.encode("utf-8")).hexdigest()

        sign = self._generate_signature(self.seq + len(data), include_aes_key)
        self.last_plaintext_len = len(plaintext)
        self.last_encrypted_sign_len = len(sign)
        self.last_encrypted_data_len = len(data)
        return {"sign": sign, "data": data}

    def _generate_signature(self, sequence_and_length: int, include_aes_key: bool) -> str:
        message = f"h={self.hash_value}&s={sequence_and_length}"
        if include_aes_key:
            message = f"{self._aes_formatted_key()}&{message}"

        # Match the router JavaScript: SIGNATURE_OFFSET is 53 chars.
        # When OAEP is enabled on a 512-bit key, NodeRSA then internally
        # splits each 53-char string into several smaller RSA-OAEP blocks.
        chunk_size = 53
        chunks = [message[i : i + chunk_size] for i in range(0, len(message), chunk_size)]

        if include_aes_key:
            return "".join(
                self._rsa_encrypt_hex(
                    chunk,
                    self.auth_rsa_n,
                    self.auth_rsa_e,
                    use_oaep=self.features.rsa_oaep,
                )
                for chunk in chunks
            )

        key = self._aes_formatted_key().encode("utf-8")
        return "".join(
            hmac.new(key, chunk.encode("utf-8"), hashlib.sha256).hexdigest()
            for chunk in chunks
        )

    def _aes_encrypt_to_base64(self, plaintext: str) -> str:
        cipher = CryptoAES.new(
            self.aes_key.encode("utf-8"),
            CryptoAES.MODE_CBC,
            self.aes_iv.encode("utf-8"),
        )
        encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), 16))
        return base64.b64encode(encrypted).decode("ascii")

    def _aes_decrypt_to_text(self, ciphertext_b64: str) -> str:
        cipher = CryptoAES.new(
            self.aes_key.encode("utf-8"),
            CryptoAES.MODE_CBC,
            self.aes_iv.encode("utf-8"),
        )
        raw = base64.b64decode(ciphertext_b64)
        return unpad(cipher.decrypt(raw), 16).decode("utf-8")

    @staticmethod
    def _rsa_encrypt_hex(
        text: str,
        modulus_hex: str,
        exponent_hex: str,
        use_oaep: bool = True,
    ) -> str:
        n = int(modulus_hex, 16)
        e = int(exponent_hex, 16)
        public_key = CryptoRSA.construct((n, e))

        try:
            if use_oaep:
                cipher = PKCS1_OAEP.new(public_key)
                key_bytes = public_key.size_in_bytes()
                hash_len = cipher._hashObj.digest_size
                max_chunk = key_bytes - (2 * hash_len) - 2
                if max_chunk <= 0:
                    raise ValueError("RSA-OAEP key too small for selected hash")

                plaintext = text.encode("utf-8")
                encrypted_parts = []
                for offset in range(0, len(plaintext), max_chunk):
                    encrypted_parts.append(cipher.encrypt(plaintext[offset:offset + max_chunk]))
                encrypted = b"".join(encrypted_parts)
            else:
                cipher = PKCS1_v1_5.new(public_key)
                encrypted = cipher.encrypt(text.encode("utf-8"))
        except ValueError as exc:
            key_bits = public_key.size_in_bits()
            raise TPLinkAX72Error(
                "RSA encryption failed. "
                f"key_bits={key_bits}, plaintext_len={len(text)}, "
                f"use_oaep={use_oaep}. Original error: {exc}"
            ) from exc

        return encrypted.hex()

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize(payload: dict[str, Any]) -> str:
        parts: list[str] = []

        def add(key: str, value: Any) -> None:
            if value is None:
                return
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, (dict, list)):
                value = json.dumps(value, separators=(",", ":"))
            else:
                value = str(value)
            parts.append(f"{quote_plus(key)}={quote_plus(value)}")

        for key, value in payload.items():
            if isinstance(value, list):
                for item in value:
                    add(key, item)
            else:
                add(key, value)

        return "&".join(parts)


    @staticmethod
    def _safe_debug_value(value: Any, depth: int = 0) -> Any:
        """Return a compact, non-secret-ish debug representation.

        Router login failures usually return useful fields such as success,
        errorcode, failureCount, and attemptsAllowed.  This avoids dumping
        long encrypted blobs, cookies, tokens, keys, or passwords.
        """
        if depth > 4:
            return "..."

        secret_key_parts = (
            "password",
            "passwd",
            "token",
            "stok",
            "sysauth",
            "cookie",
            "sign",
            "key",
        )

        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                key_text = str(key)
                lower_key = key_text.lower()

                if any(part in lower_key for part in secret_key_parts):
                    result[key_text] = "REDACTED"
                else:
                    result[key_text] = TPLinkAX72Router._safe_debug_value(
                        item,
                        depth + 1,
                    )
            return result

        if isinstance(value, list):
            return [
                TPLinkAX72Router._safe_debug_value(item, depth + 1)
                for item in value[:10]
            ]

        if isinstance(value, str):
            if len(value) > 120:
                return f"<string len={len(value)}>"
            return value

        return value

    @staticmethod
    def _response_data(response: dict[str, Any]) -> Any:
        if response.get("success") is False:
            code = (
                response.get("errorCode")
                or response.get("errorcode")
                or response.get("error")
                or response
            )
            raise TPLinkAX72Error(f"Router returned failure: {code}")
        return response.get("data", response)

    # ------------------------------------------------------------------
    # DHCP reservation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_table_key() -> str:
        # Captured TP-Link UI keys are 21 URL-safe characters such as
        # kgZTiYjdhBxZUs9XSgCrS and -W6Ai7uLlUBOdQ4V2s9fc.
        return secrets.token_urlsafe(16)[:21]

    @staticmethod
    def _normalise_mac(mac: str) -> str:
        text = str(mac or "").strip().upper()
        hex_chars = re.sub(r"[^0-9A-F]", "", text)
        if len(hex_chars) != 12:
            raise TPLinkAX72Error(f"Invalid MAC address: {mac!r}")
        return "-".join(hex_chars[i : i + 2] for i in range(0, 12, 2))

    @staticmethod
    def _normalise_ip(ip: str) -> str:
        try:
            return str(ipaddress.ip_address(str(ip).strip()))
        except ValueError as exc:
            raise TPLinkAX72Error(f"Invalid IP address: {ip!r}") from exc

    @staticmethod
    def _reservation_payload_from_loaded(
        entry: dict[str, Any],
        key: str,
    ) -> dict[str, str]:
        # Captured old object order: enable, key, hostname, ip, mac.
        hostname = str(
            entry.get("hostname")
            or entry.get("comment")
            or ""
        )
        return {
            "enable": str(entry.get("enable") or "on"),
            "key": key,
            "hostname": hostname,
            "ip": TPLinkAX72Router._normalise_ip(str(entry.get("ip") or "")),
            "mac": TPLinkAX72Router._normalise_mac(str(entry.get("mac") or "")),
        }

    def _load_reservation_rows(self) -> list[dict[str, Any]]:
        rows = self.get_dhcp_reservations()
        if isinstance(rows, dict):
            rows = rows.get("data", [])
        if not isinstance(rows, list):
            raise TPLinkAX72Error(
                f"Unexpected DHCP reservation list type: {type(rows).__name__}"
            )
        return rows

    def _find_reservation(
        self,
        *,
        match_mac: str | None = None,
        match_ip: str | None = None,
    ) -> tuple[dict[str, Any], int]:
        mac = self._normalise_mac(match_mac) if match_mac else None
        ip = self._normalise_ip(match_ip) if match_ip else None
        if not mac and not ip:
            raise TPLinkAX72Error("A MAC address or IP address is required.")

        rows = self._load_reservation_rows()

        if mac:
            for index, entry in enumerate(rows):
                try:
                    if self._normalise_mac(str(entry.get("mac", ""))) == mac:
                        return entry, index
                except TPLinkAX72Error:
                    continue

        if ip:
            for index, entry in enumerate(rows):
                try:
                    if self._normalise_ip(str(entry.get("ip", ""))) == ip:
                        return entry, index
                except TPLinkAX72Error:
                    continue

        target = mac or ip or "<unknown>"
        raise TPLinkAX72Error(f"DHCP reservation not found: {target}")

    def _assert_no_duplicate_reservation(
        self,
        *,
        mac: str,
        ip: str,
        exclude: dict[str, Any] | None = None,
    ) -> None:
        wanted_mac = self._normalise_mac(mac)
        wanted_ip = self._normalise_ip(ip)

        exclude_mac = None
        exclude_ip = None
        if exclude:
            try:
                exclude_mac = self._normalise_mac(str(exclude.get("mac", "")))
            except TPLinkAX72Error:
                pass
            try:
                exclude_ip = self._normalise_ip(str(exclude.get("ip", "")))
            except TPLinkAX72Error:
                pass

        for entry in self._load_reservation_rows():
            try:
                existing_mac = self._normalise_mac(str(entry.get("mac", "")))
                existing_ip = self._normalise_ip(str(entry.get("ip", "")))
            except TPLinkAX72Error:
                continue

            if exclude_mac and exclude_ip:
                if existing_mac == exclude_mac and existing_ip == exclude_ip:
                    continue

            if existing_mac == wanted_mac:
                raise TPLinkAX72Error(
                    f"A reservation already exists for MAC {wanted_mac} at {existing_ip}."
                )
            if existing_ip == wanted_ip:
                raise TPLinkAX72Error(
                    f"A reservation already exists for IP {wanted_ip} on MAC {existing_mac}."
                )


def load_router_from_config(path: str = "router_config.json") -> TPLinkAX72Router:
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

    selected = config["selected_router"]
    router = config["routers"][selected]

    if router.get("type") != "tplink_archer_ax72":
        raise TPLinkAX72Error(f"Unsupported router type: {router.get('type')}")

    return TPLinkAX72Router(
        base_url=router["base_url"],
        password=router["password"],
    )
