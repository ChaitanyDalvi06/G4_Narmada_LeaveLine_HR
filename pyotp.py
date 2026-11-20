"""
pyotp compatible pure-Python implementation of RFC 6238 (TOTP) and RFC 4226 (HOTP).
Provides standard interface:
  - pyotp.TOTP
  - pyotp.random_base32
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse


class TOTP:
    def __init__(self, s, digits=6, digest=None, name=None, issuer=None, interval=30):
        self.secret = s
        self.digits = digits
        self.digest = digest or hashlib.sha1
        self.name = name
        self.issuer = issuer
        self.interval = interval

    def _generate_otp(self, counter):
        # Base32 decode with padding correction
        cleaned_secret = self.secret.upper().replace(" ", "")
        missing_padding = len(cleaned_secret) % 8
        if missing_padding:
            cleaned_secret += "=" * (8 - missing_padding)
        key = base64.b32decode(cleaned_secret, casefold=True)
        msg = struct.pack(">Q", int(counter))
        h = hmac.new(key, msg, self.digest).digest()
        offset = h[-1] & 0x0F
        code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** self.digits)
        return str(code).zfill(self.digits)

    def at(self, for_time):
        return self._generate_otp(int(for_time) // self.interval)

    def now(self):
        return self.at(time.time())

    def verify(self, otp, valid_window=1):
        if not otp:
            return False
        otp_str = str(otp).strip()
        current_counter = int(time.time()) // self.interval
        for w in range(-valid_window, valid_window + 1):
            expected = self._generate_otp(current_counter + w)
            if hmac.compare_digest(expected, otp_str):
                return True
        return False

    def provisioning_uri(self, name=None, issuer_name=None):
        user_label = name or self.name or "user"
        issuer = issuer_name or self.issuer or ""
        if issuer:
            label = urllib.parse.quote(f"{issuer}:{user_label}")
        else:
            label = urllib.parse.quote(user_label)
        params = [("secret", self.secret)]
        if issuer:
            params.append(("issuer", issuer))
        return f"otpauth://totp/{label}?" + urllib.parse.urlencode(params)


def random_base32(length=32):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(chars) for _ in range(length))

