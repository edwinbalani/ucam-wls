from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .response import AuthResponse

class Key:
    def __init__(self, private_key: RSAPrivateKey, kid: int) -> None:
        if not isinstance(kid, int):
            raise TypeError("kid must be an integer")
        if not (1 <= kid <= 99999999):
            raise ValueError("kid must be in the range 1 to 99999999")
        self._private_key = private_key
        self._kid = kid

    @property
    def private_key(self) -> RSAPrivateKey:
        return self._private_key

    @property
    def kid(self) -> int:
        return self._kid

    def sign(self, response: AuthResponse) -> AuthResponse:
        response.kid = self.kid
        response.signature = self.private_key.sign(
            response.message_to_sign.encode(),
            padding.PKCS1v15(),
            hashes.SHA1(),
        )
        return response
