"ucam_wls top-level module.  The entire public API is made available here."

from typing import Union
from os import PathLike

from . import context, request, response, signing

from .context import AuthPrincipal, LoginService
from .request import AuthRequest
from .response import AuthResponse
from .signing import Key

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


__all__ = ["context", "request", "response", "signing",
           "AuthPrincipal", "LoginService",
           "AuthRequest", "AuthResponse", "Key",
           "load_private_key"]


def load_private_key(path: Union[str, PathLike], kid: int,
                     password: Union[bytes, str, None] = None) -> Key:
    """
    Load a PEM-encoded private key from a given path, assigning it a specified
    key ID ('kid').  A password, if needed, can optionally be specified.

    Arguments:
        path:     The filesystem path to the private key file.

        kid:      The key ID to assign to this private key.

        password: The password, if needed, to decrypt the private key. Should
                  be `None` if the key is not encrypted. If password is given
                  as a `str`, it will be decoded as UTF-8.

    Returns:
        a `ucam_wls.signing.Key` instance.
    """
    if not isinstance(kid, int):
        raise TypeError("kid must be an integer")
    if isinstance(password, str):
        password = password.decode()
    with open(path, 'rb') as f:
        key = load_pem_private_key(f.read(), password, default_backend())
    return Key(key, kid)
