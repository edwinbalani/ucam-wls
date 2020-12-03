from inspect import isclass
from typing import Optional

from .status import (
    SUCCESS, USER_CANCEL, NO_MUTUAL_AUTH_TYPES, UNSUPPORTED_PROTO_VER,
    REQUEST_PARAM_ERROR, INTERACTION_REQUIRED,
    AUTH_DECLINED
)

__all__ = [
    "WLSError", "InvalidAuthRequest", "SignatureNeeded", "CannotHandleRequest",
    "ProtocolVersionUnsupported", "NoMutualAuthType",
    "exception_for_code", "code_for_exception",
]

class WLSError(Exception):
    "A generic error occurred in the web login service."

    @classmethod
    def waa2wls_code(cls) -> Optional[int]:
        return code_for_exception(cls)

class InvalidAuthRequest(WLSError):
    "An invalid authentication request was received from a WAA."

class SignatureNeeded(WLSError):
    "The WLS response needs signing before further handling can be done."

class CannotHandleRequest(WLSError):
    "The web login service cannot handle the WAA request for an unspecified reason."

class ProtocolVersionUnsupported(CannotHandleRequest):
    "The web login service does not support the protocol version requested by the WAA."

class NoMutualAuthType(CannotHandleRequest):
    "The web login service does not support any of the authentication types requested by the WAA."


_EXCEPTION_CODE_MAP = { NO_MUTUAL_AUTH_TYPES: NoMutualAuthType,
    UNSUPPORTED_PROTO_VER: ProtocolVersionUnsupported,
    REQUEST_PARAM_ERROR: InvalidAuthRequest,
}

_CODE_EXCEPTION_MAP = {v: k for k, v in _EXCEPTION_CODE_MAP.items()}

def exception_for_code(code: int) -> Optional[WLSError]:
    return _EXCEPTION_CODE_MAP.get(code)

def code_for_exception(exception: WLSError) -> Optional[int]:
    if type(exception) is type:
        # We have been given the class itself
        e = exception
    else:
        # We have been given a class instance
        e = exception.__class__
    return _CODE_EXCEPTION_MAP.get(e)
