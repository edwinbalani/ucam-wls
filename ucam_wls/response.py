import base64
import random
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from typing import Any, Dict, Iterable, Optional

from . import status
from .errors import SignatureNeeded
from .request import AuthRequest
from .util import datetime_to_protocol


def encode_response_part(part):
    if part is None:
        return ''
    return str(part).replace('%', '%25').replace('!', '%21')


class AuthResponse:
    @classmethod
    def respond_to_request(cls, request: AuthRequest, code: int, *args, **kwargs):
        if not isinstance(request, AuthRequest):
            raise TypeError("request must be an AuthRequest instance")
        if not isinstance(code, int):
            raise TypeError("status code must be an integer")

        return cls(ver=request.ver, code=code, url=request.url,
                   params=request.params, *args, **kwargs)

    PARAMS = {'code', 'principal', 'msg', 'issue', 'id', 'url', 'ptags', 'auth',
              'sso', 'life', 'params', 'kid', 'signature'}

    def __init__(self, ver: int, code: int, url: str, params: str,
                 principal: Optional[str] = None, msg: Optional[str] = None,
                 issue: Optional[datetime] = None, ptags: Iterable[str] = None,
                 auth: Optional[str] = None, sso: Optional[str] = None,
                 life: Optional[int] = None) -> None:
        if not isinstance(code, int):
            raise TypeError("code %r must be an integer" % code)

        if principal is None:
            principal = ''
        if msg is None:
            msg = ''
        if issue is None:
            issue = datetime.utcnow()
        if ptags is None:
            ptags = []
        if auth is None:
            auth = ''
        if sso is None:
            sso = []

        # Check for invalid combinations of values
        if ((code == status.SUCCESS and principal == '') or 
            (code != status.SUCCESS and principal != '')):
            raise ValueError("principal must only be given if "
                             "authentication was successful")
        if code == status.SUCCESS and auth == '' and len(sso) == 0:
            raise ValueError("sso must be given if auth is not given")

        self.ver = ver
        self.code = code
        self.principal = principal
        self.msg = msg
        self.issue = issue
        self.id = random.randint(100000, 999999)
        self.url = url
        self.ptags = ptags
        self.auth = auth
        self.sso = sso
        self.life = life
        self.params = params

        self.kid = None
        self.signature = None

    @property
    def as_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.PARAMS}

    @property
    def signature_b64(self) -> str:
        if self.signature is None:
            return None
        return base64.b64encode(self.signature).decode()\
               .replace('+', '-').replace('/', '.').replace('=', '_')

    @property
    def requires_signature(self) -> bool:
        return self.code == status.SUCCESS

    @property
    def is_signed(self) -> bool:
        return self.signature is not None

    @property
    def message_to_sign(self) -> str:
        parts = [self.ver, self.code, self.msg,
                 datetime_to_protocol(self.issue),
                 self.id, self.url, self.principal] + \
                ([','.join(self.ptags)] if self.ver == 3 else []) + \
                [self.auth, ','.join(self.sso), self.life, self.params]
        return '!'.join(map(encode_response_part, parts))

    @property
    def response_string(self) -> str:
        if self.requires_signature and not self.is_signed:
            raise SignatureNeeded("response code is %d" % self.code)

        return '!'.join([
            self.message_to_sign,
            encode_response_part(self.kid),
            encode_response_part(self.signature_b64),
        ])

    @property
    def redirect_url(self) -> str:
        scheme, netloc, path, orig_query, _ = urlsplit(self.url)

        if self.ver == 1:
            # Ignore existing query string
            qsl = []
        else:
            # Incorporate WLS-Response into existing query string
            qsl = parse_qsl(orig_query)

        qsl.append(('WLS-Response', self.response_string))
        query = urlencode(qsl)
        return urlunsplit((scheme, netloc, path, query, ''))
