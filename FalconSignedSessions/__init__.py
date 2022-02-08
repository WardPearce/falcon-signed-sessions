import secrets

from falcon import Request, Response
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.exc import BadSignature


__version__ = "0.0.1"
__url__ = "https://github.com/WardPearce/falcon-signed-cookies"
__description__ = "Signed & trusted sessions for falcon."
__author__ = "WardPearce"
__author_email__ = "wardpearce@pm.me"
__license__ = "AGPL v3"


class SignedSessions:
    def __init__(self, secret_key: str = None,
                 salt: bytes = None, session_cookie: str = "session",
                 **kwargs) -> None:
        """Initialize the signed session middleware.

        Parameters
        ----------
        secret_key : str, optional
            Key used to signed sessions. By default a random secure
            key will be provided but won't be saved, by default None
        salt : bytes, optional
            Salt for signing, by default secure
            salt will be provided, by default None
        session_cookie : str, optional
            Name of the cookie the session is stored in, by default "session"
        """

        if not secret_key:
            secret_key = secrets.token_urlsafe(24)
        if not salt:
            salt = secrets.token_bytes()

        self.__serializer = URLSafeSerializer(
            secret_key=secret_key, salt=salt, **kwargs
        )
        self.__session_cookie = session_cookie

    def __set_session_context(self, req: Request, resp: Response) -> None:
        """Sets the session context for the request.

        Parameters
        ----------
        req : Request
        resp : Response
        """

        req.context.session = {}
        resp.context.session = {}

    def process_request(self, req: Request, resp: Response) -> None:
        session_cookie = req.get_cookie_values(self.__session_cookie)
        if session_cookie:
            try:
                safe_payload = self.__serializer.loads(
                    session_cookie[0]
                )
            except BadSignature:
                self.__set_session_context(req, resp)
            else:
                req.context.session = safe_payload
                resp.context.session = dict(safe_payload)
        else:
            self.__set_session_context(req, resp)

    def process_response(self, req: Request, resp: Response,
                         resource, req_succeeded: bool) -> None:
        if req_succeeded and resp.context.session:
            resp.set_cookie(
                self.__session_cookie,
                self.__serializer.dumps(resp.context.session)
            )
