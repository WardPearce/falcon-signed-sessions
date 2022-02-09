import secrets
from typing import Any

from falcon import Request, Response
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.exc import BadSignature


__version__ = "0.0.3"
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

    def __load_session_cookie(self, req: Request) -> dict:
        session_cookie = req.get_cookie_values(self.__session_cookie)
        if session_cookie:
            try:
                safe_payload = self.__serializer.loads(
                    session_cookie[0]
                )
            except BadSignature:
                safe_payload = {}
        else:
            safe_payload = {}

        return safe_payload

    def process_request(self, req: Request, resp: Response) -> None:
        def get_session(key: str) -> Any:
            if not hasattr(resp.context, "_session"):
                resp.context._session = self.__load_session_cookie(req)
            return resp.context._session.get(key, None)

        def set_session(key: str, value: Any) -> None:
            if not hasattr(resp.context, "_session"):
                resp.context._session = self.__load_session_cookie(req)
            resp.context._session[key] = value

        def sessions() -> dict:
            if not hasattr(resp.context, "_session"):
                resp.context._session = self.__load_session_cookie(req)
            return resp.context._session

        req.context.get_session = get_session
        req.context.sessions = sessions
        resp.context.set_session = set_session

    def process_response(self, req: Request, resp: Response,
                         resource, req_succeeded: bool) -> None:
        if (req_succeeded and hasattr(resp.context, "_session")
                and resp.context._session):
            resp.set_cookie(
                self.__session_cookie,
                self.__serializer.dumps(resp.context._session)
            )
