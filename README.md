# Falcon signed sessions
This project allows you to easily add trusted cookies to falcon, it works by storing a signed cookie in the client's browser using [itsdangerous](https://itsdangerous.palletsprojects.com/en/2.0.x/) what we call a session. If the cookie is edited the data won't be loaded into the session context. If you don't store the secret key & salt somewhere secure (like a env file) then the session data will be invalidated between restarts.

## How it works
- Use `req.context.get_session(key)` to read session data, None if doesn't exist.
- Use `req.context.sessions()` to read all sessions.
- Use `resp.context.set_session(key, value)` to edit session data & sign for client.

## Install
`pip3 install FalconSignedSessions`

## How to use
```py
import secrets
from FalconSignedSessions import SignedSessions


app = falcon.App()
app.add_middleware(
    SignedSessions(
        secret_key=secrets.token_urlsafe(24),
        salt=secrets.token_bytes(),
        session_cookie="session"
    )
)


class SessionResource:
    def on_get(self, req: Request, resp: Response) -> None:
        # Get all sessions as dict.
        print(req.context.sessions())

        # Used to get a session
        print(req.context.get_session("trusted"))

        # Set a session.
        resp.context.set_session("trusted", True)


app.add_route("/cookies", SessionResource())
```
