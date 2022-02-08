# Falcon signed sessions
This project allows you to easily add trusted cookies to falcon, it works by storing a signed cookie in the client's browser using [itsdangerous](https://itsdangerous.palletsprojects.com/en/2.0.x/) what we call a session. If the cookie is edited the data won't be loaded into the session context.

## How it works
- Use `req.context.session` to read session data.
- Use `resp.context.session` to edit session data & sign for client.

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
        # Get session values from request.
        print(req.context.session)

        # Set a session.
        resp.context.session["trusted"] = True


app.add_route("/cookies", SessionResource())
```
