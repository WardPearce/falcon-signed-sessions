import falcon
from falcon import testing, Request, Response

from . import SignedSessions


EXPECTED_COOKIES = {
    "hello": "world",
    "foo": "bar"
}


class CookiesResource:
    def on_get(self, req: Request, resp: Response) -> None:
        """Check if cookie matches the expected cookie.
        """

        passed = True
        for c_name, c_value in (req.context.sessions()).items():
            if (c_name not in EXPECTED_COOKIES or
                    EXPECTED_COOKIES[c_name] != c_value):
                passed = False
                break
            else:
                if not req.context.get_session(c_name):
                    passed = False
                    break

        if len(req.context.sessions()) == len(EXPECTED_COOKIES):
            passed = False

        resp.media = {
            "passed": passed
        }

    def on_post(self, req: Request, resp: Response) -> None:
        """Set expected cookie values for the expected cookies.
        """

        for c_name, c_value in EXPECTED_COOKIES.items():
            resp.context.set_session(c_name, c_value)

    def on_put(self, req: Request, resp: Response) -> None:
        resp.media = {
            "passed": not req.context.sessions()
        }


app = falcon.App()
app.add_middleware(SignedSessions())
app.add_route("/cookies", CookiesResource())


class SignedSessionsCase(testing.TestCase):
    def setUp(self):
        super(SignedSessionsCase, self).setUp()
        self.app = app


class TestSignedSessions(SignedSessionsCase):
    def test_no_plain_cookies(self) -> None:
        result = self.simulate_post("/cookies")
        for cookie in result.cookies:
            self.assertNotIn(
                cookie,
                EXPECTED_COOKIES,
                "Raw session data was in cookie!"
            )

    def test_cookie_resp_correct(self) -> None:
        result = self.simulate_get("/cookies")
        self.assertTrue(result.json["passed"])

    def test_evil_request(self) -> None:
        result = self.simulate_get("/cookies", cookies=EXPECTED_COOKIES)
        self.assertTrue(
            result.json["passed"],
            "Cookies not signed by itsdangerous was allowed passed!"
        )

    def test_cookie_same_on_no_change(self) -> None:
        old = self.simulate_post("/cookies")
        new = self.simulate_get("/cookies", cookies={
            "session": old.cookies["session"].value
        })

        self.assertEqual(
            old.cookies["session"].value,
            new.cookies["session"].value,
            "When session remains the same, the cookie changes!"
        )

    def test_edited_session_invalid(self) -> None:
        old = self.simulate_post("/cookies")
        old_cookie = old.cookies["session"].value
        new = self.simulate_get("/cookies", cookies={
            "session": "WzEsMiwzLDRd." + old_cookie[old_cookie.find("."):]
        })

        self.assertTrue(new.json["passed"])
