import logging
import unittest

from curlreq import Curl, Request, version


class CurlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.curl = Curl()
        self.user_agent = version()
        self.have_body = ["PUT", "PATCH", "POST", "DELETE"]

    def testHTTP11(self):
        for method in ["POST", "GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
            with self.subTest(f"testing {method} with HTTP 1.1", method=method):
                data = "abc" if method in self.have_body else None
                req = Request("http://httpbin.org/anything", method, data=data)
                resp = self.curl.do_req(req.prepare(), allow_redirects=False)
                self.assertFalse(resp is None, f"[{method}] response is None")
                self.assertTrue(resp.status_code == 200,
                                f"[{method}] status code failed: expected: 200, but go {resp.status_code}")
                if method != "GET" and method not in self.have_body:
                    self.assertTrue(resp.content == "", f"[{method}] content not empty")
                    continue
                rspj = resp.json
                self.assertTrue(rspj["method"] == method,
                                f"[{method}]method failed: expected: {method} got {rspj['method']}")


if __name__ == '__main__':
    unittest.main()
