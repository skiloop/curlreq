import logging
import unittest

import pycurl

from curlreq import Curl, Request, version

METHODS_WITH_BODY = ["PUT", "PATCH", "POST", "DELETE"]


def test_request(case, curl, method, url, body, **kwargs):
    data = body if method in METHODS_WITH_BODY else None
    req = Request(url, method, data=data)
    resp = curl.do_req(req.prepare(), **kwargs)
    case.assertFalse(resp is None, f"[{method}] response is None")
    if resp.status_code == 405:
        return
    case.assertTrue(resp.status_code in [200, 204],
                    f"[{method}] status code failed: expected: 200, but go {resp.status_code}")
    if resp.status_code == 204:
        return
    if method not in ["GET", "TRACE"] and method not in METHODS_WITH_BODY:
        case.assertTrue(resp.content == b"", f"[{method}] content not empty")
        return
    rspj = resp.json
    case.assertTrue(rspj["method"] == method,
                    f"[{method}]method failed: expected: {method} got {rspj['method']}")


class CurlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.curl = Curl()
        self.curl.setopt(pycurl.TIMEOUT, 20)
        self.test_http_url = "http://httpbin.org/anything"
        self.test_https_url = "https://httpbin.org/anything"
        self.user_agent = version()
        self.have_body = ["PUT", "PATCH", "POST", "DELETE"]
        self.dict_body = {"abc": "hello", "name": "你好", "go": True}
        self.options = {"timeout": 20}

    def testUrl(self):
        resp = self.curl.do_req(Request(self.test_http_url + "?name=你好").prepare())
        self.assertTrue(resp is not None, "response is None")
        self.assertTrue(resp.status_code == 200, "response status code is not 200")

    def testHTTP11Get(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "GET", self.test_http_url, self.dict_body, **self.options)

    def testHTTP11PUT(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "PUT", self.test_http_url, self.dict_body, **self.options)

    def testHTTP11POST(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "POST", self.test_http_url, self.dict_body, **self.options)

    def testHTTP11OPTIONS(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "OPTIONS", self.test_http_url, self.dict_body, **self.options)

    def testHTTP11Delete(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "DELETE", self.test_http_url, self.dict_body, **self.options)

    def testHTTP11HEAD(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "HEAD", self.test_http_url, self.dict_body, **self.options)

    def testHTTP11PATCH(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "PATCH", self.test_http_url, self.dict_body, **self.options)

    def testHTTPS11(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        test_request(self, self.curl, "GET", self.test_https_url, self.dict_body, **self.options)
        test_request(self, self.curl, "POST", self.test_https_url, self.dict_body, **self.options)

    def testHTTP2(self):
        if not hasattr(pycurl, "CURL_HTTP_VERSION_2"):
            return
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2)
        test_request(self, self.curl, "GET", self.test_https_url, self.dict_body, **self.options)
        test_request(self, self.curl, "POST", self.test_https_url, self.dict_body, **self.options)

    def testHTTP3(self):
        if not hasattr(pycurl, "CURL_HTTP_VERSION_3"):
            return
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_3)
        test_request(self, self.curl, "GET", self.test_https_url, self.dict_body, **self.options)
        test_request(self, self.curl, "POST", self.test_https_url, self.dict_body, **self.options)


if __name__ == '__main__':
    unittest.main()
