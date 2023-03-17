import unittest
from copy import deepcopy

import pycurl
from proxy import proxy

from curlreq import Curl, Request, version
from test_utils import test_request, check_dict


def checkSupportOption(curl: Curl, option: int, value):
    try:
        curl.setopt(option, value)
    except (TypeError, pycurl.error) as err:
        return not (len(err.args) and (
                err.args[0] == 'invalid arguments to setopt' or
                err.args[0] == 1 and err.args[1] == ''
        ))
    return True


def checkCurlSupportVersion(curl: Curl, name: str):
    return hasattr(pycurl, name) and \
           checkSupportOption(curl, pycurl.HTTP_VERSION, getattr(pycurl, name))


def testWithProxy(self, options, version_int):
    self.curl.setopt(pycurl.HTTP_VERSION, version_int)
    test_request(self, self.curl, "GET", self.test_https_url, self.dict_body, **options)
    test_request(self, self.curl, "POST", self.test_https_url, self.dict_body, **options)


class CurlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.curl = Curl()
        self.test_http_url = "http://httpbin.org/anything"
        self.test_https_url = "https://httpbin.org/anything"
        self.user_agent = version()
        self.have_body = ["PUT", "PATCH", "POST", "DELETE"]
        self.dict_body = {"abc": "hello", "name": "你好", "go": True}
        self.options = {"timeout": 30}

    def testVersion(self):
        versions = {
            "http1.0": "CURL_HTTP_VERSION_1_0",
            "http1.1": "CURL_HTTP_VERSION_1_1",
            "http2": "CURL_HTTP_VERSION_2",
            "http3": "CURL_HTTP_VERSION_3",
        }
        supported_versions = Curl.get_supported_http_versions()
        for name, value in versions.items():
            expected = checkCurlSupportVersion(self.curl, value)
            res = name in supported_versions
            self.assertEqual(
                res, expected,
                f"pycurl.version: {pycurl.version}, "
                f"HTTP supported version checking failed for {name},"
                f" expected {expected} but got {res}"
            )

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
        if "http2" not in Curl.get_supported_http_versions():
            return
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2)
        test_request(self, self.curl, "GET", self.test_https_url, self.dict_body, **self.options)
        test_request(self, self.curl, "POST", self.test_https_url, self.dict_body, **self.options)

    def testHTTP3(self):
        if not Curl.support_http3():
            return
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_3)
        test_request(self, self.curl, "GET", self.test_https_url, self.dict_body, **self.options)
        test_request(self, self.curl, "POST", self.test_https_url, self.dict_body, **self.options)

    def testProxy(self):
        options = deepcopy(self.options)
        options["proxies"] = {"https": "http://localhost:8899"}
        with proxy.Proxy(["--log-level=CRITICAL", "--threadless"]):
            testWithProxy(self, options, pycurl.CURL_HTTP_VERSION_1_1)
            if "http2" in Curl.get_supported_http_versions():
                testWithProxy(self, options, pycurl.CURL_HTTP_VERSION_2)
            if "http3" in Curl.get_supported_http_versions():
                testWithProxy(self, options, pycurl.CURL_HTTP_VERSION_3)

    def testPostFormat(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        resp = test_request(self, self.curl, "POST", self.test_https_url, None, json=self.dict_body)
        self.assertTrue(resp.json["json"] and len(resp.json['json']) == len(self.dict_body),
                        f"json body not setting right: {str(resp.json['json'])}")

    def testHeaders(self):
        self.curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        headers = {"Acek": "jjsp", "Doit": "yes"}
        resp = test_request(self, self.curl, "GET", self.test_https_url, None, headers=headers)
        self.assertTrue(resp.json["headers"] and check_dict(headers, resp.json["headers"]),
                        f"json body not setting right: {str(resp.json['headers'])}")


if __name__ == '__main__':
    unittest.main()
