import unittest
from copy import deepcopy

from proxy import Proxy

from curlreq import Client, get_supported_http_versions
from test_utils import test_request_with_client


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cli = Client()
        self.test_http_url = "http://httpbin.org/anything"
        self.test_https_url = "https://httpbin.org/anything"
        self.have_body = ["PUT", "PATCH", "POST", "DELETE"]
        self.dict_body = {"abc": "hello", "name": "你好", "go": True}
        self.options = {"timeout": 30}

    def testClient(self):
        kwargs = deepcopy(self.options)
        kwargs["json"] = self.dict_body
        test_request_with_client(self, self.cli, "POST", self.test_https_url, **kwargs)

    def testProxy(self):
        with Proxy(["--log-level=CRITICAL", "--threadless"]):
            kwargs = deepcopy(self.options)
            kwargs["proxies"] = "http://localhost:8899"
            test_request_with_client(self, self.cli, "GET", self.test_https_url, **kwargs)

    def testHTTPVersion(self):
        for ver in get_supported_http_versions():
            cli = Client(http_version=ver)
            test_request_with_client(self, cli, "GET", self.test_https_url, **self.options)


if __name__ == '__main__':
    unittest.main()
