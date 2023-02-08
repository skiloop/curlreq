#
# Curl class
#

import abc
from io import BytesIO, StringIO
from typing import Optional

import pycurl

from .exceptions import InvalidMethod
from .request import PreparedRequest
from .response import Response
from .version import version


class Curl(pycurl.Curl):
    """
    :class: `pycurl.Curl <Curl>` Wrapper
    """
    METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

    def __init__(self, after_reset: callable = None):
        super().__init__()
        self.resp = None
        self._buffer = BytesIO()
        self._after_reset = after_reset

    def set_option(self, *args):
        """set curl option"""
        self.setopt(*args)

    def reset(self):
        """reset state"""
        super().reset()
        self.resp = Response()

        def header_callback(data):
            self.resp.hdr += data.decode("ascii")

        self.setopt(pycurl.VERBOSE, 0)
        self.setopt(pycurl.HEADERFUNCTION, header_callback)
        self.setopt(pycurl.FOLLOWLOCATION, 1)
        self.setopt(pycurl.CONNECTTIMEOUT, 10)
        self.setopt(pycurl.TIMEOUT, 10)
        self.setopt(pycurl.MAXREDIRS, 7)
        self.setopt(pycurl.NOSIGNAL, 1)
        self.setopt(pycurl.ENCODING, "gzip, deflate")
        self.setopt(pycurl.SSL_VERIFYPEER, 0)
        self.setopt(pycurl.SSL_VERIFYHOST, 0)
        self.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
        if self._after_reset is not None:
            self._after_reset(self)
        self._buffer.seek(0)
        self._buffer.truncate()
        self.setopt(pycurl.WRITEDATA, self._buffer)

    def do_req(self, request: PreparedRequest, **kwargs) -> Optional[Response]:
        """
        send request and fetch response
        :param request: :class: `curlreq.PreparedRequest <PreparedRequest>` http request
        :param proxies: (Optional) Proxies to use.
        :type proxies: dict, in format of {"http":"http://localhost:8080",
                            "https":"http://localhost:8080"}
        :param timeout: (Optional) Request timeout, either float or tuple,
                        if tuple, connection timeout and read timeout are separately specified,
                        if float, the two are the same. Defaults: use the default setting of libcurl
        :param allow_redirects: (Optional) indicate that whether to follow redirection.
                        True to follow redirection otherwise False. Defaults: False
        :return: :class: `curlreq.Response <Response>` object or None
        """
        self.reset()
        self._prepare_kwargs(request.url, **kwargs)
        self._apply_request(request)
        self.perform()
        return self._build_resp()

    def _setup_proxy(self, url, proxies: dict):
        scheme = url.split("://", 1)[0]
        proxy = proxies.get(scheme)
        if proxy:
            self.setopt(pycurl.PROXY, proxy)
            return

    def _prepare_kwargs(self, url, **kwargs):
        """
        prepare parameters those are not in PreparedRequest
        :param url: request url
        :param proxies: (Optional) Proxies to use,
                like {"http":"http://localhost:8080","https":"http://localhost:8080"}
        :type proxies: dict
        :param timeout: (Optional) Request timeout, either float or tuple,
                        if tuple, connection timeout and read timeout are seperately specified,
                        if float, the two are the same. Defaults: use the default setting of libcurl
        :param allow_redirects: (Optional) indicate that whether to follow redirection.
                        True to follow redirection otherwise False. Defaults: False
        :return:
        """
        timeout = kwargs.get("timeout")
        if timeout is not None:
            if isinstance(timeout, tuple):
                connect, read = timeout
            else:
                connect = read = timeout
            self.setopt(pycurl.CONNECTTIMEOUT, connect)
            self.setopt(pycurl.TIMEOUT, read)
        allow_redirects = kwargs.get("allow_redirects")
        if allow_redirects is not None and not allow_redirects:
            self.setopt(pycurl.FOLLOWLOCATION, 0)
        proxies = kwargs.get("proxies")
        if proxies:
            self._setup_proxy(url, proxies)

    def _apply_method(self, method: Optional[str], has_body: bool):
        if method not in self.METHODS:
            raise InvalidMethod(f"invalid HTTP method {method}")
        if method == "GET":
            self.setopt(pycurl.HTTPGET, 1)
        elif method == "POST":
            self.setopt(pycurl.POST, 1)
        elif method == "PUT":
            self.setopt(pycurl.PUT, 1)
        elif method == "HEAD":
            # HEAD method, control by NOBODY=1
            self.setopt(pycurl.NOBODY, 1)
        else:
            self.setopt(pycurl.UPLOAD, has_body)
            self.setopt(pycurl.CUSTOMREQUEST, method)

    def _apply_request(self, request: PreparedRequest):
        # method = "GET" if request.method not in self.METHODS else request.method
        # self.setopt(pycurl.CUSTOMREQUEST, method)
        self.setopt(pycurl.URL, request.url)
        self._apply_method(request.method, request.body is not None)
        self._prepare_headers(request.headers)
        # prepare body
        if request.body:
            content = request.body.decode('utf-8')
            reader = StringIO(content)
            self.setopt(pycurl.READFUNCTION, reader.read)
            self.setopt(pycurl.INFILESIZE, len(content))
        self.resp.request = request

    def _prepare_headers(self, headers):
        "prepare headers"
        if headers is None:
            headers = {}
        if 'User-Agent' not in headers and 'user-agent' not in headers:
            headers['User-Agent'] = version()
        self.setopt(pycurl.HTTPHEADER, list(f"{key}: {val}" for key, val in headers.items()))

    def _build_resp(self):
        self.resp.status_code = self.getinfo(pycurl.HTTP_CODE)
        self.resp.url = self.getinfo(pycurl.EFFECTIVE_URL)
        self.resp.cookies = self.getinfo(pycurl.INFO_COOKIELIST)
        self.resp.content = self._buffer.getvalue()
        self.resp.parse_encoding()
        return self.resp


class CurlOption:
    """
    abstract curl option
    """

    @abc.abstractmethod
    def apply(self, curl: Curl):
        raise NotImplementedError('virtual function called')


class SSLOptions(CurlOption):
    """
    SSL options for CurlReq
    """

    def __init__(self):
        self.ciphers = ""
        self.ssl_version = pycurl.SSLVERSION_MAX_TLSv1_3
        self.ssl_ec_curves = ""
        self.enable_alpn = True

    def apply(self, curl: Curl):
        curl.set_option(pycurl.SSLVERSION, self.ssl_version)
        curl.set_option(pycurl.SSL_ENABLE_ALPN, self.enable_alpn)
        if self.ssl_ec_curves != "" and hasattr(pycurl, "SSL_EC_CURVES"):
            curl.set_option(pycurl.SSL_EC_CURVES, self.ssl_ec_curves)
        if self.ciphers != "":
            curl.set_option(pycurl.SSL_CIPHER_LIST, self.ciphers)
