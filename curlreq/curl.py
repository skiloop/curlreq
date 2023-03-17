#
# Curl class
#

import abc
import re
import warnings
from io import BytesIO, StringIO
from typing import Optional

import pycurl

from .exceptions import InvalidMethod, UnsupportedFeatures
from .request import PreparedRequest
from .response import Response
from .version import version

_HTTP_VERSION = {
    "http1.0": pycurl.CURL_HTTP_VERSION_1_0,
    "http1.1": pycurl.CURL_HTTP_VERSION_1_1,
}


def _curl_support_http2():
    """check if curl support HTTP2"""
    return re.search(r'nghttp2/\d+\.\d+\.\d+', pycurl.version) is not None


def _curl_support_http3():
    """check if curl support HTTP3"""
    return re.search(r'nghttp3|quiche|msh3', pycurl.version) is not None


def _init_():
    if _curl_support_http2():
        _HTTP_VERSION["http2"] = pycurl.CURL_HTTP_VERSION_2
    if _curl_support_http3():
        _HTTP_VERSION["http3"] = pycurl.CURL_HTTP_VERSION_3


_init_()


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

    def set_http_version(self, http_version: Optional[str]):
        """
        set http version, if version not supported, HTTP1.1 will be used instead
        :param http_version: HTTP version, options are "http1.0",
            "http1.1", "http2", "http3"
        :return:
        """
        if http_version is None:
            http_version = "http1.1"
        http_version = http_version.strip().lower()
        ver_num = _HTTP_VERSION.get(http_version)
        if ver_num is None:
            ver_num = pycurl.CURL_HTTP_VERSION_1_1
            warnings.warn(
                f'the version of libcurl does not support {http_version}, '
                f'HTTP 1.1 will be used instead',
            )
        self.setopt(pycurl.HTTP_VERSION, ver_num)

    @staticmethod
    def support_http3():
        """check if curl support HTTP3"""
        return _curl_support_http3()

    @staticmethod
    def check_if_support_http_version(ver: str):
        """check if version is supported"""
        return ver in _HTTP_VERSION

    @staticmethod
    def get_supported_http_versions():
        """get supported version"""
        return list(_HTTP_VERSION.keys())


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


class JA3Option(CurlOption):
    """enable CurlReq To modify JA3 fingerprinting"""

    def __init__(self, **kwargs):
        self.ciphers = kwargs.get("ciphers", "")
        self.alpn = 0 if not kwargs.get("alpn") else 1
        self.alps = 0 if not kwargs.get("alps") else 1
        self.grease = 0 if not kwargs.get("grease") else 1
        self.ocsp_stapling = 0 if not kwargs.get("ocsp_stapling") else 1
        self.sign_cert_ts = 0 if not kwargs.get("sign_cert_ts") else 1
        self.no_session_ticket = 0 if not kwargs.get("no_session_ticket") else 1
        self.permute_extensions = 0 if not kwargs.get("permute_extensions") else 1
        self.cert_compression = kwargs.get("cert_compression")

    def apply(self, curl: Curl):
        for key in [
            "SSL_ENABLE_ALPS",
            "SSL_ENABLE_GREASE",
            "SSL_OCSP_STAPLING",
            "SSL_PERMUTE_EXTENSIONS",
            "SSL_NO_SESS_TICKET",
            "SSL_SIG_CERT_TS",
            "SSL_CERT_COMPRESSION"
        ]:
            if not hasattr(pycurl, key):
                raise UnsupportedFeatures("CURL do not support to modify JA3 fingerprint")
        curl.set_option(curl.SSL_ENABLE_ALPN, self.alpn)
        curl.set_option(curl.SSL_ENABLE_ALPS, self.alps)
        curl.set_option(curl.SSL_ENABLE_GREASE, self.grease)
        curl.set_option(curl.SSL_OCSP_STAPLING, self.ocsp_stapling)
        curl.set_option(curl.SSL_SIG_CERT_TS, self.sign_cert_ts)
        curl.set_option(curl.SSL_PERMUTE_EXTENSIONS, self.permute_extensions)
        curl.set_option(curl.SSL_NO_SESS_TICKET, self.no_session_ticket)
        if self.cert_compression:
            curl.set_option(curl.SSL_CERT_COMPRESSION, "brotli")
        if self.ciphers:
            curl.set_option(curl.SSL_CIPHER_LIST, self.ciphers)


class HTTP2FPOption(CurlOption):
    """enable CurlReq To modify HTTP2 fingerprinting"""

    def __init__(self, h2fp: str):
        """

        :param h2fp: http2 fingerprinting in format of
        [SETTINGS]|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order|HEADERS_FRAME|WINDOW_UPDATE
        for example
        "1:189924,2:0,3:13412,4:65535,6:262144|12263105|0|m,p,s,a"
        """
        self.h2fp = h2fp

    def apply(self, curl: Curl):
        if not hasattr(pycurl, "HTTP2_FINGERPRINT"):
            raise UnsupportedFeatures("CURL does NOT support to modify HTTP2 fingerprint")
        curl.set_option(curl.HTTP2_FINGERPRINT, self.h2fp)
