"""
HTTP client
"""
import abc
from io import BytesIO, StringIO
from typing import Optional, List, Union
from urllib.parse import urlparse

import pycurl

from .exceptions import InvalidMethod

__HTTP_VERSION = {
    "http1.1": pycurl.CURL_HTTP_VERSION_1_1,
}
for name, val in [("http2", "CURL_HTTP_VERSION_2"), ("http3", "CURL_HTTP_VERSION_3")]:
    if hasattr(pycurl, val) and name not in __HTTP_VERSION:
        __HTTP_VERSION[name] = getattr(pycurl, val)
from .request import Request, PreparedRequest
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


class Client:
    """
    HTTP client
    """

    def __init__(self, **kwargs):
        """
        create new client object
        :param http_version: (optional) HTTP protocol version to use.
            Options: "http1.1", "http2", "http3". Defaults: "http1.1"
        :type http_version: str
        :param verify: (optional) Either a boolean, in which case it controls whether we verify
                the server's TLS certificate, or a string, in which case it must be a path
                to a CA bundle to use. Defaults to ``True``.
        :param cert: (optional) if String, path to ssl client cert file (.pem).
                    If Tuple, ('cert', 'key') pair.
        :param cookie_share: (optional) bool or curl cookie share object to enable cookie reuse,
                    if is true or a curl share object then enable cookie reuse
        """
        self.curl = Curl(self._after_reset)
        self._user_agent = kwargs.get("user_agent", version())
        self._cookie_share = None
        self._set_http_version(kwargs.get("http_version"))
        self._set_cert(kwargs.get('cert'))
        self._set_ssl_verify(kwargs.get('verify'))
        self._set_cookie_share(kwargs.get('cookie_share'))

    def _after_reset(self, curl: Curl):
        pass

    def _set_cookie_share(self, cookie_share):
        if cookie_share is None or not cookie_share:
            return
        if isinstance(cookie_share, pycurl.CurlShare):
            self._cookie_share = cookie_share
            return
        self._cookie_share = pycurl.CurlShare()
        self._cookie_share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_DNS)
        self._cookie_share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_COOKIE)

    def _set_http_version(self, http_version: Optional[str]):
        if http_version is None:
            http_version = "http1.1"
        http_version = http_version.strip().lower()
        ver_num = __HTTP_VERSION.get(http_version, pycurl.CURL_HTTP_VERSION_1_1)
        self.curl.set_option(pycurl.HTTP_VERSION, ver_num)

    def _set_cert(self, cert):
        if cert is None:
            return
        # TODO: apply cert

    def _set_ssl_verify(self, verify):
        if verify is None:
            return
        if isinstance(verify, bool):
            self.curl.set_option(pycurl.SSL_VERIFYPEER, verify)
            self.curl.set_option(pycurl.SSL_VERIFYHOST, verify)
        # TODO: apply when verify is string for ca bundle

    def set_curl_options(self, options: List[CurlOption]):
        """
        apply additional curl option
        :param options: list of CurlOption
        :return: None
        """
        for opt in options:
            opt.apply(self.curl)

    def request(self, method, url, **kwargs) -> Optional[Response]:
        """Constructs and sends a :class:`Request <Request>`.

        :param method: method for the new :class:`Request` object: ``GET``,
                        ``OPTIONS``, ``HEAD``, ``POST``, ``PUT``, ``PATCH``, or ``DELETE``.
        :param url: URL for the new :class:`Request` object.
        :param params: (optional) Dictionary, list of tuples or bytes to send
            in the query string for the :class:`Request`.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
        :param cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
        :param files: (optional) Dictionary of ``'name': file-like-objects`` (or ``{'name': file-tuple}``) for
                multipart encoding upload. ``file-tuple`` can be a 2-tuple ``('filename', fileobj)``,
                3-tuple ``('filename', fileobj, 'content_type')`` or a 4-tuple ``('filename', fileobj,
                'content_type', custom_headers)``, where ``'content-type'`` is a string
                defining the content type of the given file and ``custom_headers`` a dict-like object
                containing additional headers to add for the file.
        :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) How many seconds to wait for the server to send data
            before giving up, as a float, or a :ref:`(connect timeout, read
            timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param allow_redirects: (optional) Boolean. Enable/disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD
                                redirection. Defaults to ``True``.
        :type allow_redirects: bool
        :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
        :param verify: (optional) Either a boolean, in which case it controls whether we verify
                the server's TLS certificate, or a string, in which case it must be a path
                to a CA bundle to use. Defaults to ``True``.
        :param stream: (optional) if ``False``, the response content will be immediately downloaded.
        :param cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.
        :return: :class:`Response <Response>` object
        :rtype: curlreq.Response

        """
        memo = {}
        for key in ["params", "data", "json", "files", "headers", "cookies", "auth"]:
            memo[key] = kwargs.pop(key, None)
        req = Request(url, method, **memo)
        kwargs["proxies"] = self.prepare_proxies(kwargs.get('proxies'))
        return self.curl.do_req(req.prepare(), **kwargs)

    @staticmethod
    def prepare_proxies(proxies: Union[str, dict, None]) -> Optional[dict]:
        """set proxies"""
        if isinstance(proxies, str):
            proxy_url = urlparse(proxies).geturl()
            proxies = {
                "http": proxy_url, "https": proxy_url
            }
        return proxies
