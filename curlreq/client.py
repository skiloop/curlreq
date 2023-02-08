"""
HTTP client
"""

from typing import Optional, List, Union
from urllib.parse import urlparse

import pycurl

from .curl import Curl, CurlOption
from .request import Request
from .response import Response
from .version import version

__HTTP_VERSION = {
    "http1.1": pycurl.CURL_HTTP_VERSION_1_1,
}
for name, val in [("http2", "CURL_HTTP_VERSION_2"), ("http3", "CURL_HTTP_VERSION_3")]:
    if hasattr(pycurl, val) and name not in __HTTP_VERSION:
        __HTTP_VERSION[name] = getattr(pycurl, val)


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
