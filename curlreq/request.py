"""
http request
"""

try:
    import idna as IDNA
except ModuleNotFoundError:
    IDNA = None
import json as complexjson
from base64 import b64encode
from io import UnsupportedOperation
from typing import Mapping
from urllib.parse import quote, urlunparse

from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

from .compat import (to_native_string, unicode_is_ascii, encode_params,
                     basestring, BuiltinString, encode_files)
from .exceptions import InvalidURL, MissingSchema, InvalidJSONError, UnsupportedCookiesType
from .utils import re_quote_uri, check_header_validity, super_len, get_auth_from_url


def _basic_auth_str(username, password):
    """Returns a Basic Auth string."""

    # "I want us to put a big-ol' comment on top of it that
    # says that this behaviour is dumb but we need to preserve
    # it because people are relying on it."
    #    - Lukasa
    #
    # These are here solely to maintain backwards compatibility
    # for things like ints. This will be removed in 3.0.0.
    if not isinstance(username, basestring):
        username = str(username)

    if not isinstance(password, basestring):
        password = str(password)
    # -- End Removal --

    if isinstance(username, str):
        username = username.encode("latin1")

    if isinstance(password, str):
        password = password.encode("latin1")

    authstr = "Basic " + to_native_string(
        b64encode(b":".join((username, password))).strip()
    )

    return authstr


class AuthBase:
    """Base class that all auth implementations derive from"""

    def __call__(self, req):
        raise NotImplementedError("Auth hooks must be callable.")


class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __eq__(self, other):
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers["Authorization"] = _basic_auth_str(self.username, self.password)
        return r


class PreparedRequest:
    """The fully mutable :class:`PreparedRequest <PreparedRequest>` object,
    containing the exact bytes that will be sent to the server.

    Instances are generated from a :class:`Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    Usage::

      >>> import curlreq
      >>> req = curlreq.Request('https://httpbin.org/get')
      >>> r = req.prepare()
      >>> r
      <PreparedRequest [GET]>

      >>> curl = curlreq.Curl()
      >>> curl.do_req(r)
      <Response [200]>
    """

    def __init__(self):
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = None
        #: request body to send to the server.
        self.body = None
        #: integer denoting starting position of a readable file-like body.
        self._body_position = None

    # pylint: disable=too-many-arguments
    def prepare(
            self,
            method=None,
            url=None,
            headers=None,
            files=None,
            data=None,
            params=None,
            auth=None,
            cookies=None,
            json=None,
    ):
        """Prepares the entire request with the given parameters."""

        self.prepare_method(method)
        self.prepare_url(url, params)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, files, json)
        # Note that prepare_auth must be last to enable authentication schemes
        # such as OAuth to work on a fully prepared request.
        self.prepare_auth(auth, url)

    def __repr__(self):
        return f"<PreparedRequest [{self.method}]>"

    def copy(self):
        """copy object"""
        preq = PreparedRequest()
        preq.method = self.method
        preq.url = self.url
        preq.headers = self.headers.copy() if self.headers is not None else None
        preq.body = self.body
        # pylint: disable=protected-access
        preq._body_position = self._body_position
        return preq

    def prepare_method(self, method):
        """Prepares the given HTTP method."""
        self.method = method
        if self.method is not None:
            self.method = to_native_string(self.method.upper())

    def prepare_url(self, url, params):
        """Prepares the given HTTP URL."""
        #: Accept objects that have string representations.
        #: We're unable to blindly call unicode/str functions
        #: as this will include the bytestring indicator (b'')
        #: on python 3.x.
        #: https://github.com/psf/requests/pull/2238
        if isinstance(url, bytes):
            url = url.decode("utf8")
        else:
            url = str(url)

        # Remove leading whitespaces from url
        url = url.lstrip()

        # Don't do any URL preparation for non-HTTP schemes like `mailto`,
        # `data` etc to work around exceptions from `url_parse`, which
        # handles RFC 3986 only.
        if ":" in url and not url.lower().startswith("http"):
            self.url = url
            return

        # Support for unicode domain names and paths.
        scheme, auth, host, port, path, query, fragment = _parse_and_check_url(url)

        # Carefully reconstruct the network location
        netloc = (f"{auth}@" or "") + host + (f":{port}" if port else "")

        # Bare domains aren't valid URLs.
        if not path:
            path = "/"

        if isinstance(params, (str, bytes)):
            params = to_native_string(params)

        enc_params = encode_params(params)
        if enc_params:
            query = f"{query}&{enc_params}" if query else enc_params

        url = re_quote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
        self.url = url

    def prepare_headers(self, headers):
        """Prepares the given HTTP headers."""

        self.headers = {}
        if headers:
            for header in headers.items():
                # Raise exception on invalid header value.
                check_header_validity(header)
                name, value = header
                self.headers[to_native_string(name)] = value

    def _prepare_stream_body(self, data):
        """
        prepare stream body
        """
        try:
            length = super_len(data)
        except (TypeError, AttributeError, UnsupportedOperation):
            length = None

        body = data

        if getattr(body, "tell", None) is not None:
            # Record the current file position before reading.
            # This will allow us to rewind a file in the event
            # of a redirect.
            try:
                self._body_position = body.tell()
            except OSError:
                # This differentiates from None, allowing us to catch
                # a failed `tell()` later when trying to rewind the body
                self._body_position = object()

        if length:
            self.headers["Content-Length"] = BuiltinString(length)
        else:
            self.headers["Transfer-Encoding"] = "chunked"
        self.body = body

    def _prepare_json_body(self, json):
        # urllib3 requires a bytes-like body. Python 2's json.dumps
        # provides this natively, but Python 3 gives a Unicode string.

        try:
            body = complexjson.dumps(json, allow_nan=False)
        except ValueError as exc:
            raise InvalidJSONError(exc, request=self) from exc

        if not isinstance(body, bytes):
            self.body = body.encode("utf-8")
        self.headers['Content-Type'] = "application/json"
        self.body = body

    def prepare_body(self, data, files, json=None):
        """Prepares the given HTTP body data."""

        # Check if files, fo, generator, iterator.
        # If not, run through normal process.

        if not data and json is not None:
            self._prepare_json_body(json)
            return

        is_stream = all(
            [
                hasattr(data, "__iter__"),
                not isinstance(data, (basestring, list, tuple, Mapping)),
            ]
        )
        if is_stream and files:
            raise NotImplementedError(
                "Streamed bodies and files are mutually exclusive."
            )
        if is_stream:
            self._prepare_stream_body(data)
            return
        self._prepare_multi_part(data, files)
        return

    def _prepare_multi_part(self, data, files):
        """
        prepare body from files
        """
        content_type, body = None, None
        # Multi-part file uploads.
        if files:
            (body, content_type) = encode_files(files, data)
        else:
            if data:
                body = encode_params(data)
                if isinstance(body, str):
                    body = body.encode('utf-8')
                if isinstance(data, basestring) or hasattr(data, "read"):
                    content_type = None
                else:
                    content_type = "application/x-www-form-urlencoded"

        self.prepare_content_length(body)

        # Add content-type if it wasn't explicitly provided.
        if content_type and ("Content-Type" not in self.headers):
            self.headers["Content-Type"] = content_type
        self.body = body

    def prepare_content_length(self, body):
        """Prepare Content-Length header based on request method and body"""
        if body is not None:
            length = super_len(body)
            if length:
                # If length exists, set it. Otherwise, we fallback
                # to Transfer-Encoding: chunked.
                self.headers["Content-Length"] = BuiltinString(length)
        elif (
                self.method not in ("GET", "HEAD")
                and self.headers.get("Content-Length") is None
        ):
            # Set Content-Length to 0 for methods that can have a body
            # but don't provide one. (i.e. not GET or HEAD)
            self.headers["Content-Length"] = "0"

    def prepare_auth(self, auth, url=""):
        # pylint: disable=fixme
        # TODO: is url really needed?
        """Prepares the given HTTP auth data."""

        # If no Auth is explicitly provided, extract it from the URL first.
        if auth is None:
            url_auth = get_auth_from_url(url or self.url)
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                # special-case basic HTTP auth
                auth = HTTPBasicAuth(*auth)

            # Allow auth to make its changes.
            res = auth(self)

            # Update self to reflect the auth changes.
            self.__dict__.update(res.__dict__)

            # Recompute Content-Length
            self.prepare_content_length(self.body)

    def prepare_cookies(self, cookies):
        """put cookies into headers, the old will be replaced"""
        if cookies is None:
            return
        if isinstance(cookies, dict):
            # TODO: quote value?
            cookie_str = "; ".join(f"{key}={quote(val)}" for key, val in cookies.items())
        elif isinstance(cookies, str):
            cookie_str = cookies
        elif isinstance(cookies, list):
            cookie_str = "; ".join(f"{key}={quote(val)}" for key, val in cookies)
        else:
            raise UnsupportedCookiesType(f"cookies type {type(cookies)} not "
                                         f"supported, either dict, string or list")
        self.headers['Cookie'] = cookie_str


# pylint: disable=too-many-instance-attributes
class Request:
    """
    HTTP request class
    """

    def __init__(self, url: str, method: str = "GET", **kwargs):
        """

        :param url: request url
        :param method: request method, default GET
        :param headers: request headers
        :param cookies: cookies
        :param auth: http auth
        :param data: auth
        :param json: json body
        :param params: query parameters
        :param files: post files
        """
        self.url = url
        self.method = "GET" if method is None else method.upper()
        self.headers = kwargs.get("headers")
        self.cookies = kwargs.get("cookies")
        self.auth = kwargs.get("auth")
        self.data = kwargs.get("data")
        self.json = kwargs.get("json")
        self.params = kwargs.get("params")
        self.files = kwargs.get("files")

    def prepare(self) -> PreparedRequest:
        "create PreparedRequest from Request obj"
        preq = PreparedRequest()
        preq.prepare(
            self.method,
            self.url,
            self.headers,
            self.files,
            self.data,
            self.params,
            self.auth,
            self.cookies,
            self.json
        )
        return preq


def _get_idna_encoded_host(host):
    """

    """
    # pylint: disable=fixme
    # TODO: is this ok?
    if IDNA is None:
        return host
    try:
        host = IDNA.encode(host, uts46=True).decode("utf-8")
    except IDNA.IDNAError as exc:
        raise UnicodeError(exc) from exc
    return host


def _parse_and_check_url(url):
    """
    parse and check if url is valid
    """
    try:
        scheme, auth, host, port, path, query, fragment = parse_url(url)
    except LocationParseError as e:
        raise InvalidURL(*e.args) from e

    if not scheme:
        raise MissingSchema(
            f"Invalid URL {url!r}: No scheme supplied. "
            f"Perhaps you meant https://{url}?"
        )

    if not host:
        raise InvalidURL(f"Invalid URL {url!r}: No host supplied")

    # In general, we want to try IDNA encoding the hostname if the string contains
    # non-ASCII characters. This allows users to automatically get the correct IDNA
    # behaviour. For strings containing only ASCII characters, we need to also verify
    # it doesn't start with a wildcard (*), before allowing the unencoded hostname.
    if not unicode_is_ascii(host):
        try:
            host = _get_idna_encoded_host(host)
        except UnicodeError as e:
            raise InvalidURL("URL has an invalid label.") from e
    elif host.startswith(("*", ".")):
        raise InvalidURL("URL has an invalid label.")
    return scheme, auth, host, port, path, query, fragment
