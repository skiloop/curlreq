from curlreq import Curl, Request, Response, Client, PreparedRequest

METHODS_WITH_BODY = ["PUT", "PATCH", "POST", "DELETE"]


def test_with_prepared_request(case, curl: Curl, req: PreparedRequest, method, **kwargs) -> Response:
    resp = curl.do_req(req, **kwargs)
    case.assertFalse(resp is None, f"[{method}] response is None")
    if resp.status_code == 405:
        return resp
    case.assertTrue(resp.status_code in [200, 204],
                    f"[{method}] status code failed: expected: 200, but got {resp.status_code}")
    if resp.status_code == 204:
        return resp
    if method not in ["GET", "TRACE"] and method not in METHODS_WITH_BODY:
        case.assertTrue(resp.content == b"", f"[{method}] content not empty")
        return resp
    rspj = resp.json
    case.assertTrue(rspj["method"] == method,
                    f"[{method}]method failed: expected: {method} got {rspj['method']}")
    return resp


def test_request(case, curl: Curl, method, url, body, **kwargs) -> Response:
    data = body if method in METHODS_WITH_BODY else None
    req = Request(
        url,
        method,
        data=data,
        json=kwargs.pop('json', None),
        files=kwargs.pop('files', None),
        headers=kwargs.pop('headers', None),
        cookies=kwargs.pop('cookies', None),
        auth=kwargs.pop('auth', None),
        params=kwargs.pop('params', None),
    )
    return test_with_prepared_request(case, curl, req.prepare(), method, **kwargs)


def check_dict(dst: dict, src: dict) -> bool:
    for key, val in dst.items():
        if val != src.get(key):
            return False
    return True


def test_request_with_client(case, cli: Client, method, url, **kwargs) -> Response:
    """test Client with http req"""
    resp = cli.request(method, url, **kwargs)
    case.assertFalse(resp is None, f"[{method}] response is None")
    if resp.status_code == 405:
        return resp
    case.assertTrue(resp.status_code in [200, 204],
                    f"[{method}] status code failed: expected: 200, but go {resp.status_code}")
    if resp.status_code == 204:
        return resp
    if method not in ["GET", "TRACE"] and method not in METHODS_WITH_BODY:
        case.assertTrue(resp.content == b"", f"[{method}] content not empty")
        return resp
    rspj = resp.json
    case.assertTrue(rspj["method"] == method,
                    f"[{method}]method failed: expected: {method} got {rspj['method']}")
    return resp
