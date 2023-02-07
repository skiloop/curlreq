#
# http response class
#
import json
import re
from json import JSONDecodeError
from typing import Optional

from .request import Request


class Response:
    """
    HTTP response class
    """

    def __init__(self, request: Request = None):
        self.url = ""
        self.status_code = None
        self.content = None
        self._text = None
        self._json = None
        self._headers = None
        self.request = request
        self.hdr = ""
        self.encoding = ""

    @property
    def text(self) -> str:
        """text """
        if self._text is None:
            self._text = self._decode_content()
        return self._text

    def parse_encoding(self):
        if re.search(r'Content-Type:.*charset=utf-8', self.hdr, re.M | re.I):
            self.encoding = 'utf-8'
        elif re.search(r'Content-Type.*(gbk|gb2312)', self.hdr, re.M | re.I):
            self.encoding = 'gb18030'
        else:
            self.encoding = 'utf-8'

    def _decode_content(self) -> str:
        "decode content"
        if self.content is None:
            return ''
        return self.content.decode(self.encoding, "replace")

    @property
    def json(self) -> Optional[dict]:
        """
        take content text as dict
        :return: None if text is not json encoding otherwise dict from parse text
        """
        if self._json is None:
            if self.text == "":
                return None
            try:
                self._json = json.loads(self.text)
            except (ValueError, JSONDecodeError):
                self._json = None
        return self._json
