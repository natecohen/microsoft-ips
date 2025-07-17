"""
Adapted from URLExtract - https://github.com/lipoja/URLExtract
Originally created by Jan Lipovský <janlipovsky@gmail.com>, janlipovsky.cz
"""

import re
import string
from collections import OrderedDict
from collections.abc import Generator
from urllib.parse import ParseResult, urlparse


class URLExtract:
    # compiled regexp for naive validation of host name
    _hostname_re = re.compile(r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$")

    # common TLD pattern including "microsoft"
    _tlds_re = re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:"
        r"microsoft|"
        r"(?!(?:md|date|svg)\b)[a-zA-Z]{2,4}"
        r")\b",
        re.IGNORECASE,
    )

    # list of enclosure of URL that should be removed
    _enclosure = {
        ("(", ")"),
        ("{", "}"),
        ("[", "]"),
        ('"', '"'),
        ("\\", "\\"),
        ("'", "'"),
        ("`", "`"),
    }

    _ignore_list: set[str] = set()
    _permit_list: set[str] = set()

    def __init__(self):
        # General stop characters
        general_stop_chars = {'"', "<", ">", ";", "`"}

        # Defining default stop chars left
        self._stop_chars_left = set(string.whitespace)
        self._stop_chars_left |= general_stop_chars | {"|", "=", "]", ")", "}"}

        # Default stop characters on left side from schema
        self._stop_chars_left_from_schema = self._stop_chars_left.copy() | {":"}

        # Defining default stop chars right
        self._stop_chars_right = set(string.whitespace)
        self._stop_chars_right |= general_stop_chars

        # Characters that are allowed to be right after TLD
        self._after_tld_chars = self._get_after_tld_chars()

    def _get_after_tld_chars(self) -> set[str]:
        """Initialize after tld characters"""
        after_tld_chars = set(string.whitespace)
        after_tld_chars |= {"/", '"', "'", "<", ">", "?", ":", ".", ","}
        # Get right enclosure characters
        _, right_enclosure = zip(*self._enclosure)
        # Add right enclosure characters to be valid after TLD
        after_tld_chars |= set(right_enclosure)
        return after_tld_chars

    @property
    def ignore_list(self) -> set[str]:
        """
        Set of URLs to be ignored (not returned) while extracting from text

        :return: Returns set of ignored URLs
        :rtype: set(str)
        """
        return self._ignore_list

    @ignore_list.setter
    def ignore_list(self, ignore_list: set[str]):
        """
        Set of URLs to be ignored (not returned) while extracting from text

        :param set(str) ignore_list: set of URLs
        """
        self._ignore_list = ignore_list

    @property
    def permit_list(self):
        """
        Set of URLs that can be processed

        :return: Returns set of URLs that can be processed
        :rtype: set(str)
        """
        return self._permit_list

    @permit_list.setter
    def permit_list(self, permit_list):
        """
        Set of URLs that can be processed

        :param set(str) permit_list: set of URLs
        """
        self._permit_list = permit_list

    def get_after_tld_chars(self) -> list[str]:
        """
        Returns list of chars that are allowed after TLD

        :return: list of chars that are allowed after TLD
        :rtype: list
        """
        return list(self._after_tld_chars)

    def set_after_tld_chars(self, after_tld_chars: list[str]):
        """
        Set chars that are allowed after TLD.

        :param list after_tld_chars: list of characters
        """
        self._after_tld_chars = set(after_tld_chars)

    def get_stop_chars_left(self) -> set[str]:
        """
        Returns set of stop chars for text on left from TLD.

        :return: set of stop chars
        :rtype: set
        """
        return self._stop_chars_left

    def set_stop_chars_left(self, stop_chars: set[str]):
        """
        Set stop characters for text on left from TLD.

        :param set stop_chars: set of characters
        :raises: TypeError
        """
        if not isinstance(stop_chars, set):
            raise TypeError(f"stop_chars should be type set but {type(stop_chars)} was given")
        self._stop_chars_left = stop_chars

    def get_stop_chars_right(self) -> set[str]:
        """
        Returns set of stop chars for text on right from TLD.

        :return: set of stop chars
        :rtype: set
        """
        return self._stop_chars_right

    def set_stop_chars_right(self, stop_chars: set[str]):
        """
        Set stop characters for text on right from TLD.

        :param set stop_chars: set of characters
        :raises: TypeError
        """
        if not isinstance(stop_chars, set):
            raise TypeError(f"stop_chars should be type set but {type(stop_chars)} was given")
        self._stop_chars_right = stop_chars

    def get_enclosures(self) -> set[tuple[str, str]]:
        """
        Returns set of enclosure pairs that might be used to enclosure URL.

        :return: set of tuple of enclosure characters
        :rtype: set(tuple(str,str))
        """
        return self._enclosure

    def add_enclosure(self, left_char: str, right_char: str):
        """
        Add new enclosure pair of characters.

        :param str left_char: left character of enclosure pair
        :param str right_char: right character of enclosure pair
        """
        assert len(left_char) == 1, "Parameter left_char must be character not string"
        assert len(right_char) == 1, "Parameter right_char must be character not string"
        self._enclosure.add((left_char, right_char))
        self._after_tld_chars = self._get_after_tld_chars()

    def remove_enclosure(self, left_char: str, right_char: str):
        """
        Remove enclosure pair from set of enclosures.

        :param str left_char: left character of enclosure pair
        :param str right_char: right character of enclosure pair
        """
        assert len(left_char) == 1, "Parameter left_char must be character not string"
        assert len(right_char) == 1, "Parameter right_char must be character not string"
        rm_enclosure = (left_char, right_char)
        if rm_enclosure in self._enclosure:
            self._enclosure.remove(rm_enclosure)
        self._after_tld_chars = self._get_after_tld_chars()

    @staticmethod
    def _parse_url(url: str) -> ParseResult:
        """
        :param str url: URL to parse
        :return: ParseResult object
        """
        if "://" not in url:
            url = "http://" + url
        return urlparse(url)

    def _complete_url(self, text: str, match_pos: int, match_text: str, with_schema_only=False) -> str:
        """
        Expand string in both sides to match whole URL.

        :param str text: text where we want to find URL
        :param int match_pos: position of matched URL pattern
        :param str match_text: matched URL text
        :param bool with_schema_only: get domains with schema only
        :return: returns URL
        :rtype: str
        """
        left_ok = True
        right_ok = True

        # Hack to fix Markdown link match
        possible_markdown = False
        right_enclosure_pos = None

        max_len = len(text) - 1
        end_pos = match_pos + len(match_text) - 1
        start_pos = match_pos
        in_scheme = False

        while left_ok or right_ok:
            if left_ok:
                if start_pos <= 0:
                    left_ok = False
                else:
                    # For Markdown link detection
                    if text[start_pos] == "(" and text[start_pos - 1] == "]":
                        possible_markdown = True
                    if in_scheme and text[start_pos - 1] in self._stop_chars_left_from_schema:
                        left_ok = False
                    if (
                        left_ok
                        and text[start_pos - 1] not in self._stop_chars_left
                        and ord(text[start_pos - 1]) <= 127  # ASCII only
                    ):
                        start_pos -= 1
                    else:
                        left_ok = False

            if right_ok:
                if end_pos >= max_len:
                    right_ok = False
                elif text[end_pos + 1] not in self._stop_chars_right:
                    # Correcting Markdown matches
                    if right_enclosure_pos is None and text[end_pos + 1] == ")":
                        right_enclosure_pos = end_pos + 1
                    end_pos += 1
                else:
                    right_ok = False

            if start_pos >= 0 and text[start_pos : start_pos + 3] == "://":
                in_scheme = True

        # Correcting Markdown matches
        if possible_markdown and right_enclosure_pos is not None:
            end_pos = right_enclosure_pos

        complete_url = text[start_pos : end_pos + 1].lstrip("/")

        # Remove enclosures and clean up URL
        complete_url = self._split_markdown(complete_url, match_pos - start_pos)
        complete_url = self._remove_enclosure_from_url(complete_url)

        # URL should not start/end with whitespace
        complete_url = complete_url.strip()

        # URL should not start with two backslashes
        complete_url = complete_url.removeprefix("//")

        # URL should not start with unreserved characters
        if complete_url.startswith(("-", ".", "~", "_")):
            complete_url = complete_url[1:]

        if "#" in complete_url:
            return ""

        if not self._is_domain_valid(complete_url, with_schema_only=with_schema_only):
            return ""

        return complete_url

    def _is_domain_valid(self, url: str, with_schema_only=False) -> bool:
        """
        Checks if given URL has valid domain name

        :param str url: complete URL that we want to check
        :param bool with_schema_only: URL must contain schema to be valid
        :return: True if URL is valid, False otherwise
        :rtype: bool
        """
        if not url:
            return False

        scheme_pos = url.find("://")
        if scheme_pos == -1:
            if with_schema_only:
                return False
            url = "http://" + url

        try:
            parsed = self._parse_url(url)
        except Exception:
            return False

        # Authority can't start with @
        if parsed.netloc and parsed.netloc.startswith("@"):
            return False

        # Extract hostname
        hostname = parsed.hostname
        if not hostname:
            return False

        if self._permit_list and hostname not in self._permit_list:
            return False

        if hostname in self._ignore_list:
            return False

        host_parts = hostname.split(".")
        if len(host_parts) <= 1:
            return False

        # Check if the last part (TLD) looks valid
        tld = host_parts[-1]
        if not tld or not tld.isalpha():
            return False

        # Check if the second-to-last part (domain) is valid
        if len(host_parts) >= 2:
            domain = host_parts[-2]
            if self._hostname_re.match(domain) is None:
                return False

        return True

    def _remove_enclosure_from_url(self, text_url: str) -> str:
        """
        Removes enclosure characters from URL.

        :param str text_url: text with URL
        :return: URL that has removed enclosure
        :rtype: str
        """
        enclosure_map = dict(self._enclosure)

        # Find leftmost enclosure character
        left_pos = -1
        left_char = ""
        for l_char in enclosure_map:
            pos = text_url.find(l_char)
            if pos >= 0 and (left_pos == -1 or pos < left_pos):
                left_pos = pos
                left_char = l_char

        if left_pos == -1:
            return text_url

        right_char = enclosure_map.get(left_char, "")
        if not right_char:
            return text_url

        # Find corresponding right enclosure
        right_pos = text_url.rfind(right_char)
        if right_pos <= left_pos:
            return text_url

        return text_url[left_pos + 1 : right_pos]

    @staticmethod
    def _split_markdown(text_url: str, match_pos: int) -> str:
        """
        Split markdown URL to handle cases like [text](url)

        :param str text_url: URL that we want to extract from enclosure
        :param int match_pos: position of original match
        :return: cleaned URL
        :rtype: str
        """
        left_bracket_pos = text_url.find("[")
        if left_bracket_pos > match_pos - 3:
            return text_url

        right_bracket_pos = text_url.find(")")
        if right_bracket_pos < match_pos:
            return text_url

        middle_pos = text_url.rfind("](")
        if middle_pos > match_pos:
            return text_url[left_bracket_pos + 1 : middle_pos]

        return text_url

    def _extract_hostname(self, url: str) -> str:
        try:
            parsed = self._parse_url(url)
            return parsed.hostname or ""
        except Exception:
            return ""

    def gen_urls(self, text: str, with_schema_only=False) -> Generator[str | tuple[str, tuple[int, int]]]:
        """
        Creates generator over found URLs in given text.

        :param str text: text where we want to find URLs
        :param bool with_schema_only: get domains with schema only
        :yields: URL found in text or URL with indices
        :rtype: str|tuple(str, tuple(int, int))
        """
        for match in self._tlds_re.finditer(text):
            match_pos = match.start()
            match_text = match.group()

            complete_url = self._complete_url(text, match_pos, match_text, with_schema_only=with_schema_only)

            if complete_url:
                hostname = self._extract_hostname(complete_url)
                if hostname:
                    yield hostname

    def find_urls(
        self,
        text: str,
        with_schema_only=False,
    ) -> list[str | tuple[str, tuple[int, int]]]:
        """
        Find all URLs in given text.

        :param str text: text where we want to find URLs
        :param bool with_schema_only: get domains with schema only
        :return: list of URLs found in text
        :rtype: list
        """
        urls = list(
            self.gen_urls(
                text,
                with_schema_only=with_schema_only,
            )
        )

        return list(OrderedDict.fromkeys(urls))


class URLExtractError(Exception):
    """
    Raised when some error occurred during processing URLs.
    """

    def __init__(self, message, data=None):
        self.data = data
        self.message = message
        super().__init__(self.message)
