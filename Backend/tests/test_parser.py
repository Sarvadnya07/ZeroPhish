import pytest
from email_scanner.parser import EmlParser

def test_extract_links_empty():
    links = EmlParser._extract_links("", "")
    assert links == []

def test_extract_links_plain_text():
    text = "Here is a link http://example.com and another https://test.com/path."
    links = EmlParser._extract_links(text, "")
    assert links == ["http://example.com", "https://test.com/path"]

def test_extract_links_html_href():
    html = 'Click <a href="https://example.org">here</a> or <a href=\'http://test.org\'>there</a>.'
    links = EmlParser._extract_links("", html)
    assert links == ["https://example.org", "http://test.org"]

def test_extract_links_deduplication():
    text = "Link: https://duplicate.com"
    html = '<html><a href="https://duplicate.com">link</a></html>'
    links = EmlParser._extract_links(text, html)
    assert links == ["https://duplicate.com"]

def test_extract_links_punctuation_stripping():
    text = "Look at this: https://example.com/page, and this (https://example.com/other)."
    links = EmlParser._extract_links(text, "")
    assert "https://example.com/page" in links
    assert "https://example.com/other" in links

def test_extract_links_shortener():
    text = "Short link: http://bit.ly/12345/"
    links = EmlParser._extract_links(text, "")
    assert links == ["http://bit.ly/12345/", "[SHORTENER:http://bit.ly/12345/]"]

def test_extract_links_cap_200():
    text = " ".join([f"http://example.com/{i}" for i in range(250)])
    links = EmlParser._extract_links(text, "")
    assert len(links) == 200
    assert links[0] == "http://example.com/0"
    assert links[-1] == "http://example.com/199"
