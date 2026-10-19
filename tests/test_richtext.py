"""서식 있는 본문 살균기(app/richtext.py) 시험. DB 없이 실행된다. 결재 본문은 결재자·관리자가 열어 보므로 저장형 XSS 가 가장 큰 위험이다.
출력이 안전한지는 살균기 자신이 아니라 **독립적으로 다시 파싱하는 검사기**로 확인한다(허용 태그·속성·클래스만 있는지)."""
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from app import richtext as rt

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "app" / "static" / "style.css").read_text(encoding="utf-8")
JS = (ROOT / "app" / "static" / "rich-editor.js").read_text(encoding="utf-8")


class Audit(HTMLParser):
    """살균한 출력을 다시 파싱해 허용되지 않은 것이 하나라도 있으면 기록한다."""
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.problems = []

    def handle_starttag(self, tag, attrs):
        if tag not in rt.ALLOWED_TAGS:
            self.problems.append(f"tag <{tag}>")
        for key, value in attrs:
            if key == "class":
                bad = [c for c in (value or "").split() if c not in rt.ALLOWED_CLASSES]
                if bad:
                    self.problems.append(f"class {bad}")
            elif key in ("colspan", "rowspan") and tag in ("td", "th") and (value or "").isdigit() and 2 <= int(value) <= rt.SPAN_LIMIT:
                pass
            else:
                self.problems.append(f"attr {key}={value!r} on <{tag}>")

    def handle_comment(self, data):
        self.problems.append("comment")

    def handle_decl(self, decl):
        self.problems.append("declaration")

    def handle_pi(self, data):
        self.problems.append("processing instruction")


def audit(html):
    a = Audit()
    a.feed(html)
    a.close()
    assert "<script" not in html.lower().replace("&lt;script", "") and "<!--" not in html
    return a.problems


# ---------- 허용하는 서식은 그대로 남는다 ----------
def test_formatting_tables_and_lists_are_kept():
    src = ('<h2 class="al-center">제목</h2><p class="al-right fs-5 c-red">글 <b>굵게</b> <i>기울임</i> <u>밑줄</u> <s>취소</s> <sub>a</sub><sup>b</sup></p>'
           '<span class="bg-yellow">형광</span><ul><li>하나</li><li>둘</li></ul><ol><li>첫째</li></ol><hr><blockquote>인용</blockquote>'
           '<table class="doc-table"><thead><tr><th colspan="2">머리</th></tr></thead><tbody><tr><td rowspan="2">가</td><td>나</td></tr>'
           '<tr><td>다</td></tr></tbody></table>')
    out, visible = rt.sanitize(src)
    assert out == src and visible > 10 and audit(out) == []


@pytest.mark.parametrize("raw,expected", [
    ("<strike>x</strike>", "<s>x</s>"), ("<h1>x</h1>", "<h2>x</h2>"), ("<h4>x</h4>", "<h3>x</h3>"),
    ("<font size=5 color=red>옛 글꼴</font>", "옛 글꼴"),                      # font 는 벗긴다(편집기가 클래스로 바꿔 보낸다)
    ('<p class="c-red evil fs-3 onclick">a</p>', '<p class="c-red fs-3">a</p>'),   # 허용하지 않는 클래스는 이름만 걸러진다
    ('<p class="">a</p>', "<p>a</p>"),
    ("<p>a<br/>b</p>", "<p>a<br>b</p>"),
])
def test_normalisation(raw, expected):
    assert rt.sanitize(raw)[0] == expected


# ---------- 위험한 입력은 전부 걸러진다 ----------
HOSTILE = [
    "<script>alert(1)</script>", "<SCRIPT SRC=//evil/x.js></SCRIPT>", "<ScRiPt>alert(1)</sCrIpT>", "<<script>script>alert(1)<</script>/script>",
    "<script>alert(1)", "<script/src=x>", '<img src=x onerror=alert(1)>', "<img src=x onerror=alert(1)//", '<img/src/onerror=alert(1)>',
    '<svg onload=alert(1)>', "<svg><script>alert(1)</script></svg>", "<svg><style>*{}</style><a href=javascript:alert(1)>x</a></svg>",
    "<math><mtext><script>alert(1)</script></mtext></math>", '<iframe src="javascript:alert(1)"></iframe>', "<iframe srcdoc='<script>alert(1)</script>'>",
    '<object data="javascript:alert(1)"></object>', '<embed src="x.swf">', '<a href="javascript:alert(1)">x</a>', '<a href="data:text/html,<script>alert(1)</script>">x</a>',
    '<a href="&#106;avascript:alert(1)">x</a>', '<form action="//evil"><input name=a><button>x</button></form>', "<input autofocus onfocus=alert(1)>",
    "<button onclick=alert(1)>x</button>", "<style>body{display:none}</style>", "<style>@import 'http://evil/x.css';</style>",
    '<table><style><a title="</style><img src=x onerror=alert(1)>"></style></table>', '<link rel=stylesheet href="//evil/x.css">',
    '<meta http-equiv="refresh" content="0;url=//evil">', '<base href="//evil/">', "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<template><script>alert(1)</script></template>", "<textarea><script>alert(1)</script></textarea>", "<title><script>alert(1)</script></title>",
    "<xmp><script>alert(1)</script></xmp>", "<plaintext><script>alert(1)", '<p onclick="alert(1)" onmouseover=alert(1) style="x:expression(alert(1))">x</p>',
    '<p style="background:url(javascript:alert(1))">x</p>', '<div id="x" name="y" data-a="1" title="t" lang="ko" dir="rtl">x</div>',
    '<td colspan="2" onclick="alert(1)">x</td>', "<!--<script>alert(1)</script>-->x", "<!--[if IE]><script>alert(1)</script><![endif]-->", "<![CDATA[<script>alert(1)</script>]]>",
    "<?php echo 1; ?>", '<!DOCTYPE html><html><head><script>alert(1)</script></head><body onload=alert(1)>x</body></html>',
    "<video><source onerror=alert(1)></video>", "<audio src=x onerror=alert(1)>", '<details open ontoggle=alert(1)>x</details>', "<marquee onstart=alert(1)>x</marquee>",
    '<a href="x" target="_blank" rel="opener">x</a>', '<p><a href="//evil">클릭</a></p>', "<p>&#60;script&#62;alert(1)&#60;/script&#62;</p>",
    "<p>&lt;img src=x onerror=alert(1)&gt;</p>", "<p><b><i><u>x</u></b></i></p>", "<b><p>x</b></p>", "</p></div></table><p>x",
]


@pytest.mark.parametrize("src", HOSTILE)
def test_hostile_input_never_leaves_anything_dangerous(src):
    out, _ = rt.sanitize(src)
    assert audit(out) == [], (src, out)
    assert not re.search(r"<\s*(script|img|iframe|svg|object|embed|a|form|input|button|style|link|meta|base)\b", out, re.I), out
    assert not re.search(r"\bon[a-z]+\s*=", re.sub(r"&lt;.*?&gt;", "", out)), out      # 이스케이프된 글자 밖에는 이벤트 핸들러가 없다
    assert rt.sanitize(out)[0] == out                                                   # 살균한 결과는 다시 살균해도 그대로다(멱등)


def test_dangerous_content_is_dropped_but_surrounding_text_survives():
    out, visible = rt.sanitize("<p>앞<script>alert(1)</script>뒤</p><style>x{}</style>글자<svg><circle/></svg>끝")
    assert out == "<p>앞뒤</p>글자끝" and visible == 5


def test_entity_encoded_markup_stays_text_and_is_re_escaped():
    out, _ = rt.sanitize("<p>&#60;script&#62;alert(1)&#60;/script&#62; &amp;lt;b&amp;gt;</p>")
    assert out == "<p>&lt;script&gt;alert(1)&lt;/script&gt; &amp;lt;b&amp;gt;</p>"


# ---------- 표·목록 구조와 한도 ----------
@pytest.mark.parametrize("value,kept", [("2", True), ("20", True), ("1", False), ("0", False), ("21", False), ("999", False), ("-2", False), ("abc", False), ("2.5", False), ("", False)])
def test_colspan_and_rowspan_are_small_positive_integers_only(value, kept):
    for attr in ("colspan", "rowspan"):
        out, _ = rt.sanitize(f'<table><tr><td {attr}="{value}">x</td></tr></table>')
        assert (f'{attr}="{value}"' in out) is kept


def test_cells_rows_and_list_items_outside_their_parents_are_unwrapped():
    assert rt.sanitize("<td>고아 칸</td><li>고아 항목</li><tr>행</tr>")[0] == "고아 칸고아 항목행"
    assert rt.sanitize("<div><tr><td>x</td></tr></div>")[0] == "<div>x</div>"
    assert rt.sanitize("<table><tr><td><table><tr><td>안쪽</td></tr></table></td></tr></table>")[0] == \
        "<table><tr><td><table><tr><td>안쪽</td></tr></table></td></tr></table>"          # 표 안의 표는 허용
    assert rt.sanitize("<table>\n  <tr>\n  <td>x</td>\n  </tr>\n</table>")[0] == "<table><tr><td>x</td></tr></table>"   # 표 사이 공백은 버린다


def test_nesting_depth_and_node_count_are_capped():
    deep = "<div>" * 5000 + "깊이" + "</div>" * 5000
    out, visible = rt.sanitize(deep)
    assert out.count("<div>") <= rt.MAX_DEPTH and visible == 2 and audit(out) == []
    many = "<b>x</b>" * (rt.MAX_NODES * 3)
    out, visible = rt.sanitize(many)
    assert out.count("<b>") <= rt.MAX_NODES and visible == rt.MAX_NODES * 3                # 태그는 상한까지만, 글자는 모두 남는다
    assert len(rt.sanitize("a" * (rt.MAX_INPUT + 500))[0]) == rt.MAX_INPUT                 # 입력은 상한까지만 읽는다


def test_visible_character_count_ignores_markup_and_whitespace():
    assert rt.sanitize("<p><br></p><table><tr><td><br></td></tr></table>")[1] == 0
    assert rt.sanitize("<p> a b </p><p>가</p>")[1] == 3
    assert rt.sanitize("")[1] == 0 and rt.sanitize(None)[1] == 0


def test_plain_text_to_html_escapes_everything():
    assert rt.plain_to_html("a\n\n<b>x</b>\r\n&") == "<p>a</p><p><br></p><p>&lt;b&gt;x&lt;/b&gt;</p><p>&amp;</p>"


def test_parse_returns_nodes_that_serialise_the_same_way():
    tree, _ = rt.parse('<p class="al-center">가<b>나</b></p>')
    assert tree == [{"t": "p", "c": "al-center", "a": {}, "k": ["가", {"t": "b", "c": "", "a": {}, "k": ["나"]}]}]


# ---------- 클래스 이름은 서버·편집기·스타일시트가 같아야 한다 ----------
def test_every_allowed_class_has_a_style_rule():
    missing = [c for c in sorted(rt.ALLOWED_CLASSES) if f".{c} " not in CSS and f".{c}," not in CSS and f".{c}{{" not in CSS and f".{c}\n" not in CSS]
    assert missing == []


def test_editor_script_allows_exactly_the_classes_the_server_allows():
    pattern = re.search(r"var CLASS_OK = /(.+?)/;", JS).group(1)
    client = re.compile(pattern)
    for c in rt.ALLOWED_CLASSES:
        assert client.match(c), c
    for c in ("evil", "fs-0", "fs-8", "c-pink", "bg-black", "al-top", "onclick", "fs-3 evil"):
        assert not client.match(c), c
    server_tags = set(re.search(r"var ALLOWED = \{(.+?)\};", JS, re.S).group(1).replace("1", "").replace(":", "").replace(",", " ").split())
    assert server_tags == rt.ALLOWED_TAGS


def _lum(hex_color):
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def test_rich_text_colours_are_readable_on_white_and_on_every_background():
    colours = dict(re.findall(r"\.c-(\w+) \{ color: (#[0-9a-f]{6}); \}", CSS))
    backgrounds = dict(re.findall(r"\.bg-(\w+) \{ background: (#[0-9a-f]{6}); \}", CSS))
    assert len(colours) == 7 and len(backgrounds) == 5
    ratio = lambda a, b: (max(_lum(a), _lum(b)) + 0.05) / (min(_lum(a), _lum(b)) + 0.05)
    for name, fg in colours.items():
        assert ratio(fg, "#ffffff") >= 4.5, (name, ratio(fg, "#ffffff"))
    assert ratio("#1b2a4a", "#ffffff") >= 4.5
    for name, bg in backgrounds.items():                                                  # 기본 글자색이 어떤 배경 위에서도 읽혀야 한다
        assert ratio("#1b2a4a", bg) >= 4.5, name
