"""결재 본문의 서식 있는 글(HTML) 살균기. 공문처럼 글자 서식과 표가 있는 내용을 받되, 저장·표시 전에 허용 목록으로 걸러 스크립트가 들어갈 틈을 없앤다.

설계(저장형 XSS 방어 — 이 본문은 결재자·관리자가 열어 본다):
- 허용 목록 방식: 허용한 태그·속성·클래스만 남기고 나머지는 전부 버린다. script·style·iframe 같은 위험한 태그는 안의 내용까지 버리고, 모르는 태그는 태그만 벗기고 글자는 남긴다.
- 속성은 class(허용한 이름만)와 표 칸의 colspan·rowspan(작은 정수)뿐이다. style·id·on…·href·src 는 어떤 것도 남기지 않는다.
  CSP(style-src 'self')가 인라인 스타일을 막으므로 글자 크기·색·정렬은 style 이 아니라 미리 정한 클래스(fs-3, c-red, al-center …)로 표현한다.
- 표시할 때는 문자열을 그대로 내보내지 않는다: 살균한 결과를 노드 트리로 만들어 템플릿 매크로(_richtext.html)가 자동 이스케이프로 다시 그린다.
  그래서 이스케이프를 끄는 필터나 마크업 우회 없이 표시되고, 저장된 값이 DB 에서 바뀌었더라도 표시 때 한 번 더 걸러진다(parse 는 항상 다시 살균한다).
- 표준 라이브러리(html.parser)만 쓴다. 입력 크기·중첩 깊이·노드 수에 상한을 두어 거대한 입력으로 서버를 괴롭히지 못하게 한다."""
import re
from html import escape
from html.parser import HTMLParser

MAX_INPUT = 2_000_000      # 입력 글자 수 상한(이를 넘으면 호출하는 쪽이 거부한다)
MAX_DEPTH = 30             # 태그 중첩 깊이
MAX_NODES = 20_000         # 만들어 두는 노드 수

ALLOWED_TAGS = {"p", "div", "br", "hr", "span", "b", "strong", "i", "em", "u", "s", "strike", "sub", "sup", "h2", "h3",
                "ul", "ol", "li", "blockquote", "table", "caption", "thead", "tbody", "tfoot", "tr", "th", "td"}
VOID_TAGS = {"br", "hr"}
RENAME = {"strike": "s", "h1": "h2", "h4": "h3", "h5": "h3", "h6": "h3"}      # 비슷한 태그는 허용 태그로 바꾼다
# 안의 내용까지 버리는 태그(스크립트·스타일·외부 문서·폼·미디어 등)
DROP_CONTENT = {"script", "style", "iframe", "object", "embed", "noscript", "template", "svg", "math", "textarea", "title", "head",
                "select", "option", "button", "form", "frame", "frameset", "applet", "xmp", "plaintext", "noembed", "noframes",
                "audio", "video", "canvas", "map", "input", "link", "meta", "base", "datalist", "dialog", "portal"}
# 부모가 정해진 태그(엉뚱한 곳에 나오면 태그만 벗긴다)
REQUIRED_PARENT = {"li": {"ul", "ol"}, "tr": {"table", "thead", "tbody", "tfoot"}, "td": {"tr"}, "th": {"tr"},
                   "thead": {"table"}, "tbody": {"table"}, "tfoot": {"table"}, "caption": {"table"}}
CONTAINER_ONLY = {"table", "thead", "tbody", "tfoot", "tr", "ul", "ol"}     # 글자가 직접 들어가지 않는 태그

# 허용하는 클래스: 글자 크기(1~7), 글자 색, 배경색, 정렬, 표 모양. 편집기(rich-editor.js)와 style.css 가 같은 이름을 쓴다.
ALLOWED_CLASSES = (
    {f"fs-{n}" for n in range(1, 8)}
    | {"c-black", "c-red", "c-blue", "c-green", "c-orange", "c-purple", "c-gray"}
    | {"bg-yellow", "bg-gray", "bg-blue", "bg-green", "bg-red"}
    | {"al-left", "al-center", "al-right", "al-justify"}
    | {"doc-table", "b-none"}
)
SPAN_LIMIT = 20            # colspan·rowspan 상한


class _Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"t": "#root", "c": "", "a": {}, "k": []}
        self.stack = [("#root", self.root)]         # (태그 이름, 노드 또는 None=벗긴 태그)
        self.skip_tag = None
        self.skip_depth = 0
        self.nodes = 0
        self.visible = 0

    # ----- 도우미 -----
    def _real_parent(self):
        for name, node in reversed(self.stack):
            if node is not None:
                return name, node
        return "#root", self.root

    def _attrs(self, tag, attrs):
        cls, extra = [], {}
        for key, value in attrs:
            key = (key or "").lower()
            value = value or ""
            if key == "class":
                cls = [c for c in value.split() if c in ALLOWED_CLASSES]
            elif key in ("colspan", "rowspan") and tag in ("td", "th") and value.isascii() and value.isdigit():
                n = int(value)
                if 1 < n <= SPAN_LIMIT:
                    extra[key] = str(n)
        return " ".join(dict.fromkeys(cls)), extra

    # ----- 파서 이벤트 -----
    def handle_starttag(self, tag, attrs):
        tag = RENAME.get(tag.lower(), tag.lower())
        if self.skip_tag:
            if tag == self.skip_tag:
                self.skip_depth += 1
            return
        if tag in DROP_CONTENT:
            if tag not in VOID_TAGS and tag not in ("input", "link", "meta", "base"):   # 값 없는 태그는 내용이 없으니 건너뛸 구간도 없다
                self.skip_tag, self.skip_depth = tag, 1
            return
        parent_name, parent = self._real_parent()
        ok = (tag in ALLOWED_TAGS and self.nodes < MAX_NODES and len(self.stack) < MAX_DEPTH
              and (tag not in REQUIRED_PARENT or parent_name in REQUIRED_PARENT[tag]))
        if not ok:
            if tag not in VOID_TAGS:
                self.stack.append((tag, None))       # 태그만 벗기고 안의 글자는 남긴다
            return
        cls, extra = self._attrs(tag, attrs)
        node = {"t": tag, "c": cls, "a": extra, "k": []}
        parent["k"].append(node)
        self.nodes += 1
        if tag not in VOID_TAGS:
            self.stack.append((tag, node))

    def handle_endtag(self, tag):
        tag = RENAME.get(tag.lower(), tag.lower())
        if self.skip_tag:
            if tag == self.skip_tag:
                self.skip_depth -= 1
                if self.skip_depth == 0:
                    self.skip_tag = None
            return
        for i in range(len(self.stack) - 1, 0, -1):      # 가장 가까운 같은 이름의 열린 태그까지 닫는다(짝이 없으면 무시)
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if self.skip_tag or not data:
            return
        name, node = self._real_parent()
        if name in CONTAINER_ONLY and not data.strip():
            return                                        # 표·목록 사이의 공백·줄바꿈은 버린다
        kids = node["k"]
        if kids and isinstance(kids[-1], str):
            kids[-1] += data
        else:
            kids.append(data)
        self.visible += sum(1 for ch in data if not ch.isspace())

    # 주석·선언·처리 명령은 모두 버린다(핸들러를 두지 않으면 기본 구현이 아무것도 하지 않는다).


def parse(html_text):
    """HTML 문자열을 살균한 노드 트리(노드 = {"t","c","a","k"} 또는 글자 문자열)의 자식 목록으로 돌려준다. (트리, 보이는 글자 수)"""
    builder = _Builder()
    builder.feed((html_text or "")[:MAX_INPUT])
    builder.close()
    return builder.root["k"], builder.visible


def _serialize(nodes, out):
    for n in nodes:
        if isinstance(n, str):
            out.append(escape(n, quote=False))
            continue
        out.append(f"<{n['t']}")
        if n["c"]:
            out.append(f' class="{n["c"]}"')
        for k, v in n["a"].items():
            out.append(f' {k}="{v}"')
        out.append(">")
        if n["t"] not in VOID_TAGS:
            _serialize(n["k"], out)
            out.append(f"</{n['t']}>")


def sanitize(html_text):
    """저장용: (살균한 HTML 문자열, 보이는 글자 수). 같은 입력은 항상 같은 결과이고, 살균한 결과를 다시 넣어도 바뀌지 않는다."""
    tree, visible = parse(html_text)
    out = []
    _serialize(tree, out)
    return "".join(out), visible


def plain_to_html(text):
    """줄바꿈이 있는 글자를 문단으로 바꾼다(예전 본문을 편집기에 불러올 때). 모든 글자는 이스케이프된다."""
    paras = (text or "").replace("\r\n", "\n").split("\n")
    return "".join(f"<p>{escape(p, quote=False) or '<br>'}</p>" for p in paras)
