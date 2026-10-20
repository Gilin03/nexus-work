"""Opt-in portal GELF and Ollama integration. No database or tool permissions changed."""
import json
import logging
import os
import queue
import re
import socket
import threading
import urllib.request
import uuid
from datetime import datetime
from urllib.parse import urlsplit

from flask import g, has_request_context

FIELDS = set('ts event_type user role src_ip method path decision reason request_id source_component severity kind field count required resource action outcome tool mode conversation_id via token_fp api_path ms chars resource_id'.split())


def gelf(event, source):
    stamp = datetime.fromisoformat(event['ts'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('timezone_required')
    result = {'version': '1.1', 'host': source,
              'short_message': 'NEXUS ' + str(event['event_type'])[:80],
              'timestamp': stamp.timestamp(), '_portal_scope': 'nexus_team', '_synthetic': 0}
    for key in FIELDS:
        value = event.get(key)
        if not isinstance(value, (str, int, float, bool)):
            continue
        if key == 'path':
            value = str(value).split('?')[0].split('#')[0]
        if key == 'reason' and not re.fullmatch(r'[A-Za-z0-9_:., -]{0,100}', str(value)):
            continue
        result['_' + key] = int(value) if isinstance(value, bool) else value if isinstance(value, (int, float)) else value[:200]
    return json.dumps(result, ensure_ascii=False, allow_nan=False).encode('utf-8')


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        try:
            event = json.loads(record.getMessage())
            if has_request_context():
                if not getattr(g, 'nexus_request_id', None):
                    g.nexus_request_id = uuid.uuid4().hex
                event.setdefault('request_id', g.nexus_request_id)
            else:
                event.setdefault('request_id', uuid.uuid4().hex)
            event.setdefault('source_component', 'nexus_portal')
            record.msg = json.dumps(event, ensure_ascii=False)
            record.args = ()
        except (ValueError, TypeError):
            pass
        return True


class GelfQueueHandler(logging.Handler):
    def __init__(self, host, port, source):
        super().__init__()
        self.destination = (host, port)
        self.source = source
        self.pending = queue.Queue(maxsize=2000)
        self.dropped = 0
        self.sent = 0
        self.errors = 0
        self.stopped = threading.Event()
        threading.Thread(target=self._run, daemon=True, name='nexus-gelf').start()

    def emit(self, record):
        try:
            payload = gelf(json.loads(record.getMessage()), self.source)
            if len(payload) > 8000:
                raise ValueError('oversized')
            self.pending.put_nowait(payload)
        except (ValueError, TypeError, KeyError, queue.Full):
            self.dropped += 1

    def _run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            while not self.stopped.is_set():
                try:
                    payload = self.pending.get(timeout=.5)
                except queue.Empty:
                    continue
                try:
                    sock.sendto(payload, self.destination)
                    self.sent += 1
                except OSError:
                    self.errors += 1
                finally:
                    self.pending.task_done()

    def close(self):
        self.stopped.set()
        super().close()


def make_responder(url, model, timeout=60):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.query or parts.fragment:
        raise ValueError('invalid_ollama_url')
    endpoint = url.rstrip('/') + '/api/chat'
    capacity = threading.BoundedSemaphore(1)

    def respond(user, message, history):
        from app.security import log_event
        if not capacity.acquire(blocking=False):
            log_event('ai_busy', 'WARN', 'model_busy')
            return 'AI가 다른 요청을 처리하고 있습니다. 잠시 후 다시 시도해 주세요.'
        try:
            messages = [{'role': 'system', 'content': '한국어 업무 보조 도우미입니다. 간결하고 정확하게 답하세요. 현재 문서, DB, 도구에 접근하는 기능은 없습니다. 수행하지 않은 조회나 작업을 수행했다고 말하지 마세요.'}]
            for entry in history[-10:]:
                if entry.get('sender') in ('user', 'assistant') and isinstance(entry.get('content'), str):
                    messages.append({'role': entry['sender'], 'content': entry['content'][:2000]})
            messages.append({'role': 'user', 'content': message[:2000]})
            payload = json.dumps({'model': model, 'messages': messages, 'stream': False,
                                  'keep_alive': '2m', 'options': {'num_ctx': 4096, 'num_predict': 256, 'temperature': .2}}).encode()
            log_event('ai_request', 'INFO', 'ollama_chat')
            req = urllib.request.Request(endpoint, data=payload, headers={'Content-Type': 'application/json'})
            # Do not send private LAN requests through a system HTTP proxy.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=timeout) as response:
                raw = response.read(131073)
            if len(raw) > 131072:
                raise ValueError('oversized_model_response')
            data = json.loads(raw)
            text = data.get('message', {}).get('content')
            if not isinstance(text, str) or not text.strip() or not data.get('done'):
                raise ValueError('invalid_model_response')
            log_event('ai_response', 'INFO', 'ollama_chat_complete')
            return text[:8000]
        finally:
            capacity.release()
    return respond


def init_app(app):
    if app.extensions.get('nexus_team_integration'):
        return
    state = {}
    logger = logging.getLogger('nexus.security')
    if os.environ.get('NEXUS_GELF_ENABLED', '0') == '1':
        if any(h.__class__.__name__ == 'GelfHandler' for h in logger.handlers):
            raise RuntimeError('Disable old monitoring GELF handler before enabling team integration')
        if not any(isinstance(f, RequestIdFilter) for f in logger.filters):
            logger.addFilter(RequestIdFilter())
        handler = GelfQueueHandler(os.environ.get('NEXUS_GELF_HOST', '192.168.3.10'),
                                   int(os.environ.get('NEXUS_GELF_PORT', '12201')),
                                   os.environ.get('NEXUS_GELF_SOURCE', 'nexus-portal-' + socket.gethostname()))
        logger.addHandler(handler)
        state['gelf'] = handler
    if os.environ.get('NEXUS_OLLAMA_ENABLED', '0') == '1':
        app.config['CHAT_RESPONDER'] = make_responder(os.environ.get('OLLAMA_URL', 'http://192.168.3.10:11434'),
                                                     os.environ.get('OLLAMA_MODEL', 'qwen2.5:3b'),
                                                     int(os.environ.get('OLLAMA_TIMEOUT_SECONDS', '60')))
        state['ollama'] = True
    app.extensions['nexus_team_integration'] = state
