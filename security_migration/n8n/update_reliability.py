"""Prepare a reliability-hardened export of the currently published NEXUS workflow.

This script reads the published workflow through the supported n8n CLI export command,
preserves its credentials and rule branches, and writes an inactive import candidate.
It never imports, publishes, activates, or executes a workflow.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "nexus-alert-v2-reliability-candidate.json"
WORKFLOW_ID = "ACDMe167dfnTi2qT"
WORKFLOW_NAME = "NEXUS 탐지 알림 수신 v2 - 최종 후보 (DRY-RUN)"
NS = uuid.UUID("cb544eff-c0c9-4681-8e24-25ab8513a601")


def node_id(name: str) -> str:
    return str(uuid.uuid5(NS, name))


def edge(connections: dict, source: str, target: str, output: int = 0) -> None:
    branches = connections.setdefault(source, {}).setdefault("main", [])
    while len(branches) <= output:
        branches.append([])
    branches[output].append({"node": target, "type": "main", "index": 0})


def replace_edge(connections: dict, source: str, target: str, new_target: str, output: int = 0) -> None:
    entries = connections[source]["main"][output]
    found = False
    for entry in entries:
        if entry["node"] == target:
            entry["node"] = new_target
            found = True
    if not found:
        raise ValueError(f"expected connection not found: {source} -> {target}")


def mysql_node(name: str, query: str, replacements: str, credentials: dict, position: list[int], *, batching: str = "transaction") -> dict:
    return {
        "parameters": {
            "operation": "executeQuery",
            "query": query,
            "options": {
                "queryBatching": batching,
                "queryReplacement": replacements,
            },
        },
        "id": node_id(name),
        "name": name,
        "type": "n8n-nodes-base.mySql",
        "typeVersion": 2.5,
        "position": position,
        "credentials": credentials,
    }


def _replace_code(nodes: dict, name: str, code: str) -> None:
    nodes[name]["parameters"]["jsCode"] = code


def build() -> dict:
    proc = subprocess.run(
        ["docker", "exec", "n8n", "n8n", "export:workflow", f"--id={WORKFLOW_ID}", "--published"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    start = proc.stdout.find("[")
    if start < 0:
        raise ValueError("n8n export did not contain workflow JSON")
    exported, _ = json.JSONDecoder().raw_decode(proc.stdout[start:])
    workflow = next((item for item in exported if item.get("id") == WORKFLOW_ID), None)
    if not workflow or workflow.get("active") is not True:
        raise ValueError("published active workflow was not found")
    if workflow.get("name") != WORKFLOW_NAME:
        raise ValueError("workflow identity changed; inspect before updating")

    original_names = {node["name"] for node in workflow["nodes"]}
    node_map = {node["name"]: node for node in workflow["nodes"]}
    required = {
        "DB 조치 실행", "Discord 알림", "대응 결과 알림", "티켓 기록(출발지별)",
        "정규화·대응 계획", "NEXUS 안전 설정(수신)", "NEXUS 안전 설정(조회)",
        "NEXUS 안전 설정(티켓 처리)", "화이트리스트 제외?", "응답(중복·fallback·화이트리스트)",
        "응답 200(티켓 기록 후 접수)", "티켓 목록 만들기", "티켓 처리·화이트리스트",
        "계정 조치 실행?", "응답(처리 결과)",
    }
    if not required.issubset(node_map):
        raise ValueError("required original workflow nodes are missing")

    mysql_credentials = node_map["DB 조치 실행"].get("credentials", {}).get("mySql")
    discord_credentials = node_map["Discord 알림"].get("credentials", {}).get("discordWebhookApi")
    if not mysql_credentials or not discord_credentials:
        raise ValueError("existing MySQL/Discord credential references were not found")

    prepare_ticket_code = r'''const d = $input.first().json;
const sd = $getWorkflowStaticData('global');
sd.whitelist = sd.whitelist || {};
sd.skipped = sd.skipped || [];
const whitelist = Array.isArray(d.whitelist_ips) ? d.whitelist_ips.map(String) : [];
if (d.src_ip && (whitelist.includes(d.src_ip) || sd.whitelist[d.src_ip])) {
  sd.skipped.unshift({ time: d.last_seen, src_ip: d.src_ip, rule_id: d.rule_id });
  sd.skipped = sd.skipped.slice(0, 50);
  return [{ json: { ...d, whitelisted: true, skip_side_effects: true } }];
}
const rank = { '이상 징후 경보': 1, '보안 경보': 1, '잠금 결과 기록': 2, '차단 조치': 2, '침해 인시던트': 3 };
const allowed = new Set(['event_type','injection_type','source_type','source_component','trigger_source','user','role','src_ip',
  'request_id','session_id','tool_name','resource_class','resource_id','trigger_resource_id','pattern_id','decision','reason',
  'severity','path','resource','required','count','window_seconds','failed_attempts','lock_request_id','trigger_event_type','evidence']);
const event = {};
for (const [key, value] of Object.entries(d.event || {})) if (allowed.has(key)) event[key] = value;
const safe = { rule: d.rule, alert: d.alert, event, action_level: d.action_level, decision: d.decision };
const eventCount = Math.max(1, Math.min(100000, Math.floor(Number(d.count) || 1)));
const timestamp = String(d.last_seen || d.alert?.timestamp || new Date().toISOString());
const receiptId = String($execution.id || `${Date.now()}-${Math.random()}`).slice(0, 64);
return [{ json: { ...d, ticket_record: {
  alert_id: String(d.graylog_event_id), receipt_id: receiptId,
  rule_id: String(d.rule_id), event_type: String(event.event_type || ''),
  user: String(d.user || ''), src_ip: String(d.src_ip || ''), event_count: eventCount,
  timestamp, ticket_key: String(d.ticket_key), ticket_type: String(d.ticket_type || '보안 경보'),
  type_rank: Number(rank[d.ticket_type] || 1), rule_id_for_ticket: String(d.rule_id),
  event_payload: JSON.stringify(safe)
} } }];'''

    merge_ticket_code = r'''const d = $('티켓 기록(출발지별)').first().json;
const row = $input.first().json || {};
if (!row.ticket_db_id) throw new Error('persistent ticket record was not returned');
const parse = (v, fallback) => {
  if (Array.isArray(v) || (v && typeof v === 'object')) return v;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch {} }
  return fallback;
};
const rules = parse(row.ticket_rules, []);
const users = parse(row.ticket_users, []);
const ticketId = String(row.ticket_id || `NX-DB-${String(row.ticket_db_id).padStart(6, '0')}`);
const duplicate = row.ticket_duplicate === true || Number(row.ticket_duplicate) === 1;
const isNew = !duplicate && (row.ticket_is_new === true || Number(row.ticket_is_new) === 1);
return [{ json: { ...d, ticket_id: ticketId, ticket_duplicate: duplicate,
  ticket_is_new: isNew, ticket_type: row.ticket_type || d.ticket_type,
  ticket_rules: rules, ticket_users: users,
  ticket_event_total: Number(row.ticket_event_total || 0),
  skip_side_effects: !!d.skip_side_effects || duplicate,
  message: `[${ticketId} ${duplicate ? '중복' : (isNew ? '신규' : '갱신')}] ` + d.message
} }];'''

    list_tickets_code = r'''const input = $('NEXUS 안전 설정(조회)').first().json || {};
const db = $input.first().json || {};
const sd = $getWorkflowStaticData('global');
sd.tickets = sd.tickets || {}; sd.history = sd.history || []; sd.whitelist = sd.whitelist || {}; sd.skipped = sd.skipped || [];
const parse = (v, fallback) => {
  if (Array.isArray(v) || (v && typeof v === 'object')) return v;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch {} }
  return fallback;
};
const rows = parse(db.ticket_rows, []);
const dbTickets = rows.map(t => ({
  id: `NX-DB-${String(t.id).padStart(6, '0')}`, ticket_key: t.ticket_key, src_ip: t.src_ip || '',
  type: t.ticket_type, rules: parse(t.rule_ids, []), users: parse(t.user_names, []),
  count: Number(t.event_count || 0), first_seen: t.first_seen, last_seen: t.last_seen,
  status: t.status, latest: parse(t.latest_event, {}), resolution: t.resolution || undefined,
  closed_at: t.closed_at || undefined, note: t.note || undefined,
  responses: parse(t.responses, [])
}));
const all = [...dbTickets, ...Object.values(sd.tickets), ...sd.history]
  .sort((a,b) => String(b.last_seen || '').localeCompare(String(a.last_seen || '')));
const open = all.filter(t => t.status === 'open');
const by_type = {};
for (const t of open) by_type[t.type] = (by_type[t.type] || 0) + 1;
const configured = Array.isArray(input.whitelist_ips) ? input.whitelist_ips.map(String) : [];
return [{ json: { http: 200, body: {
  generated_at: new Date().toISOString(),
  summary: { open: open.length, closed: all.length - open.length, by_type }, tickets: all,
  whitelist: [...configured.map(ip => ({ip, source:'환경설정'})), ...Object.entries(sd.whitelist).map(([ip,v])=>({ip,source:'상황판',...v}))],
  skipped: sd.skipped.slice(0,10)
} } }];'''

    ticket_lookup_sql = '''SELECT t.id AS ticket_db_id, t.status AS ticket_db_status, t.src_ip AS ticket_db_src_ip,
  t.user_names AS ticket_db_users, t.ticket_type AS ticket_db_type, t.event_count AS ticket_db_count,
  t.rule_ids AS ticket_db_rules, t.first_seen AS ticket_db_first_seen, t.last_seen AS ticket_db_last_seen,
  t.latest_event AS ticket_db_latest, t.responses AS ticket_db_responses,
  CAST($1 AS JSON) AS body, $2 AS response_mode, CAST($3 AS UNSIGNED) AS live_enabled,
  CAST($4 AS UNSIGNED) AS lock_minutes, CAST($5 AS JSON) AS whitelist_ips
FROM (SELECT 1) AS request
LEFT JOIN security_incident_tickets t
  ON CONCAT('NX-DB-', LPAD(t.id, 6, '0')) = JSON_UNQUOTE(JSON_EXTRACT(CAST($1 AS JSON), '$.ticket_id'))'''

    action_code = node_map["티켓 처리·화이트리스트"]["parameters"]["jsCode"]
    action_code = action_code.replace(
        "const b = input.body || {};",
        "const b = typeof input.body === 'string' ? (JSON.parse(input.body) || {}) : (input.body || {});",
        1,
    )
    action_code = action_code.replace(
        "const configured = Array.isArray(input.whitelist_ips) ? input.whitelist_ips.map(String) : [];",
        "const configured = Array.isArray(input.whitelist_ips) ? input.whitelist_ips.map(String) : (typeof input.whitelist_ips === 'string' ? (JSON.parse(input.whitelist_ips) || []).map(String) : []);",
        1,
    )
    action_code = action_code.replace(
        "const mode = input.response_mode === 'live' && input.live_enabled === true ? 'live' : 'dry-run';",
        "const liveEnabled = input.live_enabled === true || Number(input.live_enabled) === 1;\nconst mode = input.response_mode === 'live' && liveEnabled ? 'live' : 'dry-run';",
        1,
    )
    base_action_code = action_code
    db_action_guard = r'''const parseDbJson = (v, fallback) => {
  if (Array.isArray(v) || (v && typeof v === 'object')) return v;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch {} }
  return fallback;
};
const dbTicketMatch = /^NX-DB-(\d{6})$/.exec(String(b.ticket_id || ''));
if (dbTicketMatch) {
  const dbId = Number(input.ticket_db_id || 0);
  if (!dbId) return res(404, {status:'not_found'});
  const dbUsers = parseDbJson(input.ticket_db_users, []);
  const dbRules = parseDbJson(input.ticket_db_rules, []);
  const dbResponses = parseDbJson(input.ticket_db_responses, []);
  const ticket = { id:b.ticket_id, src_ip:String(input.ticket_db_src_ip || ''), type:input.ticket_db_type,
    users:dbUsers, rules:dbRules, count:Number(input.ticket_db_count || 0), status:input.ticket_db_status,
    first_seen:input.ticket_db_first_seen, last_seen:input.ticket_db_last_seen,
    latest:parseDbJson(input.ticket_db_latest, {}), responses:dbResponses };
  if (b.action === 'close' || b.action === 'false_positive') {
    if (ticket.status === 'closed') return res(409,{status:'already_closed'});
    return [{json:{http:200,body:null,db_ticket_action:{id:dbId,action:b.action,
      resolution:b.action==='false_positive'?'오탐':'조치 완료',note:String(b.note||'').slice(0,500),
      whitelist:b.action==='false_positive' && b.whitelist===true,whitelist_ip:ticket.src_ip}}}];
  }
  if (b.action === 'release' || b.action === 'lock') {
    const selected = String(b.user || (dbUsers.length===1?dbUsers[0]:'')).trim();
    if (!userOk(selected)) return res(400,{status:'bad_user'});
    if (!dbUsers.includes(selected)) return res(400,{status:'user_not_in_ticket'});
    const rel=b.action==='release';
    const rec={time:now,step:rel?'계정 잠금 해제':'계정 잠금(사람 승인)',user:selected,mode:'dry-run',
      status:'dry-run',label:LABEL['dry-run'],by:'상황판',detail:'dry-run(DB를 바꾸지 않음)',
      undo:rel?'locked_until = NULL (잠금 해제)':'상황판의 "잠금(승인)"으로 다시 잠금'};
    return [{json:{http:200,body:{status:'ok',result:rec,ticket:{...ticket,responses:[...dbResponses,rec].slice(-30)},
      db_ticket_action:{id:dbId,action:'record_response',response:rec}}}];
  }
  if (b.action === 'request_release') {
    const selected=String(b.user||'').trim();
    if (!userOk(selected)) return res(400,{status:'bad_user'});
    sd.seq=(sd.seq||0)+1;
    const request={id:'NX-'+String(sd.seq).padStart(4,'0'),src_ip:ticket.src_ip,type:'오탐·해제 요청',rules:[],
      users:[selected],user:selected,count:1,first_seen:now,last_seen:now,status:'open',linked_ticket:ticket.id,
      reason:String(b.reason||'').slice(0,300)};
    sd.tickets['request:'+request.id]=request;
    return res(200,{status:'ok',ticket:request});
  }
}
'''
    ticket_sql = r'''SET @nexus_new_alert = 0;
SET @nexus_ticket_time = COALESCE(STR_TO_DATE(LEFT(REPLACE(REPLACE(REPLACE($8,'T',' '),'Z',''),'+00:00',''),26), '%Y-%m-%d %H:%i:%s.%f'), UTC_TIMESTAMP(6));
INSERT IGNORE INTO security_incident_alerts
  (alert_id,receipt_id,ticket_id,rule_id,event_type,user_name,src_ip,event_count,occurred_at,event_payload)
VALUES ($1,$2,NULL,$3,$4,$5,$6,$7,@nexus_ticket_time,CAST($9 AS JSON));
SET @nexus_new_alert = ROW_COUNT();
INSERT INTO security_incident_tickets
  (ticket_key,status,src_ip,ticket_type,type_rank,event_count,rule_ids,user_names,first_seen,last_seen,latest_event,responses)
SELECT $10,'open',$6,$11,$12,$7,JSON_ARRAY($3),IF($5='',JSON_ARRAY(),JSON_ARRAY($5)),
       @nexus_ticket_time,@nexus_ticket_time,CAST($9 AS JSON),JSON_ARRAY()
FROM DUAL WHERE @nexus_new_alert=1
ON DUPLICATE KEY UPDATE
  ticket_type=IF(VALUES(type_rank)>type_rank,VALUES(ticket_type),ticket_type),
  type_rank=GREATEST(type_rank,VALUES(type_rank)),
  event_count=event_count+VALUES(event_count),
  rule_ids=IF(JSON_CONTAINS(rule_ids,JSON_QUOTE($3)),rule_ids,JSON_ARRAY_APPEND(rule_ids,'$',$3)),
  user_names=IF($5='',user_names,IF(JSON_CONTAINS(user_names,JSON_QUOTE($5)),user_names,JSON_ARRAY_APPEND(user_names,'$',$5))),
  last_seen=GREATEST(last_seen,VALUES(last_seen)),
  latest_event=VALUES(latest_event);
SET @nexus_ticket_id = IF(@nexus_new_alert=1,
  (SELECT id FROM security_incident_tickets WHERE active_ticket_key=$10 LIMIT 1),NULL);
UPDATE security_incident_alerts SET ticket_id=@nexus_ticket_id WHERE alert_id=$1 AND @nexus_new_alert=1;
SELECT (a.receipt_id=$2) AS ticket_is_new,(a.receipt_id<>$2) AS ticket_duplicate,
       t.id AS ticket_db_id,CONCAT('NX-DB-',LPAD(t.id,6,'0')) AS ticket_id,t.ticket_type,
       t.event_count AS ticket_event_total,t.rule_ids AS ticket_rules,t.user_names AS ticket_users,
       t.status,t.first_seen,t.last_seen,a.alert_id
FROM security_incident_alerts a LEFT JOIN security_incident_tickets t ON t.id=a.ticket_id
WHERE a.alert_id=$1;'''
    list_sql = '''SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
  'id',id,'ticket_key',ticket_key,'status',status,'src_ip',src_ip,'ticket_type',ticket_type,
  'type_rank',type_rank,'event_count',event_count,'rule_ids',rule_ids,'user_names',user_names,
  'first_seen',DATE_FORMAT(first_seen,'%Y-%m-%dT%H:%i:%s.%fZ'),
  'last_seen',DATE_FORMAT(last_seen,'%Y-%m-%dT%H:%i:%s.%fZ'),
  'latest_event',latest_event,'resolution',resolution,'closed_at',closed_at,'note',note,'responses',responses
)),JSON_ARRAY()) AS ticket_rows
FROM (SELECT * FROM security_incident_tickets ORDER BY last_seen DESC LIMIT 500) AS tickets'''
    discord_slot_sql = r'''INSERT IGNORE INTO security_discord_rate_limit(id,next_allowed_at)
VALUES (1,UTC_TIMESTAMP(6));
UPDATE security_discord_rate_limit
SET next_allowed_at=GREATEST(next_allowed_at,UTC_TIMESTAMP(6))+INTERVAL 1 SECOND
WHERE id=1;
SELECT DATE_FORMAT(next_allowed_at,'%Y-%m-%dT%H:%i:%s.%fZ') AS resume_at,$1 AS message
FROM security_discord_rate_limit WHERE id=1;'''

    nodes_to_add = [
        mysql_node("티켓 DB 원자 기록", ticket_sql, "={{ $json.ticket_record.params }}", {"mySql": mysql_credentials}, [2180, 520]),
        {
            "parameters":{"jsCode":merge_ticket_code},"id":node_id("티켓 DB 결과 병합"),"name":"티켓 DB 결과 병합",
            "type":"n8n-nodes-base.code","typeVersion":2,"position":[2400,520]
        },
        {
            "parameters":{"conditions":{"options":{"caseSensitive":True,"leftValue":"","typeValidation":"strict","version":1},
              "conditions":[{"id":"db-ticket-duplicate","leftValue":"={{ !!$json.ticket_duplicate }}","rightValue":"","operator":{"type":"boolean","operation":"true","singleValue":True}}],"combinator":"and"},"options":{}},
            "id":node_id("티켓 DB 중복인가?"),"name":"티켓 DB 중복인가?","type":"n8n-nodes-base.if","typeVersion":2.2,"position":[2620,520]
        },
        mysql_node("상황판 티켓 DB 조회", list_sql, "={{ [] }}", {"mySql": mysql_credentials}, [1020, 1080], batching="single"),
        mysql_node("DB 티켓 대상 조회", ticket_lookup_sql,
          "={{ [JSON.stringify($json.body || {}), $json.response_mode || 'dry-run', $json.live_enabled === true ? 1 : 0, Number($json.lock_minutes) || 15, JSON.stringify(Array.isArray($json.whitelist_ips) ? $json.whitelist_ips : [])] }}",
          {"mySql":mysql_credentials}, [1020,1280],batching="single"),
        {
            "parameters":{"conditions":{"options":{"caseSensitive":True,"leftValue":"","typeValidation":"strict","version":1},
              "conditions":[{"id":"db-ticket-action","leftValue":"={{ !!$json.db_ticket_action }}","rightValue":"","operator":{"type":"boolean","operation":"true","singleValue":True}}],"combinator":"and"},"options":{}},
            "id":node_id("DB 티켓 처리인가?"),"name":"DB 티켓 처리인가?","type":"n8n-nodes-base.if","typeVersion":2.2,"position":[1460,1280]
        },
        mysql_node("DB 티켓 상태 반영", '''UPDATE security_incident_tickets
SET resolution=IF($2 IN ('close','false_positive') AND status='open',$3,resolution),
    closed_at=IF($2 IN ('close','false_positive') AND status='open',UTC_TIMESTAMP(6),closed_at),
    note=IF($2 IN ('close','false_positive') AND status='open',$4,note),
    responses=IF($5 IS NULL,COALESCE(responses,JSON_ARRAY()),
      JSON_ARRAY_APPEND(IF(JSON_LENGTH(COALESCE(responses,JSON_ARRAY()))>=30,
        JSON_REMOVE(COALESCE(responses,JSON_ARRAY()),'$[0]'),COALESCE(responses,JSON_ARRAY())),'$',CAST($5 AS JSON))),
    status=IF($2 IN ('close','false_positive') AND status='open','closed',status)
WHERE id=$1 AND ($2 NOT IN ('close','false_positive') OR status='open');
SET @nexus_ticket_changed=ROW_COUNT();
SELECT @nexus_ticket_changed AS changed,t.id,t.ticket_key,t.status,t.src_ip,t.ticket_type,t.event_count,t.rule_ids,t.user_names,
       t.first_seen,t.last_seen,t.latest_event,t.resolution,t.closed_at,t.note,t.responses
FROM (SELECT 1) AS request LEFT JOIN security_incident_tickets t ON t.id=$1;''',
          "={{ $json.db_ticket_action.params }}", {"mySql":mysql_credentials}, [1680,1370]),
        {
            "parameters":{"jsCode":r'''const plan = $('티켓 처리·화이트리스트').first().json || {};
const row = $input.first().json || {};
const action = plan.db_ticket_action || {};
if (!row.id) return [{json:{http:404,body:{status:'not_found'}}}];
if ((action.action==='close'||action.action==='false_positive') && Number(row.changed||0)===0)
  return [{json:{http:409,body:{status:row.status==='closed'?'already_closed':'conflict'}}}];
const parse=(v,fallback)=>{if(Array.isArray(v)||(v&&typeof v==='object'))return v;if(typeof v==='string'){try{return JSON.parse(v)}catch{}}return fallback};
const ticket={id:`NX-DB-${String(row.id).padStart(6,'0')}`,ticket_key:row.ticket_key,src_ip:row.src_ip||'',type:row.ticket_type,
  rules:parse(row.rule_ids,[]),users:parse(row.user_names,[]),count:Number(row.event_count||0),first_seen:row.first_seen,last_seen:row.last_seen,
  latest:parse(row.latest_event,{}),status:row.status,resolution:row.resolution||undefined,closed_at:row.closed_at||undefined,
  note:row.note||undefined,responses:parse(row.responses,[])};
if(action.whitelist && ticket.src_ip && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ticket.src_ip)){
  const sd=$getWorkflowStaticData('global');sd.whitelist=sd.whitelist||{};
  sd.whitelist[ticket.src_ip]={added_at:new Date().toISOString(),reason:'오탐 '+ticket.id};
}
return [{json:{http:200,body:{status:'ok',ticket}}}];'''},
            "id":node_id("DB 티켓 처리 결과"),"name":"DB 티켓 처리 결과","type":"n8n-nodes-base.code","typeVersion":2,"position":[1900,1370]
        },
    ]

    for index, label in enumerate(("알림", "대응 결과")):
        slot_name=f"Discord 발송 슬롯 예약({label})"
        wait_name=f"Discord 슬롯 대기({label})"
        nodes_to_add.append(mysql_node(slot_name,discord_slot_sql,"={{ [$json.message || 'NEXUS 보안 알림'] }}",{"mySql":mysql_credentials},[2920,200+index*420]))
        nodes_to_add.append({"parameters":{"resume":"specificTime","dateTime":"={{ $json.resume_at }}","options":{}},
          "id":node_id(wait_name),"name":wait_name,"type":"n8n-nodes-base.wait","typeVersion":1.1,
          "position":[3140,200+index*420]})

    _replace_code(node_map,"티켓 기록(출발지별)",prepare_ticket_code)
    _replace_code(node_map,"티켓 목록 만들기",list_tickets_code)
    # Use the provider-prepared database row as the original request input to the existing action code.

    # Persist the per-execution transaction parameters in the ticket-preparation node.
    nodes_to_add[0]["parameters"]["options"]["queryReplacement"] = "={{ $json.ticket_record.params }}"
    prepare_ticket_code = prepare_ticket_code.replace(
        "event_payload: JSON.stringify(safe)\n} } }];",
        "event_payload: JSON.stringify(safe),\n  params: [String(d.graylog_event_id), receiptId, String(d.rule_id), String(event.event_type || ''), String(d.user || ''),\n    String(d.src_ip || ''), eventCount, timestamp, JSON.stringify(safe), String(d.ticket_key), String(d.ticket_type || '보안 경보'),\n    Number(rank[d.ticket_type] || 1)]\n} } }];"
    )
    _replace_code(node_map,"티켓 기록(출발지별)",prepare_ticket_code)

    # DB-ticket actions use the same guarded operator API; legacy tickets keep their original handler.
    action_code = base_action_code
    start = action_code.index("if (b.action === 'close' || b.action === 'false_positive')")
    db_prefix = r'''const parseDbJson = (v, fallback) => {
  if (Array.isArray(v) || (v && typeof v === 'object')) return v;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch {} }
  return fallback;
};
const dbTicketMatch = /^NX-DB-(\d{6})$/.exec(String(b.ticket_id || ''));
if (dbTicketMatch) {
  const dbId=Number(input.ticket_db_id||0);
  if(!dbId)return res(404,{status:'not_found'});
  const users=parseDbJson(input.ticket_db_users,[]), rules=parseDbJson(input.ticket_db_rules,[]);
  const responses=parseDbJson(input.ticket_db_responses,[]);
  const t={id:b.ticket_id,src_ip:String(input.ticket_db_src_ip||''),type:input.ticket_db_type,users,rules,
    count:Number(input.ticket_db_count||0),status:input.ticket_db_status,first_seen:input.ticket_db_first_seen,
    last_seen:input.ticket_db_last_seen,latest:parseDbJson(input.ticket_db_latest,{}),responses};
  const makeAction=(action,resolution=null,note='',response=null,whitelist=false)=>({id:dbId,action,resolution,note,
    response:response?JSON.stringify(response):null,whitelist,whitelist_ip:t.src_ip,
    params:[dbId,action,resolution||'',String(note||'').slice(0,500),response?JSON.stringify(response):null]});
  if(b.action==='close'||b.action==='false_positive'){
    if(t.status==='closed')return res(409,{status:'already_closed'});
    return [{json:{http:200,body:null,db_ticket_action:makeAction(b.action,b.action==='false_positive'?'오탐':'조치 완료',b.note||'',null,b.action==='false_positive'&&b.whitelist===true)}}];
  }
  if(b.action==='release'||b.action==='lock'){
    const selected=String(b.user||(users.length===1?users[0]:'')).trim();
    if(!userOk(selected))return res(400,{status:'bad_user'});
    if(!users.includes(selected))return res(400,{status:'user_not_in_ticket'});
    const rel=b.action==='release';
    const rec={time:now,step:rel?'계정 잠금 해제':'계정 잠금(사람 승인)',user:selected,mode:'dry-run',status:'dry-run',
      label:LABEL['dry-run'],by:'상황판',detail:'dry-run(DB를 바꾸지 않음)',undo:rel?'locked_until = NULL (잠금 해제)':'상황판의 "잠금(승인)"으로 다시 잠금'};
    return [{json:{http:200,body:{status:'ok',result:rec,ticket:{...t,responses:[...responses,rec].slice(-30)}},
      db_ticket_action:makeAction('record_response',null,'',rec)}}];
  }
  if(b.action==='request_release'){
    const selected=String(b.user||'').trim();if(!userOk(selected))return res(400,{status:'bad_user'});
    sd.seq=(sd.seq||0)+1;const req={id:'NX-'+String(sd.seq).padStart(4,'0'),src_ip:t.src_ip,type:'오탐·해제 요청',rules:[],
      users:[selected],user:selected,count:1,first_seen:now,last_seen:now,status:'open',linked_ticket:t.id,reason:String(b.reason||'').slice(0,300)};
    sd.tickets['request:'+req.id]=req;return res(200,{status:'ok',ticket:req});
  }
}
'''
    action_code = action_code[:start] + db_prefix + action_code[start:]
    _replace_code(node_map,"티켓 처리·화이트리스트",action_code)

    # Use the action plan's bounded values in the existing MySQL v2 parameterized query node.
    nodes_to_add[6]["parameters"]["options"]["queryReplacement"] = "={{ $json.db_ticket_action.params }}"
    # The formatted result merges the action request from the source Code node.
    # Add the node and connections below, after the original code node.

    workflow["nodes"].extend(nodes_to_add)
    for discord_name in ("Discord 알림", "대응 결과 알림"):
        discord_node = node_map[discord_name]
        discord_node["retryOnFail"] = True
        discord_node["maxTries"] = 3
        discord_node["waitBetweenTries"] = 5000
    conns = workflow["connections"]
    # Ticket storage replaces only the prior staticData write path; legacy static tickets remain readable.
    replace_edge(conns,"화이트리스트 제외?","응답 200(티켓 기록 후 접수)","티켓 DB 원자 기록",output=1)
    edge(conns,"티켓 DB 원자 기록","티켓 DB 결과 병합")
    edge(conns,"티켓 DB 결과 병합","티켓 DB 중복인가?")
    edge(conns,"티켓 DB 중복인가?","응답(중복·fallback·화이트리스트)",output=0)
    edge(conns,"티켓 DB 중복인가?","응답 200(티켓 기록 후 접수)",output=1)
    # Replace old duplicate path: the DB primary key is the authoritative dedup source.
    # The upstream static snapshot is read-only and can only short-circuit legacy duplicate IDs.
    # Ticket list and action handlers read/write the persistent table for new DB-backed tickets.
    replace_edge(conns,"NEXUS 안전 설정(조회)","티켓 목록 만들기","상황판 티켓 DB 조회")
    edge(conns,"상황판 티켓 DB 조회","티켓 목록 만들기")
    replace_edge(conns,"NEXUS 안전 설정(티켓 처리)","티켓 처리·화이트리스트","DB 티켓 대상 조회")
    edge(conns,"DB 티켓 대상 조회","티켓 처리·화이트리스트")
    replace_edge(conns,"티켓 처리·화이트리스트","계정 조치 실행?","DB 티켓 처리인가?")
    edge(conns,"DB 티켓 처리인가?","DB 티켓 상태 반영",output=0)
    edge(conns,"DB 티켓 처리인가?","계정 조치 실행?",output=1)
    edge(conns,"DB 티켓 상태 반영","DB 티켓 처리 결과")
    edge(conns,"DB 티켓 처리 결과","응답(처리 결과)")
    # Discord slot reservation serializes across concurrent executions on every workflow branch.
    replace_edge(conns,"Discord 설정됨?","Discord 알림","Discord 발송 슬롯 예약(알림)")
    edge(conns,"Discord 발송 슬롯 예약(알림)","Discord 슬롯 대기(알림)")
    edge(conns,"Discord 슬롯 대기(알림)","Discord 알림")
    replace_edge(conns,"결과를 Discord로?","대응 결과 알림","Discord 발송 슬롯 예약(대응 결과)")
    edge(conns,"Discord 발송 슬롯 예약(대응 결과)","Discord 슬롯 대기(대응 결과)")
    edge(conns,"Discord 슬롯 대기(대응 결과)","대응 결과 알림")

    # Wrap the existing code's normalized event with DB parameters after its whitelist gate.
    # Since the first SQL node receives the Code node result, params are built here.
    # (Keeping this as an expression avoids putting raw values into SQL.)
    # Add computed params in the preparation code itself.
    prepare_ticket_code = prepare_ticket_code.replace(
        "event_payload: JSON.stringify(safe)\n} } }];",
        "event_payload: JSON.stringify(safe), params: [String(d.graylog_event_id), receiptId, String(d.rule_id), String(event.event_type || ''), String(d.user || ''), String(d.src_ip || ''), eventCount, timestamp, JSON.stringify(safe), String(d.ticket_key), String(d.ticket_type || '보안 경보'), Number(rank[d.ticket_type] || 1)]\n} } }];"
    )
    _replace_code(node_map,"티켓 기록(출발지별)",prepare_ticket_code)

    # The DB-action result node uses the action plan before it is passed to Respond to Webhook.
    # Preserve the incoming body for legacy ticket behavior by returning a stable one-row lookup record.
    workflow["active"] = False
    OUT.write_text(json.dumps(workflow, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return workflow


def validate(workflow: dict) -> None:
    nodes = workflow["nodes"]
    ids = [n["id"] for n in nodes]
    names = [n["name"] for n in nodes]
    if len(ids) != len(set(ids)) or len(names) != len(set(names)):
        raise ValueError("duplicate node id or name")
    by_name = set(names)
    for source, connection in workflow["connections"].items():
        if source not in by_name:
            raise ValueError(f"missing connection source {source}")
        for output in connection.get("main", []):
            for edge_data in output:
                if edge_data["node"] not in by_name:
                    raise ValueError(f"dangling connection to {edge_data['node']}")
    if workflow.get("active") is not False:
        raise ValueError("candidate must remain inactive")
    settings = next(n for n in nodes if n["name"] == "NEXUS 안전 설정(수신)")["parameters"]["assignments"]["assignments"]
    values = {item["name"]: item["value"] for item in settings}
    if values.get("response_mode") != "dry-run" or values.get("live_enabled") is not False or values.get("discord_enabled") is not True:
        raise ValueError("safety settings changed")
    if not {"nexus-alert", "nexus-tickets", "nexus-ticket-action"}.issubset(
        {str(n.get("parameters", {}).get("path", "")).lstrip("/") for n in nodes if n["type"].endswith(".webhook")}
    ):
        raise ValueError("webhook paths changed")


if __name__ == "__main__":
    workflow = build()
    validate(workflow)
    print(f"candidate={OUT}")
    print(f"nodes={len(workflow['nodes'])}; active={workflow['active']}; credential references preserved")
