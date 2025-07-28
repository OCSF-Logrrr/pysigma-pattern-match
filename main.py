#!/usr/bin/env python3

import os, sys, time, json, re
from pathlib import Path
from dotenv import load_dotenv
from yaml.loader import SafeLoader
from yaml.constructor import SafeConstructor
from elasticsearch import Elasticsearch
from state_tracker import IPStateTracker
from rule_manager import RuleManager
from notifier import Notifier
from datetime import datetime

print(f"🚀 running {__file__} with {sys.executable}")

#pattern 디렉토리의 json 파일 읽어오기
def load_patterns(pattern_dir):
    patterns = []
    for p in Path(pattern_dir).glob("*.json"):
        try:
            with open(p) as f:
                patterns.append(json.load(f))
        except Exception as e:
            print(f"[PATTERN] load error {p}: {e}")
    return patterns

#id 값의 숫자가 문자열로 들어오도록
SafeLoader.add_constructor(
    "tag:yaml.org,2002:timestamp",
    lambda loader, node: loader.construct_scalar(node)
)
SafeConstructor.yaml_constructors.pop("tag:yaml.org,2002:timestamp", None)

#환경 변수 load
load_dotenv(".env")

#elasticsearch 관련 환경 변수
ES_URL = os.environ["ES_URL"]
ES_USER = os.environ["ES_USER"]
ES_PASS = os.environ["ES_PASS"]

#Sigma Rules, 시나리오 패턴 파일이 위치한 디렉토리 환경 변수
RULE_BASE = Path(os.environ["RULE_BASE"]).expanduser()
PATTERN_BASE = Path(os.environ["PATTERN_BASE"]).expanduser()

#Slack 관련 환경 변수
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHAN = os.environ["SLACK_DEFAULT_CHAN"]

#Sigma Rules에 level 정의가 없다면 INFO 반환 (아닌경우 Sigma Rules에 정의된 level로 반환)
def level_text(lv):
    if lv is None: 
        return "INFO"
    return str(lv).upper()

#날짜 마이크로초 제거
def parse_ts(ts):
    if isinstance(ts, (int, float)):
        return ts
    try:
        return int(datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").timestamp())
    except:
        return int(time.time()) 

#sigma rules의 tag의 event_type. 뒤를 추출하여 반환
def get_event_type(hit, rule=None):
    if rule and hasattr(rule, "tags"):
        for tag in rule.tags:
            tag_str = str(tag)
            if tag_str.startswith("event_type."):
                return tag_str.split(".", 1)[1].strip()
    return None

#문자열 따옴표 처리 (ES에서 에러 안나게)
def quote_lucene_values(lucene: str):
    def replacer(match):
        field, value = match.group(1), match.group(2)
        if value.startswith('"') and value.endswith('"'):
            return f"{field}:{value}"
        if re.fullmatch(r'\d+(\.\d+)?', value) or value in ("true", "false"):
            return f"{field}:{value}"
        return f'{field}:"{value}"'
    return re.sub(r'(\w+(?:\.\w+)*):([^\s]+)', replacer, lucene)


recent_alerts = {} #중복 기록 딕셔너리
ALERT_INTERVAL = 600 #중복 알림이 발생하지 않는 시간

def main():
    #Elasticsearch 접속 객체
    es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS),
                       verify_certs=False, ssl_show_warn=False)
    
    #IP별 이벤트 관리 객체 (state_tracker.py에 정의되어 있음)
    ip_tracker = IPStateTracker()
    
    #Sigma Rules 관리 객체 (rule_manager.py에 정의되어 있음)
    mgr = RuleManager(RULE_BASE)
    
    #Slack에 알림을 보내는 객체 (notifier.py에 정의되어 있음)
    notifier = Notifier(SLACK_BOT_TOKEN, SLACK_CHAN)
    
    #set 자료구조 선언 (중복 방지)
    seen = set()
    
    #Elasticsearch의 로그 탐지 주기
    POLL = 15
    
    #시나리오 탐지 패턴 관리 객체
    patterns = load_patterns(PATTERN_BASE)
    
    while True:
        now = int(time.time()) #현재 시간 저장
        
        #패턴 이벤트 발생 후 저장되는 시간을 현재 시간에서 뺀 값이 특정 시간 이상이면 해당 로그들 삭제
        for k in list(recent_alerts):
            if now - recent_alerts[k] > ALERT_INTERVAL:
                del recent_alerts[k]
        
        start = time.time() #시작 시간 저장
        
        
        for title, lucene, rule in mgr.snapshot(): #sigma rules 리스트를 각 변수에 저장
            lucene_fixed = quote_lucene_values(lucene) #문자열 따옴표 처리 (ES에서 에러 안나게)
            
            #ocsf-log index에 lucene 쿼리 전송 후 결과 값 저장
            try:
                res = es.search(index="ocsf-log", body={
                    "size": 10,
                    "sort": [{"@timestamp": "asc"}],
                    "query": {"query_string": {"query": lucene_fixed}}
                })
            except Exception as e:
                print(f"[ES] {title} search error: {e}")
                continue
            
            for hit in res["hits"]["hits"]: #검색된 로그 배열을 하나씩 불러와 저장
                uid = hit["_id"] #개별 로그의 _id(고유한 값임)
                if uid in seen: continue #중복의 경우 종료
                seen.add(uid) #처리된 로그의 _id 저장

                src   = hit.get("_source", {}) #로그의 모든 필드 저장
                ts    = src.get("@timestamp", "N/A") #로그의 @timestamp 필드 저장
                ua    = src.get('http_request', {}).get('user_agent', 'N/A') #로그의 http_request의 user agent 저장
                ip    = src.get("src_endpoint", {}).get("ip", "N/A") #로그의 src_endpoint의 ip 저장
                path  = src.get("http_request", {}).get("url", {}).get("path", "N/A") #로그의 http_request의 url, path 저장
                uid_c = src.get("class_uid", "N/A") #로그의 class_uid 필드 저장
                sev   = level_text(getattr(rule, "level", None)) #rules의 level 저장
                event_type = get_event_type(hit, rule) #ruels의 event_type을 반환
                if not event_type: continue #event_type이 반환되지 않으면 종료

                ip_tracker.add_event(ip, event_type, parse_ts(ts)) #ip별로 event_type과 시간을 추가

                for pattern in patterns: #패턴과 일치하는 이벤트 탐지
                    key = (ip, pattern["name"]) #ip와 패턴 이름 저장
                    now = int(time.time()) #현재 시간 저장
                    last_alert = recent_alerts.get(key, 0) #해당 Ip와 패턴 이름으로 발생한 마지막 이벤트 시간을 가져옴
                    if now - last_alert < ALERT_INTERVAL: continue #10분이 넘지 않은 시간에 발생했었다면 알림을 보내지 않고 종료

                    if ip_tracker.has_sequence(ip, pattern["sequence"], pattern["within_seconds"]): #특정 ip로 특정 시간이내에 event_type 리스트와 일치하는 동작을 했다면
                        # if len(fields) % 2: #위의 필드가 홀수일 때 켜두기
                        #     fields.append({"type": "mrkdwn", "text": " "})
                        
                        #slack에 출력될 알림 블록
                        blocks = [
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": f"🚨 {pattern['name']} 🚨",
                                    "emoji": True
                                }
                            },
                            {"type": "divider"},
                            {
                                "type": "section",
                                "fields": [
                                    {"type": "mrkdwn", "text": f"*🕒 Time:*\n`{ts}`"},
                                    {"type": "mrkdwn", "text": f"*🌐 Client IP:*\n`{ip}`"},
                                    {"type": "mrkdwn", "text": f"*🛠️ User-Agent:*\n`{ua}`"},
                                    {"type": "mrkdwn", "text": f"*🧩 Pattern:*\n`{pattern['sequence']}`"},
                                ]
                            },
                            {"type": "divider"},
                            {
                                "type": "context",
                                "elements": [
                                    {"type": "mrkdwn", "text": f"🚩 *WHS 3th - Logrr OCSF 시나리오 탐지 시스템* | 탐지 시각: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"}
                                ]
                            }
                        ]

                        try:
                            notifier.send(blocks=blocks) #블록을 포함하여 알림 전송
                            print("[DETECT] :", pattern["name"]) #콘솔에도 로그 남도록
                            recent_alerts[key] = now #알림 발생 시간 갱신
                        except Exception as e:
                            print(f"[SLACK] error : {e}")
                        break

        if len(seen) > 20000: #senn의 크기(저장된 로그)들의 크기가 20000이 넘으면
            seen = set(list(seen)[-10000:]) #가장 최근 10000개만 남기고 삭제
        time.sleep(max(1, POLL - (time.time() - start)))

if __name__ == "__main__":
    main()
