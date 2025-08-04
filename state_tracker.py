from collections import defaultdict, deque

class IPStateTracker:
    def __init__(self, maxlen=20):  #ip 별로 최대 20개의 이벤트 저장
        self.states = defaultdict(lambda: deque(maxlen=maxlen))

    def add_event(self, ip, event_type, ts): #ip 별로 이벤트 타입과 타임스탬프를 함께 튜플로 만들어 추가
        self.states[ip].append((event_type, ts))

    def has_sequence(self, ip, sequence, within_seconds): #ip 별로 지정된 패턴과 일치하는 이벤트 타입이 지정된 시간 안에 기록되었는지 확인
        events = list(self.states[ip])
        if len(events) < len(sequence):
            return False
        #슬라이딩 윈도우로 최근 이벤트에서 시퀀스 체크
        for i in range(len(events) - len(sequence) + 1):
            match = True
            base_ts = events[i][1]
            for j, expected in enumerate(sequence):
                if events[i+j][0] != expected:
                    match = False
                    break
            if match and events[i+len(sequence)-1][1] - base_ts <= within_seconds:
                return True
        return False