from slack_sdk import WebClient

class Notifier:
    def __init__(self, slack_token, default_chan): #Slack 객체 생성
        self.slack = WebClient(token=slack_token)
        self.channel = default_chan

    def send(self, blocks=None): #Slack에 보낼 메시지 형식 블록을 인자값으로 받아옴
        try: #메시지 전송 요청
            resp = self.slack.chat_postMessage(
                channel=self.channel, #채널 명
                blocks=blocks #메시지 형식
            )
            return resp
        except Exception as e: #에러 디버깅
            print(f"[SLACK] send error: {e}")
            return None