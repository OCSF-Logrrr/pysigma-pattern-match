from slack_sdk import WebClient

class Notifier:
    def __init__(self, slack_token, default_chan):
        self.slack = WebClient(token=slack_token)
        self.channel = default_chan

    def send(self, blocks=None):
        try:
            resp = self.slack.chat_postMessage(
                channel=self.channel,
                blocks=blocks
            )
            return resp
        except Exception as e:
            print(f"[SLACK] send error: {e}")
            return None