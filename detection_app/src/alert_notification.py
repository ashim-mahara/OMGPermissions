import os
import json
import logging
import urllib.request
import dotenv

dotenv.load_dotenv()


class SlackNotifier:
    def __init__(self, webhook_url: str | None = None, timeout: int = 10):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.timeout = timeout
        if not self.webhook_url:
            logging.warning("SlackNotifier disabled: no webhook URL provided.")

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def send(self, text: str, blocks: list[dict] | None = None):
        if not self.enabled():
            return
        payload = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status >= 300:
                    logging.error(f"Slack webhook failed: {resp.status} {resp.read()}")
        except Exception as e:
            logging.error(f"Slack webhook error: {e}")
