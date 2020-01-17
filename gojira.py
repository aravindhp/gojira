import os
import time
import re
import certifi
import ssl as ssl_lib
from slack import RTMClient

@RTMClient.run_on(event="message")
def say_hello(**payload):
    data = payload.get('data')
    if not data:
        return

    web_client = payload.get('web_client')
    if not web_client:
        return

    text = data.get('text')
    if not text:
        return

    if 'Hello' in text:
        channel_id = data.get('channel')
        if not channel_id:
            return

        thread_ts = data.get('ts')
        if not thread_ts:
            return

        user = data.get('user')
        if not user:
            return

        web_client.chat_postMessage(
        channel=channel_id,
        text=f"Hi <@{user}>!",
        thread_ts=thread_ts
        )

if __name__ == "__main__":
    ssl_context = ssl_lib.create_default_context(cafile=certifi.where())
    slack_token = os.environ["SLACK_BOT_TOKEN"]
    rtm_client = RTMClient(token=slack_token, ssl=ssl_context)
    rtm_client.start()
