from typing import Optional
from discord_webhook import DiscordWebhook
from .logger import Logger

logger = Logger().get_logger()


def send_hook(hook_url: Optional[str], msg: any):
    """Send a discord webhook, never throws an exception.

    Always logs the message to the console, will only send the hook if hook_url is provided.
    """
    try:
        logger.info(f'sending hook: {msg}')
        if hook_url:
            DiscordWebhook(url=hook_url, content=str(msg),
                           rate_limit_retry=True, timeout=5).execute()
    except Exception as ex:
        logger.info(f'failed to send hook: {ex}')
