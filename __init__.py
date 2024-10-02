import os
import logging
import json
from slack_sdk import WebClient
from datetime import datetime, timedelta
import azure.functions as func
from slack_sdk.errors import SlackApiError

# Predefined target channel ID
PREDEFINED_TARGET_CHANNEL_ID = "C9E8BH8JV"

# Channel ID for listening and posting
LISTEN_AND_POST_CHANNEL_ID = "C076FD9V010"  

# Initializing the Slack client and bot ID
slack_token = os.environ.get("SLACK_BOT_TOKEN_MESSAGE")
client = WebClient(slack_token)
bot_id = client.api_call("auth.test")['user_id']

# Function to fetch conversation history for a specific channel within a date range
def get_conversation_history(client, channel_id, latest, oldest):
    all_messages = []
    try:
        result = client.conversations_history(
            channel=channel_id,
            inclusive=True,
            latest=latest,
            oldest=oldest,
            limit=100
        )
        all_messages = result["messages"]
        while result.get('has_more'):
            result = client.conversations_history(
                channel=channel_id,
                cursor=result['response_metadata']['next_cursor'],
                latest=latest,
                oldest=oldest,
                limit=100
            )
            all_messages += result["messages"]

        thread_messages = [msg for msg in all_messages if 'thread_ts' in msg]
        for thread in thread_messages:
            replies = client.conversations_replies(
                channel=channel_id,
                ts=thread['thread_ts'],
                inclusive=True,
                latest=latest,
                oldest=oldest,
                limit=100
            )
            all_messages += [reply for reply in replies["messages"] if reply not in all_messages]

    except SlackApiError as e:
        logging.error(f"Error retrieving conversation history: {e}")
        raise e

    return all_messages

def get_user_message_count(client, target_user_ids, latest, oldest):
    conversation_history = get_conversation_history(client, PREDEFINED_TARGET_CHANNEL_ID, latest, oldest)
    message_counts = {user_id: 0 for user_id in target_user_ids}
    for message in conversation_history:
        user_id = message.get('user')
        if user_id in target_user_ids:
            message_counts[user_id] += 1
    return message_counts

def parse_dates_and_users_from_message(message_text):
    try:
        parts = message_text.split()
        if len(parts) < 6 or 'from' not in parts or 'to' not in parts:
            return None, None, None, "Invalid command format. Usage: check @target_user_id1 @target_user_id2 ... from YYYY-MM-DD to YYYY-MM-DD"
        
        from_index = parts.index('from')
        to_index = parts.index('to')
        
        user_mentions = parts[1:from_index]
        if not user_mentions:
            return None, None, None, "No target user IDs provided."
        
        target_user_ids = [mention.strip('<@').strip('>') for mention in user_mentions]
        
        date_from = datetime.strptime(parts[from_index + 1], "%Y-%m-%d")
        date_to = datetime.strptime(parts[to_index + 1], "%Y-%m-%d")
        
        if date_from > date_to:
            return None, None, None, "Invalid date range. The start date must be earlier than the end date."
        
        return target_user_ids, date_from, date_to, None
    except ValueError as e:
        logging.error(f"Error parsing dates: {e}")
        return None, None, None, "Invalid date format. Use YYYY-MM-DD"

# Global set to track processed events
processed_events = set()

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        event_type = req_body.get('event', {}).get('type')
        


    except ValueError:
        return func.HttpResponse("Invalid JSON in request body", status_code=400)

    logging.info(f"Received event: {event_type}")

    if event_type == 'url_verification':
        challenge = req_body.get('challenge')
        if challenge:
            response_data = {"challenge": challenge}
            logging.info(f"Challenge passed! Challenge: {challenge}")
            return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")

    elif event_type == 'message' :
        event_id = req_body.get('event_id')
        if event_id in processed_events:
            logging.info(f"Event {event_id} already processed.")
            return func.HttpResponse("Event already processed.", status_code=200)
        
        processed_events.add(event_id)#for tracking the events and making sure it won't be repeated 

        channel_id = req_body.get('event', {}).get('channel')
        if channel_id != LISTEN_AND_POST_CHANNEL_ID:
            logging.info(f"Event is not from the specified channel: {LISTEN_AND_POST_CHANNEL_ID}")
            return func.HttpResponse("Event is not from the specified channel. ", status_code=200)
        
        user_id = req_body.get('event', {}).get('user')
        message_text = req_body.get('event', {}).get('text', '')

        if user_id and bot_id != user_id:
            if 'check' in message_text.lower():
                target_user_ids, date_from, date_to, error_message = parse_dates_and_users_from_message(message_text)
                if error_message:
                    client.chat_postMessage(channel=channel_id, text=error_message)
                    return func.HttpResponse(error_message, status_code=400)
                
                oldest = date_from.timestamp()
                latest = date_to.timestamp()

                try:
                    message_counts = get_user_message_count(client, target_user_ids, latest, oldest)
                except SlackApiError as e:
                    logging.error(f"Error retrieving user message count: {e}")
                    return func.HttpResponse(f"Error retrieving user message count: {e}", status_code=500)

                response_text = "\n".join(
                    [f"The user <@{user_id}> has sent {count} messages in the channel <#{PREDEFINED_TARGET_CHANNEL_ID}> from {date_from.strftime('%Y-%m-%d')} to {date_to.strftime('%Y-%m-%d')}" 
                    for user_id, count in message_counts.items()]
                )
                client.chat_postMessage(channel=channel_id, text=response_text)

                logging.info(f"Messages sent by {target_user_ids} from {date_from} to {date_to}: {message_counts}")

                return func.HttpResponse("Event handled successfully", status_code=200)
        else:
            logging.warning("User ID is not provided in the message event.")
            return func.HttpResponse("User ID is not provided in the message event.", status_code=400)

    else:
        logging.info(f"Received unrecognized event type: '{event_type}'")