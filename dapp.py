from os import environ
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

rollup_server = environ.get("ROLLUP_HTTP_SERVER_URL")
logger.info(f"HTTP rollup_server url is {rollup_server}")


def hex2str(hex_value):
    if hex_value.startswith('0x'):
        hex_value = hex_value[2:]
    try:
        byte_data = bytes.fromhex(hex_value)
        string_data = byte_data.decode('utf-8')
        return string_data
    except ValueError:
        return None


def str2hex(payload):
    if isinstance(payload, str):
        return payload.encode('utf-8').hex()
    else:
        raise TypeError("Input must be a string")


users = []
to_upper_total = 0


def handle_advance(data):
    global to_upper_total
    logger.info(f"Received advance request data {data}")
    meta_data = data['metadata']
    sender = meta_data['msg_sender']
    payload = data['payload']

    sentence = hex2str(payload)
    if sentence is None:
        report_req = requests.post(rollup_server + "/report", json={'payload': str2hex('Invalid hex format')})
        return 'reject'

    users.append(sender)
    to_upper_total += 1
    sentence_upper = sentence.upper()
    notice_req = requests.post(rollup_server + "/notice", json={'payload': str2hex(sentence_upper)})

    return "accept"


def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    payload = data['payload']
    route = hex2str(payload)

    if route == 'users':
        resp_obj = str(users)
    elif route == 'list':
        resp_obj = str(to_upper_total)
    else:
        resp_obj = 'route not implemented.'

    report_req = requests.post(rollup_server + "/report", json={'payload': '0x'+str2hex(resp_obj)})

    return "accept"


handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
