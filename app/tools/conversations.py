from app.utils.tshark import run_tshark
from app.config import settings


async def analyze_conversations(
    pcap_path: str,
    conversation_type: str = "ip"
):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        f"conv,{conversation_type}"
    ]

    output = run_tshark(cmd)

    return {
        "conversation_type": conversation_type,
        "data": output
    }