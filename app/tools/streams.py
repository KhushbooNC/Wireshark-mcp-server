from app.utils.tshark import run_tshark
from app.config import settings


async def inspect_stream(
    pcap_path: str,
    stream_type: str,
    stream_id: int
):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        f"follow,{stream_type},ascii,{stream_id}"
    ]

    output = run_tshark(cmd)

    return {
        "stream_data": output
    }