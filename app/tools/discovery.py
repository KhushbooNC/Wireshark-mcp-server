from app.utils.tshark import run_tshark
from app.config import settings


async def discover_protocols(pcap_path: str):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        "io,phs"
    ]

    output = run_tshark(cmd)

    return {
        "protocol_hierarchy": output
    }