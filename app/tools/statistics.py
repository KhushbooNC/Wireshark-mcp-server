from app.utils.tshark import run_tshark
from app.config import settings


async def protocol_statistics(pcap_path: str):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-q",
        "-z",
        "io,stat,1"
    ]

    output = run_tshark(cmd)

    return {
        "statistics": output
    }