from app.utils.tshark import run_tshark
from app.config import settings


async def query_packets(
    pcap_path: str,
    fields: list,
    display_filter: str = None,
    limit: int = 100
):

    cmd = [
        settings.TSHARK_PATH,
        "-r",
        pcap_path,
        "-T",
        "fields"
    ]

    for field in fields:
        cmd.extend([
            "-e",
            field
        ])

    if display_filter:
        cmd.extend([
            "-Y",
            display_filter
        ])

    cmd.extend([
        "-E",
        "separator=|",
        "-c",
        str(limit)
    ])

    output = run_tshark(cmd)

    rows = []

    for line in output.splitlines():
        rows.append(line.split("|"))

    return {
        "fields": fields,
        "rows": rows
    }