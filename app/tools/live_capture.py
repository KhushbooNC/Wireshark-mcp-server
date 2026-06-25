import json
import os
from datetime import datetime

from app.utils.tshark import run_tshark
from app.config import settings


async def live_capture(
    interface: str = None,
    duration: int = 10,
    capture_filter: str = None,
    save_capture: bool = False
):

    # ---------------------------------------------------
    # Get Available Interfaces
    # ---------------------------------------------------

    list_cmd = [
        settings.TSHARK_PATH,
        "-D"
    ]

    interface_output = run_tshark(list_cmd)

    available_interfaces = []

    for line in interface_output.splitlines():

        line = line.strip()

        if line:

            available_interfaces.append(line)

    # ---------------------------------------------------
    # Ask User to Select Interface
    # ---------------------------------------------------

    if not interface:

        return {

            "status": "user_input_required",

            "message": (
                "Multiple interfaces are available. "
                "Select one for live capture."
            ),

            "available_interfaces": available_interfaces
        }

    # ---------------------------------------------------
    # Validate Interface
    # ---------------------------------------------------

    matched_interface = None

    for item in available_interfaces:

        if (
            interface.lower() in item.lower()
            or item.startswith(interface)
        ):

            matched_interface = item
            break

    if not matched_interface:

        return {

            "status": "invalid_interface",

            "message": "Invalid interface selected.",

            "available_interfaces": available_interfaces
        }

    interface_id = matched_interface.split(".", 1)[0]

    # ---------------------------------------------------
    # Temporary Capture File
    # ---------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    temp_pcap = os.path.join(
        settings.CAPTURE_DIR,
        f"temp_capture_{timestamp}.pcapng"
    )

    # ---------------------------------------------------
    # Capture Command
    # ---------------------------------------------------

    capture_cmd = [

        settings.TSHARK_PATH,

        "-i",
        interface_id,

        "-a",
        f"duration:{duration}",

        "-w",
        temp_pcap
    ]

    if capture_filter:

        capture_cmd.extend([
            "-f",
            capture_filter
        ])

    # ---------------------------------------------------
    # Start Capture
    # ---------------------------------------------------

    run_tshark(capture_cmd)

    # ---------------------------------------------------
    # Analyze Capture
    # ---------------------------------------------------

    analysis_cmd = [

        settings.TSHARK_PATH,

        "-r",
        temp_pcap,

        "-T",
        "json"
    ]

    output = run_tshark(analysis_cmd)

    try:

        packets = json.loads(output)

    except Exception as e:

        return {

            "status": "error",

            "message": (
                "Failed to parse tshark JSON output."
            ),

            "error": str(e)
        }

    # ---------------------------------------------------
    # Dynamic Analysis
    # ---------------------------------------------------

    protocol_counter = {}

    conversations = {}

    endpoints = {}

    total_packets = 0

    total_bytes = 0

    for packet in packets:

        total_packets += 1

        layers = (
            packet
            .get("_source", {})
            .get("layers", {})
        )

        # ------------------------------------------------
        # Frame Information
        # ------------------------------------------------

        frame_layer = layers.get("frame", {})

        try:

            frame_len = int(
                frame_layer.get(
                    "frame.len",
                    0
                )
            )

            total_bytes += frame_len

        except Exception:

            pass

        # ------------------------------------------------
        # Protocol Discovery
        # ------------------------------------------------

        frame_protocols = (
            frame_layer
            .get("frame.protocols", "")
        )

        for proto in frame_protocols.split(":"):

            proto = proto.lower().strip()

            if proto:

                protocol_counter[proto] = (

                    protocol_counter.get(proto, 0) + 1
                )

        # ------------------------------------------------
        # Conversation Tracking
        # ------------------------------------------------

        ip_layer = layers.get("ip")

        ipv6_layer = layers.get("ipv6")

        src = None
        dst = None

        if ip_layer:

            src = ip_layer.get("ip.src")

            dst = ip_layer.get("ip.dst")

        elif ipv6_layer:

            src = ipv6_layer.get("ipv6.src")

            dst = ipv6_layer.get("ipv6.dst")

        if src and dst:

            key = f"{src} -> {dst}"

            conversations[key] = (

                conversations.get(key, 0) + 1
            )

            endpoints[src] = (
                endpoints.get(src, 0) + 1
            )

            endpoints[dst] = (
                endpoints.get(dst, 0) + 1
            )

    # ---------------------------------------------------
    # Top Conversations
    # ---------------------------------------------------

    top_conversations = sorted(

        conversations.items(),

        key=lambda x: x[1],

        reverse=True

    )[:10]

    # ---------------------------------------------------
    # Top Endpoints
    # ---------------------------------------------------

    top_endpoints = sorted(

        endpoints.items(),

        key=lambda x: x[1],

        reverse=True

    )[:10]

    # ---------------------------------------------------
    # Dynamic Behavioral Metadata
    # ---------------------------------------------------

    analysis_metadata = {

        "unique_protocols": list(
            protocol_counter.keys()
        ),

        "protocol_counts": protocol_counter,

        "conversation_count": len(conversations),

        "endpoint_count": len(endpoints),

        "top_conversations": top_conversations,

        "top_endpoints": top_endpoints,

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "capture_duration": duration
    }

    # ---------------------------------------------------
    # Save Capture If Requested
    # ---------------------------------------------------

    if save_capture:

        final_pcap = os.path.join(

            settings.CAPTURE_DIR,

            f"live_capture_{timestamp}.pcapng"
        )

        os.rename(
            temp_pcap,
            final_pcap
        )

        return {

            "status": "success",

            "capture_saved": True,

            "saved_capture": final_pcap,

            "interface": matched_interface,

            "analysis_metadata": analysis_metadata
        }

    # ---------------------------------------------------
    # Ask User Whether To Save
    # ---------------------------------------------------

    return {

        "status": "user_input_required",

        "message": (
            "Live capture analysis completed. "
            "Do you want to save this capture?"
        ),

        "capture_saved": False,

        "temporary_capture": temp_pcap,

        "interface": matched_interface,

        "analysis_metadata": analysis_metadata,

        "save_options": [
            "yes",
            "no"
        ]
    }