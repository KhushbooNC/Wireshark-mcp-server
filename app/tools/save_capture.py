import os
import shutil


async def save_capture(
    temporary_capture: str
):

    if not os.path.exists(temporary_capture):

        return {

            "status": "error",

            "message": (
                "Temporary capture file not found."
            )
        }

    filename = os.path.basename(
        temporary_capture
    )

    final_name = filename.replace(
        "temp_capture",
        "saved_capture"
    )

    final_path = os.path.join(

        os.path.dirname(temporary_capture),

        final_name
    )

    shutil.move(
        temporary_capture,
        final_path
    )

    return {

        "status": "success",

        "saved_capture": final_path
    }