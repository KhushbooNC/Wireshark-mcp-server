import subprocess

from app.config import settings


def run_tshark(cmd: list):

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=settings.MAX_TIMEOUT
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return result.stdout