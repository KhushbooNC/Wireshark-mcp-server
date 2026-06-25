from pathlib import Path

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):

    # Wireshark / Tshark
    TSHARK_PATH: str = "tshark"

    # Processing limits
    MAX_TIMEOUT: int = 120
    MAX_PACKETS: int = 5000

    # HTTP transport
    HTTP_HOST: str = "0.0.0.0"
    HTTP_PORT: int = 8080
    HTTP_TIMEOUT: int = 60

    # Capture configuration
    DEFAULT_CAPTURE_DURATION: int = 10
    MAX_CAPTURE_SIZE_MB: int = 500

    # Logging
    LOG_LEVEL: str = "INFO"

    # Storage
    CAPTURE_DIR: str = str(
        BASE_DIR / "captures"
    )

    LOG_DIR: str = str(
        BASE_DIR / "logs"
    )

    # Environment loading
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()


# Auto-create directories
Path(
    settings.CAPTURE_DIR
).mkdir(
    parents=True,
    exist_ok=True
)

Path(
    settings.LOG_DIR
).mkdir(
    parents=True,
    exist_ok=True
)