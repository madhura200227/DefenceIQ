"""DefenceIQ Backend Configuration & Environment Settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://defenceiq-theta.vercel.app",
    "https://defenceiq-5iazzx3nb-madhura-lakade-s-projects.vercel.app",
]


@dataclass(frozen=True)
class Settings:
    database_url: str
    sqlite_path: str
    pace: float
    gemini_api_key: str
    gemini_model: str
    anthropic_api_key: str
    anthropic_model: str
    abuseipdb_api_key: str
    vt_api_key: str
    otx_api_key: str
    allowed_origins: list[str]

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith(("postgresql://", "postgres://"))


def get_settings() -> Settings:
    env_origins = [
        o.strip()
        for o in os.getenv("DEFENCEIQ_ALLOWED_ORIGINS", "").split(",")
        if o.strip()
    ]
    return Settings(
        database_url=os.getenv("DATABASE_URL", "").strip(),
        sqlite_path=os.getenv("DEFENCEIQ_DB", os.getenv("SOCPILOT_DB", ":memory:")),
        pace=float(os.getenv("PACE", "0.6")),
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip(),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "").strip(),
        anthropic_model=os.getenv("MODEL", "claude-sonnet-5-5").strip(),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        vt_api_key=os.getenv("VT_API_KEY", "").strip(),
        otx_api_key=os.getenv("OTX_API_KEY", "").strip(),
        allowed_origins=env_origins if env_origins else list(DEFAULT_ALLOWED_ORIGINS),
    )
