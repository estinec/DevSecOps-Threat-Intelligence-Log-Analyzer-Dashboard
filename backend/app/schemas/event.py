from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class NormalizedEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    event_type: str
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    auth_result: Optional[str] = None
    raw_line: str
