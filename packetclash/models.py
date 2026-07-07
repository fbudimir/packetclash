from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse

@dataclass
class AttackTarget:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    


    # hostname + port
    @property
    def host(self) -> str:
        parsed = urlparse(self.url)
        return parsed.netloc

    # hostname
    @property
    def hostname(self) -> str:
        parsed = urlparse(self.url)
        return parsed.hostname

    # port
    @property
    def port(self) -> int:
        parsed = urlparse(self.url)
        if parsed.port:
            return parsed.port
        if self.scheme == "https":
            return 443
        return 80

    # path + query
    @property
    def path(self) -> str:
        parsed = urlparse(self.url)
        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += f"?{parsed.query}"
        return path

    # http or https
    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme
