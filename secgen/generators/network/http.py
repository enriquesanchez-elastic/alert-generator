"""HTTP event generator for creating ECS-compliant HTTP transaction events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host

HTTPMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


@register_event_type(
    name="http",
    category=GeneratorCategory.NETWORK,
    description="HTTP transaction events for web traffic and attack detection",
    ecs_fields=[
        "http.request.method",
        "url.full",
        "http.response.status_code",
        "user_agent.original",
        "http.request.body.bytes",
    ],
    index_pattern="logs-network_traffic.http-default",
    example_params={"method": "POST", "is_malicious": True},
)
class HTTPEventGenerator:
    """
    Generator for creating ECS-compliant HTTP transaction events.

    HTTP events are critical for detecting:
    - Web application attacks (SQLi, XSS, etc.)
    - Malicious file downloads
    - C2 communications over HTTP
    - Data exfiltration via HTTP POST
    - Suspicious user agents
    """

    # Common user agents
    USER_AGENTS = {
        "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "curl": "curl/7.88.1",
        "wget": "Wget/1.21.3",
        "python": "python-requests/2.31.0",
    }

    # Suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",  # Old IE
        "Mozilla/4.0 (compatible; MSIE 6.0)",
        "Java/1.8.0_201",
        "Python-urllib/3.9",
        "Go-http-client/1.1",
        "Wget",
        "curl",
        "",  # Empty user agent
        "Meterpreter",
        "CobaltStrike",
    ]

    # Common legitimate URLs
    LEGITIMATE_URLS = [
        "/api/v1/users",
        "/api/v1/products",
        "/index.html",
        "/static/js/app.js",
        "/static/css/style.css",
        "/images/logo.png",
        "/login",
        "/logout",
        "/dashboard",
        "/settings",
    ]

    # Suspicious URL patterns
    SUSPICIOUS_URLS = [
        "/admin/config.php",
        "/wp-admin/admin-ajax.php",
        "/.git/config",
        "/.env",
        "/etc/passwd",
        "/shell.php",
        "/c2/beacon",
        "/upload.php",
        "/cmd.aspx",
        "/../../../etc/passwd",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize HTTP event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        method: HTTPMethod | None = None,
        url_path: str | None = None,
        domain: str | None = None,
        status_code: int | None = None,
        host: Optional["Host"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        request_body_bytes: int | None = None,
        response_body_bytes: int | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single HTTP event.

        Args:
            method: HTTP method
            url_path: URL path
            domain: Target domain
            status_code: HTTP response status code
            host: Optional Host entity
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious characteristics
            request_body_bytes: Request body size
            response_body_bytes: Response body size
            user_agent: User agent string

        Returns:
            ECS-compliant HTTP event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Set defaults
        if method is None:
            method = random.choices(
                ["GET", "POST", "PUT", "DELETE"], weights=[0.7, 0.2, 0.05, 0.05]
            )[0]

        if url_path is None:
            url_path = random.choice(self.SUSPICIOUS_URLS if is_malicious else self.LEGITIMATE_URLS)

        if domain is None:
            domain = f"www.{'malicious' if is_malicious else 'example'}.com"

        if status_code is None:
            if is_malicious:
                status_code = random.choices([200, 403, 404, 500], weights=[0.4, 0.2, 0.3, 0.1])[0]
            else:
                status_code = random.choices(
                    [200, 201, 301, 304, 404], weights=[0.7, 0.1, 0.05, 0.1, 0.05]
                )[0]

        if user_agent is None:
            if is_malicious:
                user_agent = random.choice(self.SUSPICIOUS_USER_AGENTS)
            else:
                user_agent = random.choice(list(self.USER_AGENTS.values()))

        # Generate body sizes
        if request_body_bytes is None:
            request_body_bytes = random.randint(0, 10000) if method in ["POST", "PUT"] else 0
        if response_body_bytes is None:
            response_body_bytes = random.randint(100, 500000)

        # Generate source/destination IPs
        if host:
            source_ip = random.choice(host.ip)
        else:
            source_ip = self.randomizer.generate_ip()
        destination_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Build full URL
        scheme = "https" if random.random() < 0.8 else "http"
        port = 443 if scheme == "https" else 80
        full_url = f"{scheme}://{domain}{url_path}"

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["network", "web"],
                "type": ["connection", "protocol"],
                "action": "http-request",
                "outcome": "success" if 200 <= status_code < 400 else "failure",
                "id": self.randomizer.generate_uuid(),
            },
            "http": {
                "request": {
                    "method": method,
                    "body": {
                        "bytes": request_body_bytes,
                    },
                },
                "response": {
                    "status_code": status_code,
                    "body": {
                        "bytes": response_body_bytes,
                    },
                },
                "version": random.choice(["1.1", "2"]),
            },
            "url": {
                "full": full_url,
                "scheme": scheme,
                "domain": domain,
                "path": url_path,
                "port": port,
            },
            "user_agent": {
                "original": user_agent,
            },
            "source": {
                "ip": source_ip,
                "port": random.randint(49152, 65535),
            },
            "destination": {
                "ip": destination_ip,
                "port": port,
                "domain": domain,
            },
            "network": {
                "transport": "tcp",
                "protocol": "http",
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "network_traffic.http",
                "namespace": "default",
            },
        }

        # Add host information
        if host:
            event["host"] = host.to_ecs_dict()

        # Add related fields
        event["related"] = {
            "ip": [source_ip, destination_ip],
            "hosts": [domain],
        }

        return event

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Generate a batch of HTTP events."""
        events = []

        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                host=host,
                timestamp_offset=timestamp_offset,
                is_malicious=is_malicious,
            )
            events.append(event)

        return events

    def generate_web_shell_traffic(
        self,
        host: "Host",
        shell_url: str = "/uploads/shell.php",
        command_count: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate web shell command traffic.

        Args:
            host: Source host
            shell_url: Web shell URL
            command_count: Number of commands

        Returns:
            List of HTTP events
        """
        events = []
        commands = ["id", "whoami", "pwd", "ls -la", "cat /etc/passwd", "uname -a"]

        for i in range(command_count):
            cmd = random.choice(commands)
            url_path = f"{shell_url}?cmd={cmd}"

            event = self.generate(
                method="GET",
                url_path=url_path,
                host=host,
                timestamp_offset=command_count - i,
                is_malicious=True,
                response_body_bytes=random.randint(100, 5000),
            )
            events.append(event)

        return events

    def generate_data_exfiltration_http(
        self,
        host: "Host",
        exfil_domain: str,
        data_size_mb: float = 10.0,
        chunk_count: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate HTTP POST data exfiltration.

        Args:
            host: Source host
            exfil_domain: Exfiltration domain
            data_size_mb: Total data in MB
            chunk_count: Number of POST requests

        Returns:
            List of HTTP events
        """
        events = []
        total_bytes = int(data_size_mb * 1024 * 1024)
        bytes_per_chunk = total_bytes // chunk_count

        for i in range(chunk_count):
            event = self.generate(
                method="POST",
                url_path="/api/upload",
                domain=exfil_domain,
                status_code=200,
                host=host,
                timestamp_offset=chunk_count - i,
                is_malicious=True,
                request_body_bytes=bytes_per_chunk,
                response_body_bytes=random.randint(50, 200),
            )
            events.append(event)

        return events
