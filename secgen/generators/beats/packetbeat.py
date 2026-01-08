"""Packetbeat event generator for creating ECS-compliant network events."""

import random
import string
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.beats.base import BeatEventGenerator
from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_attack_pattern, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

PacketbeatDataset = Literal["dns", "http", "tls", "flow"]


@register_event_type(
    name="packetbeat",
    category=GeneratorCategory.NETWORK,
    description="Packetbeat events for network traffic analysis (DNS, HTTP, TLS, flows)",
    ecs_fields=[
        "event.module",
        "event.dataset",
        "network.protocol",
        "source.ip",
        "destination.ip",
        "dns.question.name",
        "http.request.method",
        "tls.version",
    ],
    index_pattern="packetbeat-*",
    example_params={"dataset": "dns", "is_malicious": False},
)
class PacketbeatEventGenerator(BeatEventGenerator):
    """
    Generator for creating ECS-compliant Packetbeat events.

    Packetbeat captures network traffic and provides:
    - dns: DNS queries and responses
    - http: HTTP transactions
    - tls: TLS handshakes and metadata
    - flow: Network flow data (connections)
    """

    # Common DNS query types
    DNS_QUERY_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT"]

    # DNS response codes
    DNS_RESPONSE_CODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"]

    # Legitimate domains
    LEGITIMATE_DOMAINS = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "cloudflare.com",
        "github.com",
        "office365.com",
        "azure.com",
        "aws.amazon.com",
    ]

    # C2 domains
    C2_DOMAINS = [
        "evil-c2.badactor.com",
        "command.malicious.net",
        "control.darkweb.org",
        "beacon.apt.xyz",
        "exfil.threat.top",
    ]

    # HTTP methods
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    # Suspicious HTTP paths
    SUSPICIOUS_HTTP_PATHS = [
        "/admin",
        "/wp-admin",
        "/phpmyadmin",
        "/.env",
        "/config.php",
        "/shell.php",
        "/c2/beacon",
        "/upload.php",
        "/backdoor",
    ]

    # Common user agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.28.0",
    ]

    # Suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        "python-requests/2.28.0",
        "curl/7.68.0",
        "Wget/1.21",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "sqlmap/1.5",
        "Nikto/2.1.6",
    ]

    # TLS versions
    TLS_VERSIONS = ["1.2", "1.3"]

    # TLS cipher suites
    TLS_CIPHERS = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ]

    # Common JA3 fingerprints
    JA3_FINGERPRINTS = {
        "chrome": "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,0-10-11,23-24-25,0",
        "firefox": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
        "curl": "769,49196-49200-49195-49199-159-158-52393-52392-52394-49327-49325-49188-49192-107-106-49267-49271-196-195-49162-49172-57-56-136-135-49312-49308-49315-49311-49319-49316-157-156-61-60-53-47-255,0-11-10-13-16,29-23-1-24,0",
        "malware": "771,49196-49195-49200-49199-49188-49187-49192-49191-49172-49171-159-158-57-51-157-156-61-60-53-47-10,65281-0-23-35-13-5-18-16-11-10,29-23-24-25,0",
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize Packetbeat generator."""
        super().__init__(beat_type="packetbeat", randomizer=randomizer)

    def generate(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        timestamp_offset: int = 0,
        dataset: PacketbeatDataset | None = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a single Packetbeat event.

        Args:
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            timestamp_offset: Minutes to offset timestamp
            dataset: Packetbeat dataset (dns, http, tls, flow)
            is_malicious: Whether to generate suspicious activity
            **kwargs: Additional parameters

        Returns:
            ECS-compliant Packetbeat event dictionary
        """
        timestamp = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)

        if dataset is None:
            dataset = random.choice(["dns", "http", "tls", "flow"])

        if dataset == "dns":
            return self._generate_dns_event(timestamp, host, is_malicious, **kwargs)
        elif dataset == "http":
            return self._generate_http_event(timestamp, host, is_malicious, **kwargs)
        elif dataset == "tls":
            return self._generate_tls_event(timestamp, host, is_malicious, **kwargs)
        elif dataset == "flow":
            return self._generate_flow_event(timestamp, host, is_malicious, **kwargs)
        else:
            return self._generate_dns_event(timestamp, host, is_malicious, **kwargs)

    def _generate_dns_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a DNS query event."""
        event = self._build_base_event(timestamp, host)

        # Select domain
        if is_malicious:
            domain = kwargs.get("domain") or self._generate_malicious_domain()
            response_code = random.choice(["NOERROR", "NXDOMAIN"])
        else:
            domain = kwargs.get("domain") or random.choice(self.LEGITIMATE_DOMAINS)
            response_code = "NOERROR"

        query_type = kwargs.get("query_type") or random.choice(self.DNS_QUERY_TYPES)
        dns_server = kwargs.get("dns_server") or "8.8.8.8"

        # Generate source and destination
        src_ip = host.ip[0] if host and host.ip else self.randomizer.generate_ip()
        src_port = random.randint(49152, 65535)

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "packetbeat",
                    "dataset": "packetbeat.dns",
                    "category": ["network"],
                    "type": ["protocol", "connection"],
                    "action": "dns-query",
                    "outcome": "success" if response_code == "NOERROR" else "failure",
                    "id": self.randomizer.generate_uuid(),
                    "duration": random.randint(1000000, 50000000),  # nanoseconds
                },
                "type": "dns",
                "status": "OK" if response_code == "NOERROR" else "Error",
                "method": query_type,
                "resource": domain,
                "query": query_type,
                "dns": {
                    "id": random.randint(1, 65535),
                    "type": "query",
                    "op_code": "QUERY",
                    "question": {
                        "name": domain,
                        "type": query_type,
                        "class": "IN",
                    },
                    "response_code": response_code,
                    "flags": {
                        "recursion_desired": True,
                        "recursion_available": True,
                        "authentic_data": False,
                        "checking_disabled": False,
                    },
                },
                "source": {
                    "ip": src_ip,
                    "port": src_port,
                    "bytes": random.randint(40, 100),
                },
                "destination": {
                    "ip": dns_server,
                    "port": 53,
                    "bytes": random.randint(60, 500),
                },
                "network": {
                    "type": "ipv4",
                    "transport": "udp",
                    "protocol": "dns",
                    "bytes": random.randint(100, 600),
                    "community_id": self._generate_community_id(src_ip, dns_server, src_port, 53),
                },
                "related": {
                    "ip": [src_ip, dns_server],
                    "hosts": [domain],
                },
            }
        )

        # Add resolved IPs if successful
        if response_code == "NOERROR" and query_type in ["A", "AAAA"]:
            resolved_ip = self.randomizer.generate_ip()
            event["dns"]["answers"] = [
                {
                    "name": domain,
                    "type": query_type,
                    "class": "IN",
                    "ttl": random.randint(60, 86400),
                    "data": resolved_ip,
                }
            ]
            event["dns"]["resolved_ip"] = [resolved_ip]
            event["related"]["ip"].append(resolved_ip)

        return event

    def _generate_http_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate an HTTP transaction event."""
        event = self._build_base_event(timestamp, host)

        # Select request details
        if is_malicious:
            method = kwargs.get("method") or random.choice(["GET", "POST"])
            path = kwargs.get("path") or random.choice(self.SUSPICIOUS_HTTP_PATHS)
            domain = random.choice(self.C2_DOMAINS)
            user_agent = random.choice(self.SUSPICIOUS_USER_AGENTS)
            status_code = random.choice([200, 301, 403, 404, 500])
        else:
            method = kwargs.get("method") or random.choice(self.HTTP_METHODS)
            path = kwargs.get("path") or random.choice(["/", "/api/v1/data", "/index.html", "/assets/logo.png"])
            domain = random.choice(self.LEGITIMATE_DOMAINS)
            user_agent = random.choice(self.USER_AGENTS)
            status_code = random.choices([200, 201, 204, 301, 304, 400, 404], weights=[60, 10, 5, 5, 10, 5, 5])[0]

        src_ip = host.ip[0] if host and host.ip else self.randomizer.generate_ip()
        src_port = random.randint(49152, 65535)
        dst_ip = self.randomizer.generate_ip()

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "packetbeat",
                    "dataset": "packetbeat.http",
                    "category": ["network", "web"],
                    "type": ["protocol", "connection"],
                    "action": "http-request",
                    "outcome": "success" if status_code < 400 else "failure",
                    "id": self.randomizer.generate_uuid(),
                    "duration": random.randint(10000000, 500000000),  # nanoseconds
                },
                "type": "http",
                "status": f"{status_code} {self._get_http_status_phrase(status_code)}",
                "method": method,
                "path": path,
                "query": "q=test" if random.random() < 0.3 else "",
                "http": {
                    "request": {
                        "method": method,
                        "body": {"bytes": random.randint(0, 5000)},
                        "bytes": random.randint(200, 2000),
                    },
                    "response": {
                        "status_code": status_code,
                        "body": {"bytes": random.randint(100, 100000)},
                        "bytes": random.randint(300, 100000),
                    },
                    "version": "1.1",
                },
                "url": {
                    "scheme": "https" if random.random() < 0.8 else "http",
                    "domain": domain,
                    "path": path,
                    "full": f"https://{domain}{path}",
                },
                "user_agent": {
                    "original": user_agent,
                },
                "source": {
                    "ip": src_ip,
                    "port": src_port,
                    "bytes": random.randint(200, 2000),
                },
                "destination": {
                    "ip": dst_ip,
                    "port": 443 if random.random() < 0.8 else 80,
                    "bytes": random.randint(300, 100000),
                },
                "network": {
                    "type": "ipv4",
                    "transport": "tcp",
                    "protocol": "http",
                    "bytes": random.randint(500, 102000),
                    "community_id": self._generate_community_id(src_ip, dst_ip, src_port, 443),
                },
                "related": {
                    "ip": [src_ip, dst_ip],
                    "hosts": [domain],
                },
            }
        )

        return event

    def _generate_tls_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a TLS handshake event."""
        event = self._build_base_event(timestamp, host)

        # Select TLS details
        if is_malicious:
            domain = random.choice(self.C2_DOMAINS)
            ja3 = self.JA3_FINGERPRINTS.get("malware", self.JA3_FINGERPRINTS["curl"])
            tls_version = random.choice(self.TLS_VERSIONS)
        else:
            domain = random.choice(self.LEGITIMATE_DOMAINS)
            ja3 = random.choice([self.JA3_FINGERPRINTS["chrome"], self.JA3_FINGERPRINTS["firefox"]])
            tls_version = "1.3" if random.random() < 0.7 else "1.2"

        src_ip = host.ip[0] if host and host.ip else self.randomizer.generate_ip()
        src_port = random.randint(49152, 65535)
        dst_ip = self.randomizer.generate_ip()

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "packetbeat",
                    "dataset": "packetbeat.tls",
                    "category": ["network"],
                    "type": ["protocol", "connection"],
                    "action": "tls-handshake",
                    "outcome": "success",
                    "id": self.randomizer.generate_uuid(),
                    "duration": random.randint(50000000, 200000000),  # nanoseconds
                },
                "type": "tls",
                "status": "OK",
                "tls": {
                    "version": tls_version,
                    "version_protocol": "tls",
                    "cipher": random.choice(self.TLS_CIPHERS),
                    "established": True,
                    "resumed": random.random() < 0.3,
                    "client": {
                        "ja3": self.randomizer.generate_hash("md5"),  # JA3 is MD5
                        "server_name": domain,
                        "supported_ciphers": self.TLS_CIPHERS[:3],
                    },
                    "server": {
                        "ja3s": self.randomizer.generate_hash("md5"),
                        "certificate": self._generate_certificate_info(domain),
                    },
                },
                "source": {
                    "ip": src_ip,
                    "port": src_port,
                    "bytes": random.randint(500, 2000),
                },
                "destination": {
                    "ip": dst_ip,
                    "port": 443,
                    "bytes": random.randint(1000, 5000),
                },
                "network": {
                    "type": "ipv4",
                    "transport": "tcp",
                    "protocol": "tls",
                    "bytes": random.randint(1500, 7000),
                    "community_id": self._generate_community_id(src_ip, dst_ip, src_port, 443),
                },
                "related": {
                    "ip": [src_ip, dst_ip],
                    "hosts": [domain],
                },
            }
        )

        return event

    def _generate_flow_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a network flow event."""
        event = self._build_base_event(timestamp, host)

        # Select flow details
        if is_malicious:
            dst_port = random.choice([4444, 8443, 8080, 1337, 31337])  # C2 ports
            bytes_out = random.randint(100, 1000)  # Small outbound
            bytes_in = random.randint(10000, 100000)  # Large inbound (commands)
        else:
            dst_port = random.choice([80, 443, 22, 3389, 8080, 25, 110, 143])
            bytes_out = random.randint(1000, 100000)
            bytes_in = random.randint(1000, 1000000)

        src_ip = host.ip[0] if host and host.ip else self.randomizer.generate_ip()
        src_port = random.randint(49152, 65535)
        dst_ip = self.randomizer.generate_ip()

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "packetbeat",
                    "dataset": "packetbeat.flow",
                    "category": ["network"],
                    "type": ["connection", "end"],
                    "action": "flow_end",
                    "id": self.randomizer.generate_uuid(),
                    "duration": random.randint(1000000000, 60000000000),  # nanoseconds
                },
                "type": "flow",
                "flow": {
                    "id": self.randomizer.generate_uuid(),
                    "final": True,
                    "vlan": random.randint(1, 4094) if random.random() < 0.2 else None,
                },
                "source": {
                    "ip": src_ip,
                    "port": src_port,
                    "bytes": bytes_out,
                    "packets": random.randint(10, 1000),
                },
                "destination": {
                    "ip": dst_ip,
                    "port": dst_port,
                    "bytes": bytes_in,
                    "packets": random.randint(10, 1000),
                },
                "network": {
                    "type": "ipv4",
                    "transport": "tcp",
                    "bytes": bytes_in + bytes_out,
                    "packets": random.randint(20, 2000),
                    "community_id": self._generate_community_id(src_ip, dst_ip, src_port, dst_port),
                    "direction": "outbound",
                },
                "related": {
                    "ip": [src_ip, dst_ip],
                },
            }
        )

        return event

    def _generate_malicious_domain(self) -> str:
        """Generate a malicious-looking domain (DGA-style)."""
        length = random.randint(12, 20)
        chars = string.ascii_lowercase + string.digits
        name = "".join(random.choice(chars) for _ in range(length))
        tld = random.choice([".xyz", ".top", ".club", ".tk", ".ml"])
        return f"{name}{tld}"

    def _generate_community_id(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> str:
        """Generate a network community ID."""
        # Simplified community ID (real one uses base64 of SHA1)
        return f"1:{self.randomizer.generate_hash('sha1')[:20]}="

    def _get_http_status_phrase(self, status_code: int) -> str:
        """Get HTTP status phrase for status code."""
        phrases = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }
        return phrases.get(status_code, "Unknown")

    def _generate_certificate_info(self, domain: str) -> dict[str, Any]:
        """Generate TLS certificate information."""
        not_before = datetime.now(timezone.utc) - timedelta(days=random.randint(30, 365))
        not_after = not_before + timedelta(days=random.randint(90, 730))

        return {
            "subject": {
                "common_name": domain,
                "organization": [domain.split(".")[0].title()],
            },
            "issuer": {
                "common_name": "DigiCert SHA2 Extended Validation Server CA",
                "organization": ["DigiCert Inc"],
            },
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "public_key_algorithm": "RSA",
        }

    @register_attack_pattern(
        name="packetbeat-dga",
        description="DGA (Domain Generation Algorithm) activity detected by Packetbeat",
        ttps=["T1568", "T1568.002"],
        category=GeneratorCategory.NETWORK,
        required_params=["host"],
        optional_params=["count"],
        event_types=["packetbeat"],
        detection_recommendations=[
            "Monitor for high entropy domain queries",
            "Alert on high NXDOMAIN rates from single hosts",
            "Track DNS queries to newly registered domains",
        ],
    )
    def generate_dga_activity(
        self,
        host: "Host",
        count: int = 50,
    ) -> list[dict[str, Any]]:
        """Generate DGA domain query events."""
        events = []
        for i in range(count):
            event = self._generate_dns_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=count - i),
                host=host,
                is_malicious=True,
            )
            # Most DGA queries return NXDOMAIN
            if random.random() < 0.9:
                event["dns"]["response_code"] = "NXDOMAIN"
                event["event"]["outcome"] = "failure"
            events.append(event)
        return events

    @register_attack_pattern(
        name="packetbeat-c2-beacon",
        description="C2 beaconing traffic detected by Packetbeat",
        ttps=["T1071", "T1071.001"],
        category=GeneratorCategory.NETWORK,
        required_params=["host"],
        optional_params=["beacon_count", "c2_domain"],
        event_types=["packetbeat"],
        detection_recommendations=[
            "Monitor for regular interval connections to the same destination",
            "Alert on suspicious JA3 fingerprints",
            "Track connections to rare/unusual domains",
        ],
    )
    def generate_c2_beacon(
        self,
        host: "Host",
        beacon_count: int = 10,
        c2_domain: str | None = None,
    ) -> list[dict[str, Any]]:
        """Generate C2 beaconing traffic events."""
        events = []
        c2_domain = c2_domain or random.choice(self.C2_DOMAINS)

        for i in range(beacon_count):
            # Generate DNS query for C2 domain
            dns_event = self._generate_dns_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=beacon_count - i),
                host=host,
                is_malicious=True,
                domain=c2_domain,
            )
            events.append(dns_event)

            # Generate TLS connection to C2
            tls_event = self._generate_tls_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=beacon_count - i),
                host=host,
                is_malicious=True,
            )
            events.append(tls_event)

            # Generate HTTP POST (beacon)
            http_event = self._generate_http_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=beacon_count - i),
                host=host,
                is_malicious=True,
                method="POST",
                path="/c2/beacon",
            )
            events.append(http_event)

        return events

