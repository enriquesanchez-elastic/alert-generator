"""DNS event generator for creating ECS-compliant DNS transaction events."""

import math
import random
import string
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import (
    GeneratorCategory,
    register_attack_pattern,
    register_event_type,
)

if TYPE_CHECKING:
    from secgen.models.entities import Host

DNSQueryType = Literal["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]
DNSResponseCode = Literal["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"]


@register_event_type(
    name="dns",
    category=GeneratorCategory.NETWORK,
    description="DNS query and response events for detecting malicious domain activity",
    ecs_fields=[
        "dns.question.name",
        "dns.question.type",
        "dns.resolved_ip",
        "dns.response_code",
    ],
    index_pattern="logs-dns.query-default",
    example_params={"is_malicious": True, "query_type": "A"},
)
class DNSEventGenerator:
    """
    Generator for creating ECS-compliant DNS transaction events.

    DNS events are critical for detecting:
    - Domain Generation Algorithm (DGA) activity
    - DNS tunneling for data exfiltration
    - C2 communications via DNS
    - DNS rebinding attacks
    - Suspicious TLD usage
    """

    # Common legitimate domains
    LEGITIMATE_DOMAINS = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "github.com",
        "cloudflare.com",
        "akamai.com",
        "fastly.com",
        "cloudfront.net",
        "office365.com",
        "outlook.com",
        "live.com",
        "azure.com",
    ]

    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS = [
        ".xyz",
        ".top",
        ".club",
        ".work",
        ".date",
        ".racing",
        ".win",
        ".bid",
        ".stream",
        ".download",
        ".review",
        ".party",
        ".loan",
        ".gq",
        ".cf",
        ".ga",
        ".ml",
        ".tk",
    ]

    # C2 domains
    C2_DOMAINS = [
        "evil-c2.badactor.com",
        "command.malicious.net",
        "control.darkweb.org",
        "payload.threat.xyz",
        "beacon.apt.net",
        "exfil.data.top",
    ]

    # DNS servers
    DNS_SERVERS = [
        "8.8.8.8",  # Google
        "8.8.4.4",  # Google
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",  # Cloudflare
        "9.9.9.9",  # Quad9
        "208.67.222.222",  # OpenDNS
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize DNS event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        query_name: str | None = None,
        query_type: DNSQueryType | None = None,
        response_code: DNSResponseCode | None = None,
        host: Optional["Host"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        resolved_ips: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single DNS event.

        Args:
            query_name: DNS query name
            query_type: Query type (A, AAAA, TXT, etc.)
            response_code: DNS response code
            host: Optional Host entity
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious DNS characteristics
            resolved_ips: Optional list of resolved IP addresses

        Returns:
            ECS-compliant DNS event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Generate query name if not provided
        if query_name is None:
            if is_malicious:
                query_name = self._generate_suspicious_domain()
            else:
                query_name = self._generate_legitimate_domain()

        # Set defaults
        if query_type is None:
            query_type = random.choice(["A", "AAAA", "TXT", "MX"])
        if response_code is None:
            response_code = "NOERROR" if not is_malicious or random.random() < 0.7 else "NXDOMAIN"

        # Parse domain components
        parts = query_name.split(".")
        if len(parts) >= 2:
            registered_domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else None
            top_level_domain = parts[-1]
        else:
            registered_domain = query_name
            subdomain = None
            top_level_domain = ""

        # Generate resolved IPs
        if resolved_ips is None and response_code == "NOERROR":
            if is_malicious:
                resolved_ips = [f"198.51.100.{random.randint(1, 254)}"]  # TEST-NET-2
            else:
                resolved_ips = [
                    f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                ]

        # Select DNS server
        dns_server = random.choice(self.DNS_SERVERS)

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": ["protocol", "connection"],
                "action": "dns-query",
                "outcome": "success" if response_code == "NOERROR" else "failure",
                "id": self.randomizer.generate_uuid(),
            },
            "dns": {
                "type": "query",
                "question": {
                    "name": query_name,
                    "type": query_type,
                    "class": "IN",
                    "registered_domain": registered_domain,
                    "top_level_domain": top_level_domain,
                },
                "response_code": response_code,
                "header_flags": ["RD", "RA"],  # Recursion Desired, Recursion Available
            },
            "network": {
                "transport": "udp",
                "protocol": "dns",
                "type": "ipv4",
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "dns.query",
                "namespace": "default",
            },
        }

        # Add subdomain if present
        if subdomain:
            event["dns"]["question"]["subdomain"] = subdomain

        # Add resolved IPs
        if resolved_ips:
            event["dns"]["resolved_ip"] = resolved_ips
            event["dns"]["answers"] = [
                {
                    "name": query_name,
                    "type": query_type,
                    "class": "IN",
                    "ttl": random.randint(60, 86400),
                    "data": ip,
                }
                for ip in resolved_ips
            ]

        # Add host information
        if host:
            event["host"] = host.to_ecs_dict()
            source_ip = random.choice(host.ip)
        else:
            hostname = self.randomizer.generate_hostname()
            source_ip = self.randomizer.generate_ip()
            event["host"] = {
                "name": hostname,
                "hostname": hostname,
            }

        # Add source/destination
        event["source"] = {
            "ip": source_ip,
            "port": random.randint(49152, 65535),
        }
        event["destination"] = {
            "ip": dns_server,
            "port": 53,
        }

        # Add related fields
        related_ips = [source_ip, dns_server]
        if resolved_ips:
            related_ips.extend(resolved_ips)
        event["related"] = {
            "ip": related_ips,
            "hosts": [query_name],
        }

        return event

    def _generate_legitimate_domain(self) -> str:
        """Generate a legitimate-looking domain name."""
        base = random.choice(self.LEGITIMATE_DOMAINS)
        # Sometimes add subdomain
        if random.random() < 0.3:
            subdomains = ["www", "api", "cdn", "mail", "app", "login", "auth"]
            return f"{random.choice(subdomains)}.{base}"
        return base

    def _generate_suspicious_domain(self) -> str:
        """Generate a suspicious domain name."""
        pattern = random.choice(["dga", "c2", "typosquat", "suspicious_tld"])

        if pattern == "dga":
            return self._generate_dga_domain()
        elif pattern == "c2":
            return random.choice(self.C2_DOMAINS)
        elif pattern == "typosquat":
            return self._generate_typosquat_domain()
        else:
            return self._generate_suspicious_tld_domain()

    def _generate_dga_domain(self) -> str:
        """Generate a DGA-like domain with high entropy."""
        # Random alphanumeric string
        length = random.randint(12, 20)
        chars = string.ascii_lowercase + string.digits
        name = "".join(random.choice(chars) for _ in range(length))
        tld = random.choice([".com", ".net", ".org", ".info"] + self.SUSPICIOUS_TLDS)
        return f"{name}{tld}"

    def _generate_typosquat_domain(self) -> str:
        """Generate a typosquatted domain."""
        targets = ["google", "microsoft", "amazon", "apple", "facebook"]
        target = random.choice(targets)

        # Various typosquatting techniques
        techniques = [
            lambda s: s.replace("o", "0"),
            lambda s: s.replace("l", "1"),
            lambda s: s.replace("e", "3"),
            lambda s: s + s[-1],  # Double last char
            lambda s: s[:-1],  # Missing char
            lambda s: s[: len(s) // 2] + s[len(s) // 2] + s[len(s) // 2 :],  # Double middle char
        ]

        modified = random.choice(techniques)(target)
        return f"{modified}.com"

    def _generate_suspicious_tld_domain(self) -> str:
        """Generate a domain with suspicious TLD."""
        words = ["download", "free", "update", "secure", "login", "verify"]
        name = random.choice(words) + str(random.randint(1, 999))
        tld = random.choice(self.SUSPICIOUS_TLDS)
        return f"{name}{tld}"

    def calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of a domain name."""
        # Remove TLD for entropy calculation
        name = domain.split(".")[0]
        if not name:
            return 0.0

        prob = [float(name.count(c)) / len(name) for c in set(name)]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        return entropy

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of DNS events.

        Args:
            count: Number of events to generate
            host: Optional Host entity
            malicious_ratio: Ratio of malicious events
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of DNS event dictionaries
        """
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

    @register_attack_pattern(
        name="dga-activity",
        description="Domain Generation Algorithm activity with high NXDOMAIN rates",
        ttps=["T1568.002"],
        category=GeneratorCategory.NETWORK,
        required_params=["host"],
        optional_params=["domain_count", "nxdomain_ratio"],
        event_types=["dns"],
        detection_recommendations=[
            "High NXDOMAIN response rates",
            "High entropy domain names",
            "Rapid DNS queries to random domains",
        ],
    )
    def generate_dga_activity(
        self,
        host: "Host",
        domain_count: int = 50,
        nxdomain_ratio: float = 0.9,
    ) -> list[dict[str, Any]]:
        """
        Generate DGA (Domain Generation Algorithm) activity.

        DGA is characterized by many queries to random-looking domains
        with high NXDOMAIN response rates.

        Args:
            host: Host making queries
            domain_count: Number of domains to query
            nxdomain_ratio: Ratio of NXDOMAIN responses

        Returns:
            List of DNS events representing DGA activity
        """
        events = []

        for i in range(domain_count):
            dga_domain = self._generate_dga_domain()
            response_code: DNSResponseCode = (
                "NXDOMAIN" if random.random() < nxdomain_ratio else "NOERROR"
            )
            timestamp_offset = domain_count - i

            event = self.generate(
                query_name=dga_domain,
                query_type="A",
                response_code=response_code,
                host=host,
                timestamp_offset=timestamp_offset,
                is_malicious=True,
            )
            events.append(event)

        return events

    @register_attack_pattern(
        name="dns-tunneling",
        description="DNS tunneling for data exfiltration using encoded subdomains",
        ttps=["T1071.004", "T1048.003"],
        category=GeneratorCategory.NETWORK,
        required_params=["host", "tunnel_domain"],
        optional_params=["query_count", "data_size_bytes"],
        event_types=["dns"],
        detection_recommendations=[
            "Long subdomain strings (encoded data)",
            "TXT queries with large responses",
            "High query frequency to same domain",
        ],
    )
    def generate_dns_tunneling(
        self,
        host: "Host",
        tunnel_domain: str,
        query_count: int = 20,
        data_size_bytes: int = 10000,
    ) -> list[dict[str, Any]]:
        """
        Generate DNS tunneling events.

        DNS tunneling is characterized by:
        - Long subdomain strings (encoded data)
        - TXT queries with large responses
        - High query frequency to same domain

        Args:
            host: Host performing tunneling
            tunnel_domain: Base domain for tunneling
            query_count: Number of queries
            data_size_bytes: Total data to tunnel

        Returns:
            List of DNS events representing tunneling
        """
        events = []
        bytes_per_query = data_size_bytes // query_count

        for i in range(query_count):
            # Generate encoded subdomain (simulating data exfil)
            encoded_length = min(63, bytes_per_query)  # DNS label max 63 chars
            encoded_data = "".join(
                random.choices(string.ascii_lowercase + string.digits, k=encoded_length)
            )

            query_name = f"{encoded_data}.{tunnel_domain}"
            timestamp_offset = query_count - i

            event = self.generate(
                query_name=query_name,
                query_type="TXT",
                response_code="NOERROR",
                host=host,
                timestamp_offset=timestamp_offset,
                is_malicious=True,
            )

            # Add large TXT response (data coming back)
            event["dns"]["answers"] = [
                {
                    "name": query_name,
                    "type": "TXT",
                    "class": "IN",
                    "ttl": 60,
                    "data": "".join(random.choices(string.ascii_letters + string.digits, k=200)),
                }
            ]

            events.append(event)

        return events

    @register_attack_pattern(
        name="c2-dns",
        description="Command and control DNS beacon communications",
        ttps=["T1071.004", "T1573"],
        category=GeneratorCategory.NETWORK,
        required_params=["host", "c2_domain"],
        optional_params=["beacon_count", "interval_minutes"],
        event_types=["dns"],
        detection_recommendations=[
            "Regular periodic DNS queries to same domain",
            "Known malicious domain lookups",
            "DNS queries from unusual processes",
        ],
    )
    def generate_c2_dns(
        self,
        host: "Host",
        c2_domain: str,
        beacon_count: int = 10,
        interval_minutes: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Generate C2 DNS beacon events.

        Args:
            host: Infected host
            c2_domain: C2 domain
            beacon_count: Number of beacon queries
            interval_minutes: Interval between beacons

        Returns:
            List of DNS events for C2 beaconing
        """
        events = []

        for i in range(beacon_count):
            # Add jitter to interval
            jitter = random.randint(-1, 1)
            timestamp_offset = (beacon_count - i) * (interval_minutes + jitter)

            event = self.generate(
                query_name=c2_domain,
                query_type="A",
                response_code="NOERROR",
                host=host,
                timestamp_offset=timestamp_offset,
                is_malicious=True,
                resolved_ips=[f"198.51.100.{random.randint(1, 254)}"],
            )
            events.append(event)

        return events
