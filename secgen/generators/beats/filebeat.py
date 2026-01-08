"""Filebeat event generator for creating ECS-compliant log events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.beats.base import BeatEventGenerator
from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_attack_pattern, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

FilebeatDataset = Literal[
    "system.syslog",
    "system.auth",
    "apache.access",
    "apache.error",
    "nginx.access",
    "nginx.error",
]


@register_event_type(
    name="filebeat",
    category=GeneratorCategory.ENDPOINT,
    description="Filebeat events for log file monitoring (syslog, auth, web server logs)",
    ecs_fields=[
        "event.module",
        "event.dataset",
        "log.file.path",
        "message",
        "http.request.method",
        "http.response.status_code",
    ],
    index_pattern="filebeat-*",
    example_params={"dataset": "system.syslog", "is_malicious": False},
)
class FilebeatEventGenerator(BeatEventGenerator):
    """
    Generator for creating ECS-compliant Filebeat events.

    Filebeat collects log files from:
    - system.syslog: System syslog messages
    - system.auth: Authentication logs
    - apache.access: Apache HTTP access logs
    - apache.error: Apache HTTP error logs
    - nginx.access: Nginx access logs
    - nginx.error: Nginx error logs
    """

    # Syslog facilities
    SYSLOG_FACILITIES = [
        "kern", "user", "mail", "daemon", "auth", "syslog",
        "lpr", "news", "uucp", "cron", "authpriv", "local0",
    ]

    # Syslog severities
    SYSLOG_SEVERITIES = [
        "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
    ]

    # Common syslog programs
    SYSLOG_PROGRAMS = [
        "systemd", "kernel", "sshd", "cron", "sudo", "NetworkManager",
        "dbus-daemon", "polkitd", "snapd", "dockerd", "kubelet",
    ]

    # Suspicious syslog messages
    SUSPICIOUS_SYSLOG_MESSAGES = [
        "Possible SYN flooding on port 22. Sending cookies.",
        "POSSIBLE BREAK-IN ATTEMPT!",
        "Failed password for invalid user admin from {ip}",
        "error: maximum authentication attempts exceeded",
        "segfault at 0 ip (null) sp 00007fffffff error 14",
        "kernel: Out of memory: Kill process",
        "iptables denied connection from {ip}",
    ]

    # Normal syslog messages
    NORMAL_SYSLOG_MESSAGES = [
        "Started Session {n} of user {user}.",
        "New session {n} of user {user}.",
        "Removed session {n}.",
        "pam_unix(cron:session): session opened for user root",
        "pam_unix(cron:session): session closed for user root",
        "systemd[1]: Started Daily apt download activities.",
        "systemd[1]: Reached target Multi-User System.",
        "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=",
    ]

    # HTTP methods and paths
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

    NORMAL_PATHS = [
        "/",
        "/index.html",
        "/api/v1/health",
        "/api/v1/users",
        "/static/css/style.css",
        "/static/js/app.js",
        "/favicon.ico",
        "/robots.txt",
    ]

    MALICIOUS_PATHS = [
        "/admin",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/.env",
        "/config.php",
        "/shell.php",
        "/../../../etc/passwd",
        "/cgi-bin/test.cgi?q=;cat+/etc/passwd",
        "/api/../../../etc/shadow",
    ]

    # User agents
    NORMAL_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    SUSPICIOUS_USER_AGENTS = [
        "sqlmap/1.5#stable (http://sqlmap.org)",
        "Nikto/2.1.6",
        "python-requests/2.28.0",
        "curl/7.68.0",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "() { :;}; /bin/bash -c 'cat /etc/passwd'",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize Filebeat generator."""
        super().__init__(beat_type="filebeat", randomizer=randomizer)

    def generate(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        timestamp_offset: int = 0,
        dataset: FilebeatDataset | None = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a single Filebeat event.

        Args:
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            timestamp_offset: Minutes to offset timestamp
            dataset: Filebeat dataset (system.syslog, apache.access, etc.)
            is_malicious: Whether to generate suspicious activity
            **kwargs: Additional parameters

        Returns:
            ECS-compliant Filebeat event dictionary
        """
        timestamp = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)

        if dataset is None:
            dataset = random.choice([
                "system.syslog", "system.auth",
                "apache.access", "nginx.access",
            ])

        if dataset == "system.syslog":
            return self._generate_syslog_event(timestamp, host, user, is_malicious, **kwargs)
        elif dataset == "system.auth":
            return self._generate_auth_event(timestamp, host, user, is_malicious, **kwargs)
        elif dataset in ["apache.access", "nginx.access"]:
            return self._generate_web_access_event(timestamp, host, dataset, is_malicious, **kwargs)
        elif dataset in ["apache.error", "nginx.error"]:
            return self._generate_web_error_event(timestamp, host, dataset, is_malicious, **kwargs)
        else:
            return self._generate_syslog_event(timestamp, host, user, is_malicious, **kwargs)

    def _generate_syslog_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a system syslog event."""
        event = self._build_base_event(timestamp, host)

        # Select message
        source_ip = kwargs.get("source_ip") or self.randomizer.generate_ip()
        username = user.name if user else self.randomizer.generate_username()

        if is_malicious:
            message_template = random.choice(self.SUSPICIOUS_SYSLOG_MESSAGES)
            severity = random.choice(["err", "crit", "alert", "warning"])
            facility = random.choice(["auth", "authpriv", "kern"])
            program = random.choice(["sshd", "kernel", "sudo"])
        else:
            message_template = random.choice(self.NORMAL_SYSLOG_MESSAGES)
            severity = random.choice(["info", "notice", "debug"])
            facility = random.choice(self.SYSLOG_FACILITIES)
            program = random.choice(self.SYSLOG_PROGRAMS)

        # Format message with placeholders
        message = message_template.format(
            ip=source_ip,
            user=username,
            n=random.randint(1, 1000),
        )

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "system",
                    "dataset": "system.syslog",
                    "category": ["host"],
                    "type": ["info"],
                    "id": self.randomizer.generate_uuid(),
                },
                "message": message,
                "log": {
                    "file": {
                        "path": "/var/log/syslog",
                    },
                    "syslog": {
                        "facility": {
                            "name": facility,
                        },
                        "severity": {
                            "name": severity,
                        },
                        "priority": random.randint(0, 191),
                    },
                },
                "process": {
                    "name": program,
                    "pid": random.randint(1, 65535),
                },
                "syslog": {
                    "facility": facility,
                    "severity": severity,
                    "hostname": host.name if host else self.randomizer.generate_hostname(),
                    "appname": program,
                },
            }
        )

        if user:
            event["user"] = {"name": user.name}

        return event

    def _generate_auth_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a system auth event."""
        event = self._build_base_event(timestamp, host)

        source_ip = kwargs.get("source_ip") or self.randomizer.generate_ip()
        username = user.name if user else self.randomizer.generate_username()
        src_port = random.randint(49152, 65535)

        if is_malicious:
            outcome = random.choices(["failure", "success"], weights=[0.9, 0.1])[0]
            messages = [
                f"Failed password for {username} from {source_ip} port {src_port} ssh2",
                f"Failed password for invalid user {username} from {source_ip} port {src_port} ssh2",
                f"Invalid user {username} from {source_ip} port {src_port}",
                f"Connection closed by authenticating user {username} {source_ip} port {src_port} [preauth]",
                f"Disconnected from invalid user {username} {source_ip} port {src_port} [preauth]",
            ]
        else:
            outcome = random.choices(["success", "failure"], weights=[0.9, 0.1])[0]
            if outcome == "success":
                messages = [
                    f"Accepted password for {username} from {source_ip} port {src_port} ssh2",
                    f"Accepted publickey for {username} from {source_ip} port {src_port} ssh2",
                    f"pam_unix(sshd:session): session opened for user {username}",
                ]
            else:
                messages = [
                    f"Failed password for {username} from {source_ip} port {src_port} ssh2",
                ]

        message = random.choice(messages)

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "system",
                    "dataset": "system.auth",
                    "category": ["authentication"],
                    "type": ["start"] if outcome == "success" else ["info"],
                    "outcome": outcome,
                    "id": self.randomizer.generate_uuid(),
                },
                "message": message,
                "log": {
                    "file": {
                        "path": "/var/log/auth.log",
                    },
                },
                "process": {
                    "name": "sshd",
                    "pid": random.randint(1000, 65535),
                },
                "source": {
                    "ip": source_ip,
                    "port": src_port,
                },
                "user": {
                    "name": username,
                },
                "system": {
                    "auth": {
                        "ssh": {
                            "event": "Accepted" if outcome == "success" else "Failed",
                            "method": random.choice(["password", "publickey"]),
                        },
                    },
                },
                "related": {
                    "ip": [source_ip],
                    "user": [username],
                },
            }
        )

        return event

    def _generate_web_access_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        dataset: str = "apache.access",
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a web server access log event."""
        event = self._build_base_event(timestamp, host)

        source_ip = kwargs.get("source_ip") or self.randomizer.generate_ip()
        web_server = "apache" if "apache" in dataset else "nginx"
        log_path = f"/var/log/{web_server}/access.log"

        if is_malicious:
            method = random.choice(["GET", "POST"])
            path = random.choice(self.MALICIOUS_PATHS)
            user_agent = random.choice(self.SUSPICIOUS_USER_AGENTS)
            status_code = random.choice([200, 403, 404, 500])
        else:
            method = random.choice(self.HTTP_METHODS)
            path = random.choice(self.NORMAL_PATHS)
            user_agent = random.choice(self.NORMAL_USER_AGENTS)
            status_code = random.choices(
                [200, 201, 204, 301, 304, 400, 404],
                weights=[60, 5, 5, 10, 10, 5, 5]
            )[0]

        body_bytes = random.randint(100, 50000)
        response_time = random.randint(1, 5000)  # milliseconds

        # Build access log message
        message = f'{source_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {path} HTTP/1.1" {status_code} {body_bytes} "-" "{user_agent}"'

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": web_server,
                    "dataset": dataset,
                    "category": ["web"],
                    "type": ["access"],
                    "outcome": "success" if status_code < 400 else "failure",
                    "id": self.randomizer.generate_uuid(),
                    "duration": response_time * 1000000,  # nanoseconds
                },
                "message": message,
                "log": {
                    "file": {
                        "path": log_path,
                    },
                },
                "http": {
                    "request": {
                        "method": method,
                        "referrer": kwargs.get("referrer", "-"),
                    },
                    "response": {
                        "status_code": status_code,
                        "body": {
                            "bytes": body_bytes,
                        },
                    },
                    "version": "1.1",
                },
                "url": {
                    "path": path,
                    "original": path,
                },
                "source": {
                    "ip": source_ip,
                    "address": source_ip,
                },
                "user_agent": {
                    "original": user_agent,
                },
                "related": {
                    "ip": [source_ip],
                },
            }
        )

        # Add user if authenticated
        if "-" not in message.split()[2]:
            event["user"] = {"name": self.randomizer.generate_username()}

        return event

    def _generate_web_error_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        dataset: str = "apache.error",
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a web server error log event."""
        event = self._build_base_event(timestamp, host)

        source_ip = kwargs.get("source_ip") or self.randomizer.generate_ip()
        web_server = "apache" if "apache" in dataset else "nginx"
        log_path = f"/var/log/{web_server}/error.log"

        if is_malicious:
            error_messages = [
                f"[client {source_ip}] ModSecurity: Access denied with code 403",
                f"[client {source_ip}] File does not exist: /var/www/html/shell.php",
                f"[client {source_ip}] Invalid URI in request GET /../../../etc/passwd",
                f"[client {source_ip}] attempt to invoke directory as script",
            ]
            level = random.choice(["error", "crit"])
        else:
            error_messages = [
                f"[client {source_ip}] File does not exist: /var/www/html/favicon.ico",
                f"[client {source_ip}] script not found or unable to stat: /var/www/cgi-bin/test",
                "AH00558: apache2: Could not reliably determine the server's fully qualified domain name",
                "[mpm_prefork:notice] AH00163: Apache/2.4.41 (Ubuntu) configured -- resuming normal operations",
            ]
            level = random.choice(["notice", "warn", "error"])

        message = random.choice(error_messages)

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": web_server,
                    "dataset": dataset,
                    "category": ["web"],
                    "type": ["error"],
                    "id": self.randomizer.generate_uuid(),
                },
                "message": message,
                "log": {
                    "file": {
                        "path": log_path,
                    },
                    "level": level,
                },
                "source": {
                    "ip": source_ip,
                    "address": source_ip,
                },
                "related": {
                    "ip": [source_ip],
                },
            }
        )

        return event

    @register_attack_pattern(
        name="filebeat-ssh-brute-force",
        description="SSH brute force attack detected via auth logs",
        ttps=["T1110", "T1110.001", "T1021.004"],
        category=GeneratorCategory.IDENTITY,
        required_params=["host"],
        optional_params=["target_user", "attempts", "source_ip"],
        event_types=["filebeat"],
        detection_recommendations=[
            "Alert on multiple failed SSH authentications from single IP",
            "Monitor for authentication attempts to invalid usernames",
            "Track geographic anomalies in SSH connection sources",
        ],
    )
    def generate_ssh_brute_force(
        self,
        host: "Host",
        target_user: Optional["User"] = None,
        attempts: int = 20,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Generate SSH brute force attack events."""
        events = []
        source_ip = source_ip or self.randomizer.generate_ip()

        for i in range(attempts):
            is_last = i == attempts - 1
            event = self._generate_auth_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=attempts - i),
                host=host,
                user=target_user,
                is_malicious=not is_last,
                source_ip=source_ip,
            )
            if is_last:
                event["event"]["outcome"] = "success"
                event["message"] = event["message"].replace("Failed", "Accepted")
            events.append(event)

        return events

    @register_attack_pattern(
        name="filebeat-web-attack",
        description="Web application attack detected via access logs",
        ttps=["T1190", "T1059.007"],
        category=GeneratorCategory.NETWORK,
        required_params=["host"],
        optional_params=["count", "source_ip"],
        event_types=["filebeat"],
        detection_recommendations=[
            "Alert on suspicious URL patterns (path traversal, SQL injection)",
            "Monitor for unusual user agents (sqlmap, nikto)",
            "Track high error rates from single IPs",
        ],
    )
    def generate_web_attack(
        self,
        host: "Host",
        count: int = 30,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Generate web application attack events."""
        events = []
        source_ip = source_ip or self.randomizer.generate_ip()

        for i in range(count):
            dataset = random.choice(["apache.access", "nginx.access"])
            event = self._generate_web_access_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=count - i),
                host=host,
                dataset=dataset,
                is_malicious=True,
                source_ip=source_ip,
            )
            events.append(event)

            # Sometimes add corresponding error log
            if random.random() < 0.3:
                error_dataset = dataset.replace("access", "error")
                error_event = self._generate_web_error_event(
                    timestamp=datetime.now(timezone.utc) - timedelta(minutes=count - i),
                    host=host,
                    dataset=error_dataset,
                    is_malicious=True,
                    source_ip=source_ip,
                )
                events.append(error_event)

        return events

