"""World state management for correlated data generation."""

import json
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from secgen.models.campaign import Campaign
from secgen.models.entities.host import Host, OSInfo
from secgen.models.entities.process_tree import ProcessNode, ProcessTree
from secgen.models.entities.user import User

if TYPE_CHECKING:
    from secgen.llm.generators.profiles import EntityProfileGenerator

logger = logging.getLogger(__name__)


@dataclass
class ThreatActor:
    """
    Represents a threat actor for campaign generation.

    Attributes:
        id: Unique identifier
        name: Threat actor name (APT29, FIN7, etc.)
        attacker_ips: List of attacker source IPs
        c2_domains: Command and control domains
        c2_ips: C2 IP addresses
        malware_families: Associated malware families
        ttps: MITRE ATT&CK TTPs
    """

    id: str
    name: str
    attacker_ips: list[str] = field(default_factory=list)
    c2_domains: list[str] = field(default_factory=list)
    c2_ips: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)


@dataclass
class NetworkTopology:
    """
    Network infrastructure configuration.

    Attributes:
        internal_subnets: Internal network ranges
        dns_servers: Internal DNS servers
        domain_controllers: Domain controller hostnames
        proxy_servers: Proxy server addresses
        gateway_ip: Default gateway
    """

    internal_subnets: list[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )
    dns_servers: list[str] = field(default_factory=lambda: ["10.0.0.2", "10.0.0.3"])
    domain_controllers: list[str] = field(default_factory=lambda: ["dc-01", "dc-02"])
    proxy_servers: list[str] = field(default_factory=list)
    gateway_ip: str = "10.0.0.1"


@dataclass
class BehaviorProfile:
    """
    User behavior profile for realistic event generation.

    Attributes:
        role: Job role/title
        department: Department name
        typical_applications: List of typical applications
        working_hours: Typical working hours
        data_access: Types of data typically accessed
        anomaly_indicators: List of anomalous behaviors
        privilege_level: standard, elevated, or admin
    """

    role: str
    department: str = "General"
    typical_applications: list[str] = field(default_factory=list)
    working_hours: str = "8am-5pm weekdays"
    data_access: list[str] = field(default_factory=list)
    network_behavior: dict[str, Any] = field(default_factory=dict)
    anomaly_indicators: list[dict[str, Any]] = field(default_factory=list)
    privilege_level: str = "standard"


@dataclass
class World:
    """
    Persistent world state for correlated data generation.

    The World maintains consistent entity identifiers across all generated
    events, enabling proper correlation in Elastic Security Solution features
    like Timeline, Entity Analytics, and Analyzer.

    Key correlation identifiers:
    - host.id: Primary host identifier
    - user.name: Primary user identifier
    - process.entity_id: Process tracking within a host

    Attributes:
        hosts: Dictionary of host.id -> Host entity
        users: Dictionary of user.name -> User entity
        process_trees: Dictionary of host.id -> ProcessTree
        network: Network topology configuration
        threat_actors: Available threat actors for campaigns
        active_campaigns: Currently running campaigns
        created_at: World creation timestamp
        behavior_profiles: Dictionary of user.name -> BehaviorProfile
        industry: Industry vertical for profile generation
    """

    hosts: dict[str, Host] = field(default_factory=dict)
    users: dict[str, User] = field(default_factory=dict)
    process_trees: dict[str, ProcessTree] = field(default_factory=dict)
    network: NetworkTopology = field(default_factory=NetworkTopology)
    threat_actors: list[ThreatActor] = field(default_factory=list)
    active_campaigns: list[Campaign] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    behavior_profiles: dict[str, BehaviorProfile] = field(default_factory=dict)
    industry: str = "technology"

    # Host templates for generation
    HOST_TEMPLATES = [
        "workstation",
        "linux_workstation",
        "mac_workstation",
        "server",
        "web_server",
        "db_server",
        "domain_controller",
        "file_server",
        "mail_server",
        "docker_host",
        "jenkins",
    ]

    # User templates for generation
    USER_TEMPLATES = [
        "standard",
        "admin",
        "service",
        "system_linux",
        "system_windows",
    ]

    def get_or_create_host(
        self,
        template: str = "workstation",
        name: str | None = None,
    ) -> Host:
        """
        Get an existing host by name or create a new one.

        Args:
            template: Host template type
            name: Optional specific hostname

        Returns:
            Host entity (existing or newly created)
        """
        # Check for existing host by name
        if name:
            for host in self.hosts.values():
                if host.name == name:
                    return host

        # Create new host
        host = Host.generate(template=template, name_override=name)
        self.hosts[host.id] = host

        # Initialize process tree for host
        self.process_trees[host.id] = ProcessTree(
            host_id=host.id,
            boot_id=host.boot_id,
        )

        return host

    def get_host_by_name(self, name: str) -> Host | None:
        """Get a host by hostname."""
        for host in self.hosts.values():
            if host.name == name:
                return host
        return None

    def get_host_by_id(self, host_id: str) -> Host | None:
        """Get a host by host.id."""
        return self.hosts.get(host_id)

    def get_random_host(self, os_family: str | None = None) -> Host | None:
        """
        Get a random host from the world.

        Args:
            os_family: Optional filter by OS family (linux, windows, macos)

        Returns:
            Random Host or None if no hosts exist
        """
        hosts = list(self.hosts.values())
        if os_family:
            hosts = [h for h in hosts if h.os.family == os_family]
        return random.choice(hosts) if hosts else None

    def get_or_create_user(
        self,
        template: str = "standard",
        name: str | None = None,
        domain: str | None = None,
    ) -> User:
        """
        Get an existing user by name or create a new one.

        Args:
            template: User template type
            name: Optional specific username
            domain: Optional domain

        Returns:
            User entity (existing or newly created)
        """
        # Check for existing user by name
        if name and name in self.users:
            return self.users[name]

        # Create new user
        user = User.generate(template=template, domain=domain, name_override=name)
        self.users[user.name] = user

        return user

    def get_user_by_name(self, name: str) -> User | None:
        """Get a user by username."""
        return self.users.get(name)

    def get_random_user(
        self,
        user_type: str | None = None,
        privileged: bool | None = None,
    ) -> User | None:
        """
        Get a random user from the world.

        Args:
            user_type: Optional filter by user type
            privileged: Optional filter by privilege status

        Returns:
            Random User or None if no users exist
        """
        users = list(self.users.values())
        if user_type:
            users = [u for u in users if u.user_type == user_type]
        if privileged is not None:
            users = [u for u in users if u.is_privileged == privileged]
        return random.choice(users) if users else None

    def assign_user_to_host(self, user: User, host: Host) -> None:
        """Assign a user to regularly use a host."""
        user.assign_to_host(host.id)

    def get_process_tree(self, host_id: str) -> ProcessTree | None:
        """Get the process tree for a host."""
        return self.process_trees.get(host_id)

    def spawn_process(
        self,
        host_id: str,
        name: str,
        executable: str,
        args: list[str],
        working_directory: str,
        user: User,
        parent_id: str | None = None,
        is_session_leader: bool = False,
    ) -> ProcessNode | None:
        """
        Spawn a process on a host.

        Args:
            host_id: Host to spawn process on
            name: Process name
            executable: Executable path
            args: Command line arguments
            working_directory: Working directory
            user: User running the process
            parent_id: Parent process entity_id
            is_session_leader: Whether this is a session leader

        Returns:
            ProcessNode or None if host not found
        """
        tree = self.get_process_tree(host_id)
        if not tree:
            return None

        return tree.spawn_process(
            name=name,
            executable=executable,
            args=args,
            working_directory=working_directory,
            user_name=user.name,
            user_id=user.id,
            parent_id=parent_id,
            is_session_leader=is_session_leader,
        )

    def spawn_process_chain(
        self,
        host_id: str,
        process_infos: list[dict[str, Any]],
        user: User,
    ) -> list[ProcessNode]:
        """
        Spawn a chain of processes on a host.

        Args:
            host_id: Host to spawn processes on
            process_infos: List of process info dicts
            user: User running the processes

        Returns:
            List of ProcessNodes or empty list if host not found
        """
        tree = self.get_process_tree(host_id)
        if not tree:
            return []

        return tree.spawn_chain(process_infos, user.name, user.id)

    def reboot_host(self, host_id: str) -> None:
        """
        Simulate rebooting a host.

        Clears the process tree and generates new boot_id.

        Args:
            host_id: Host to reboot
        """
        host = self.get_host_by_id(host_id)
        if host:
            host.reboot()
            # Clear and reinitialize process tree
            self.process_trees[host_id] = ProcessTree(
                host_id=host_id,
                boot_id=host.boot_id,
            )

    def add_threat_actor(self, threat_actor: ThreatActor) -> None:
        """Add a threat actor to the world."""
        self.threat_actors.append(threat_actor)

    def get_random_threat_actor(self) -> ThreatActor | None:
        """Get a random threat actor."""
        return random.choice(self.threat_actors) if self.threat_actors else None

    def add_campaign(self, campaign: Campaign) -> None:
        """Add an active campaign to the world."""
        self.active_campaigns.append(campaign)

    def populate(
        self,
        num_hosts: int = 10,
        num_users: int = 20,
        host_distribution: dict[str, int] | None = None,
        user_distribution: dict[str, int] | None = None,
    ) -> None:
        """
        Populate the world with hosts and users.

        Args:
            num_hosts: Total number of hosts to create
            num_users: Total number of users to create
            host_distribution: Optional dict of template -> count
            user_distribution: Optional dict of template -> count
        """
        # Default distributions
        if host_distribution is None:
            host_distribution = {
                "workstation": int(num_hosts * 0.5),
                "server": int(num_hosts * 0.2),
                "web_server": int(num_hosts * 0.1),
                "db_server": int(num_hosts * 0.1),
                "domain_controller": max(1, int(num_hosts * 0.05)),
                "linux_workstation": int(num_hosts * 0.05),
            }

        if user_distribution is None:
            user_distribution = {
                "standard": int(num_users * 0.7),
                "admin": int(num_users * 0.1),
                "service": int(num_users * 0.15),
                "system_linux": 2,
                "system_windows": 2,
            }

        # Create hosts
        for template, count in host_distribution.items():
            for _ in range(count):
                self.get_or_create_host(template=template)

        # Create users
        for template, count in user_distribution.items():
            for _ in range(count):
                self.get_or_create_user(template=template)

        # Assign users to hosts
        hosts_list = list(self.hosts.values())
        for user in self.users.values():
            if user.user_type in ["standard", "admin"]:
                # Assign to 1-3 random hosts
                num_assignments = random.randint(1, 3)
                assigned_hosts = random.sample(hosts_list, min(num_assignments, len(hosts_list)))
                for host in assigned_hosts:
                    self.assign_user_to_host(user, host)

        # Add default threat actors
        self._add_default_threat_actors()

    def load_behavior_profiles(
        self,
        profile_generator: "EntityProfileGenerator",
        industry: str | None = None,
        org_size: str = "medium",
    ) -> int:
        """
        Load behavior profiles from LLM generator and assign to users.

        Args:
            profile_generator: EntityProfileGenerator instance
            industry: Industry vertical (uses self.industry if None)
            org_size: Organization size

        Returns:
            Number of profiles assigned
        """
        industry = industry or self.industry
        self.industry = industry

        try:
            personas = profile_generator.get_personas(industry=industry, org_size=org_size)
        except Exception as e:
            logger.warning(f"Failed to load behavior profiles: {e}")
            return 0

        if not personas:
            logger.warning(f"No personas found for industry '{industry}'")
            return 0

        # Group personas by privilege level
        personas_by_privilege = {"standard": [], "elevated": [], "admin": []}
        for persona in personas:
            level = persona.get("privilege_level", "standard")
            if level in personas_by_privilege:
                personas_by_privilege[level].append(persona)
            else:
                personas_by_privilege["standard"].append(persona)

        assigned_count = 0

        for user in self.users.values():
            # Match user type to privilege level
            if user.is_privileged or user.user_type == "admin":
                matching_personas = personas_by_privilege.get("admin", [])
            elif user.user_type == "service":
                continue  # Skip service accounts
            else:
                matching_personas = personas_by_privilege.get("standard", [])

            if not matching_personas:
                matching_personas = personas  # Fall back to all personas

            # Assign random persona
            persona = random.choice(matching_personas)
            typical = persona.get("typical_behavior", {})

            profile = BehaviorProfile(
                role=persona.get("role", "Employee"),
                department=persona.get("department", "General"),
                typical_applications=typical.get("applications", []),
                working_hours=typical.get("working_hours", "8am-5pm weekdays"),
                data_access=typical.get("data_access", []),
                network_behavior=typical.get("network", {}),
                anomaly_indicators=persona.get("anomaly_indicators", []),
                privilege_level=persona.get("privilege_level", "standard"),
            )

            self.behavior_profiles[user.name] = profile
            assigned_count += 1

        logger.info(f"Assigned {assigned_count} behavior profiles from {industry} industry")
        return assigned_count

    def get_behavior_profile(self, user_name: str) -> BehaviorProfile | None:
        """Get behavior profile for a user."""
        return self.behavior_profiles.get(user_name)

    def get_typical_applications(self, user_name: str) -> list[str]:
        """Get typical applications for a user based on their profile."""
        profile = self.get_behavior_profile(user_name)
        if profile:
            return profile.typical_applications
        return []

    def is_anomalous_for_user(
        self,
        user_name: str,
        process_name: str | None = None,
        data_access: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Check if an action would be anomalous for a user.

        Args:
            user_name: Username to check
            process_name: Process name to check
            data_access: Data type being accessed

        Returns:
            Tuple of (is_anomalous, reason)
        """
        profile = self.get_behavior_profile(user_name)
        if not profile:
            return False, None

        for indicator in profile.anomaly_indicators:
            # Check process-based anomaly
            if process_name and indicator.get("indicator") == process_name:
                return True, indicator.get("reason", "Anomalous process for role")

            # Check data access anomaly
            if data_access and indicator.get("indicator") == data_access:
                return True, indicator.get("reason", "Anomalous data access for role")

        return False, None

    def get_users_by_profile_role(self, role: str) -> list[User]:
        """Get users with a specific profile role."""
        matching = []
        for user_name, profile in self.behavior_profiles.items():
            if profile.role.lower() == role.lower():
                user = self.users.get(user_name)
                if user:
                    matching.append(user)
        return matching

    def _add_default_threat_actors(self) -> None:
        """Add default threat actors for campaign generation."""
        default_actors = [
            ThreatActor(
                id="apt29",
                name="APT29 (Cozy Bear)",
                attacker_ips=["203.0.113.10", "203.0.113.11"],
                c2_domains=["cozy-bear.evil.com", "apt29-c2.malware.net"],
                c2_ips=["198.51.100.10", "198.51.100.11"],
                malware_families=["WellMess", "WellMail", "SoreFang"],
                ttps=["T1566", "T1059", "T1053", "T1027"],
            ),
            ThreatActor(
                id="fin7",
                name="FIN7",
                attacker_ips=["203.0.113.20", "203.0.113.21"],
                c2_domains=["fin7-ops.badactor.com", "carbanak.threat.xyz"],
                c2_ips=["198.51.100.20", "198.51.100.21"],
                malware_families=["Carbanak", "GRIFFON", "BOOSTWRITE"],
                ttps=["T1566.001", "T1059.001", "T1055", "T1003"],
            ),
            ThreatActor(
                id="lazarus",
                name="Lazarus Group",
                attacker_ips=["203.0.113.30", "203.0.113.31"],
                c2_domains=["lazarus.darkweb.org", "hidden-cobra.threat.net"],
                c2_ips=["198.51.100.30", "198.51.100.31"],
                malware_families=["Manuscrypt", "ThreatNeedle", "COPPERHEDGE"],
                ttps=["T1566.002", "T1059.003", "T1140", "T1071"],
            ),
        ]

        for actor in default_actors:
            self.add_threat_actor(actor)

    def save(self, path: str) -> None:
        """
        Save world state to a JSON file.

        Args:
            path: File path to save to
        """
        state = {
            "created_at": self.created_at,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "hosts": {
                host_id: {
                    "id": host.id,
                    "name": host.name,
                    "ip": host.ip,
                    "mac": host.mac,
                    "os": host.os.to_dict(),
                    "architecture": host.architecture,
                    "agent_id": host.agent_id,
                    "boot_id": host.boot_id,
                    "domain": host.domain,
                    "geo": host.geo,
                }
                for host_id, host in self.hosts.items()
            },
            "users": {
                user_name: {
                    "name": user.name,
                    "id": user.id,
                    "domain": user.domain,
                    "email": user.email,
                    "full_name": user.full_name,
                    "user_type": user.user_type,
                    "roles": user.roles,
                    "assigned_hosts": user.assigned_hosts,
                    "groups": user.groups,
                    "is_privileged": user.is_privileged,
                }
                for user_name, user in self.users.items()
            },
            "network": {
                "internal_subnets": self.network.internal_subnets,
                "dns_servers": self.network.dns_servers,
                "domain_controllers": self.network.domain_controllers,
                "proxy_servers": self.network.proxy_servers,
                "gateway_ip": self.network.gateway_ip,
            },
            "threat_actors": [
                {
                    "id": actor.id,
                    "name": actor.name,
                    "attacker_ips": actor.attacker_ips,
                    "c2_domains": actor.c2_domains,
                    "c2_ips": actor.c2_ips,
                    "malware_families": actor.malware_families,
                    "ttps": actor.ttps,
                }
                for actor in self.threat_actors
            ],
            "behavior_profiles": {
                user_name: {
                    "role": profile.role,
                    "department": profile.department,
                    "typical_applications": profile.typical_applications,
                    "working_hours": profile.working_hours,
                    "data_access": profile.data_access,
                    "network_behavior": profile.network_behavior,
                    "anomaly_indicators": profile.anomaly_indicators,
                    "privilege_level": profile.privilege_level,
                }
                for user_name, profile in self.behavior_profiles.items()
            },
            "industry": self.industry,
        }

        filepath = Path(path)
        with filepath.open("w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "World":
        """
        Load world state from a JSON file.

        Args:
            path: File path to load from

        Returns:
            Loaded World instance
        """
        filepath = Path(path)
        with filepath.open("r", encoding="utf-8") as f:
            state = json.load(f)

        world = cls(created_at=state.get("created_at", datetime.now(timezone.utc).isoformat()))

        # Load network topology
        if "network" in state:
            net = state["network"]
            world.network = NetworkTopology(
                internal_subnets=net.get("internal_subnets", []),
                dns_servers=net.get("dns_servers", []),
                domain_controllers=net.get("domain_controllers", []),
                proxy_servers=net.get("proxy_servers", []),
                gateway_ip=net.get("gateway_ip", "10.0.0.1"),
            )

        # Load hosts
        for host_id, host_data in state.get("hosts", {}).items():
            os_data = host_data.get("os", {})
            os_info = OSInfo(
                family=os_data.get("family", "linux"),
                name=os_data.get("name", "Linux"),
                full=os_data.get("full", "Ubuntu 22.04"),
                version=os_data.get("version", "22.04"),
                kernel=os_data.get("kernel"),
                platform=os_data.get("platform"),
                type=os_data.get("type"),
            )

            host = Host(
                id=host_data["id"],
                name=host_data["name"],
                ip=host_data["ip"],
                mac=host_data["mac"],
                os=os_info,
                architecture=host_data.get("architecture", "x86_64"),
                agent_id=host_data.get("agent_id", ""),
                boot_id=host_data.get("boot_id", ""),
                domain=host_data.get("domain"),
                geo=host_data.get("geo"),
            )
            world.hosts[host_id] = host

            # Initialize process tree
            world.process_trees[host_id] = ProcessTree(
                host_id=host_id,
                boot_id=host.boot_id,
            )

        # Load users
        for user_name, user_data in state.get("users", {}).items():
            user = User(
                name=user_data["name"],
                id=user_data["id"],
                domain=user_data.get("domain"),
                email=user_data.get("email"),
                full_name=user_data.get("full_name"),
                user_type=user_data.get("user_type", "standard"),
                roles=user_data.get("roles", []),
                assigned_hosts=user_data.get("assigned_hosts", []),
                groups=user_data.get("groups", []),
                is_privileged=user_data.get("is_privileged", False),
            )
            world.users[user_name] = user

        # Load threat actors
        for actor_data in state.get("threat_actors", []):
            actor = ThreatActor(
                id=actor_data["id"],
                name=actor_data["name"],
                attacker_ips=actor_data.get("attacker_ips", []),
                c2_domains=actor_data.get("c2_domains", []),
                c2_ips=actor_data.get("c2_ips", []),
                malware_families=actor_data.get("malware_families", []),
                ttps=actor_data.get("ttps", []),
            )
            world.add_threat_actor(actor)

        # Load behavior profiles
        world.industry = state.get("industry", "technology")
        for user_name, profile_data in state.get("behavior_profiles", {}).items():
            profile = BehaviorProfile(
                role=profile_data.get("role", "Employee"),
                department=profile_data.get("department", "General"),
                typical_applications=profile_data.get("typical_applications", []),
                working_hours=profile_data.get("working_hours", "8am-5pm weekdays"),
                data_access=profile_data.get("data_access", []),
                network_behavior=profile_data.get("network_behavior", {}),
                anomaly_indicators=profile_data.get("anomaly_indicators", []),
                privilege_level=profile_data.get("privilege_level", "standard"),
            )
            world.behavior_profiles[user_name] = profile

        return world

    def summary(self) -> dict[str, Any]:
        """
        Get a summary of the world state.

        Returns:
            Dictionary with world statistics
        """
        host_by_os = {}
        for host in self.hosts.values():
            os_family = host.os.family
            host_by_os[os_family] = host_by_os.get(os_family, 0) + 1

        user_by_type = {}
        for user in self.users.values():
            user_by_type[user.user_type] = user_by_type.get(user.user_type, 0) + 1

        return {
            "created_at": self.created_at,
            "total_hosts": len(self.hosts),
            "hosts_by_os": host_by_os,
            "total_users": len(self.users),
            "users_by_type": user_by_type,
            "threat_actors": len(self.threat_actors),
            "active_campaigns": len(self.active_campaigns),
            "behavior_profiles": len(self.behavior_profiles),
            "industry": self.industry,
        }
