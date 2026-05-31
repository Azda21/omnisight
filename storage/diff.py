from dataclasses import dataclass, field


@dataclass
class HostDelta:
    ip: str
    new_ports: list = field(default_factory=list)
    closed_ports: list = field(default_factory=list)
    changed_services: list = field(default_factory=list)   # (port, old, new)
    new_findings: list = field(default_factory=list)         # (port, finding)
    resolved_findings: list = field(default_factory=list)    # (port, finding)
    new_cves: list = field(default_factory=list)             # (port, cve_id)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_ports or self.closed_ports or self.changed_services
            or self.new_findings or self.resolved_findings or self.new_cves
        )

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "new_ports": self.new_ports,
            "closed_ports": self.closed_ports,
            "changed_services": [
                {"port": p, "old": o, "new": n} for p, o, n in self.changed_services
            ],
            "new_findings": [{"port": p, "finding": f} for p, f in self.new_findings],
            "resolved_findings": [{"port": p, "finding": f} for p, f in self.resolved_findings],
            "new_cves": [{"port": p, "cve": c} for p, c in self.new_cves],
            "has_changes": self.has_changes,
        }


class DiffEngine:
    """Compares two scan snapshots and reports what changed on the network.

    A point-in-time scan tells you the state now; the security value compounds
    when you can answer *what changed since last time* — a port that opened, a
    service that was downgraded, a host that started accepting anonymous logins.
    This turns OmniSight from a search index into a monitoring tool.
    """

    @staticmethod
    def _index(records: list[dict]) -> dict[tuple[str, int], dict]:
        out = {}
        for r in records:
            out[(r.get("ip"), r.get("port"))] = r
        return out

    def diff(self, old: list[dict], new: list[dict]) -> list[HostDelta]:
        old_idx = self._index(old)
        new_idx = self._index(new)

        ips = {ip for ip, _ in old_idx} | {ip for ip, _ in new_idx}
        deltas: list[HostDelta] = []

        for ip in sorted(ips):
            delta = HostDelta(ip=ip)
            old_ports = {p for (i, p) in old_idx if i == ip}
            new_ports = {p for (i, p) in new_idx if i == ip}

            delta.new_ports = sorted(new_ports - old_ports)
            delta.closed_ports = sorted(old_ports - new_ports)

            for port in sorted(old_ports & new_ports):
                o = old_idx[(ip, port)]
                n = new_idx[(ip, port)]

                o_svc = f"{o.get('service', '')} {o.get('version', '')}".strip()
                n_svc = f"{n.get('service', '')} {n.get('version', '')}".strip()
                if o_svc != n_svc and (o_svc or n_svc):
                    delta.changed_services.append((port, o_svc, n_svc))

                o_find = set(o.get("findings") or [])
                n_find = set(n.get("findings") or [])
                for f in sorted(n_find - o_find):
                    delta.new_findings.append((port, f))
                for f in sorted(o_find - n_find):
                    delta.resolved_findings.append((port, f))

                o_cves = {c.get("id") for c in (o.get("cves") or [])}
                n_cves = {c.get("id") for c in (n.get("cves") or [])}
                for c in sorted(n_cves - o_cves):
                    delta.new_cves.append((port, c))

            # New ports may themselves carry findings/cves worth surfacing.
            for port in delta.new_ports:
                n = new_idx[(ip, port)]
                for f in (n.get("findings") or []):
                    delta.new_findings.append((port, f))
                for c in (n.get("cves") or []):
                    if c.get("id"):
                        delta.new_cves.append((port, c["id"]))

            if delta.has_changes:
                deltas.append(delta)

        return deltas

    def summarize(self, deltas: list[HostDelta]) -> dict:
        return {
            "hosts_changed": len(deltas),
            "ports_opened": sum(len(d.new_ports) for d in deltas),
            "ports_closed": sum(len(d.closed_ports) for d in deltas),
            "services_changed": sum(len(d.changed_services) for d in deltas),
            "findings_new": sum(len(d.new_findings) for d in deltas),
            "findings_resolved": sum(len(d.resolved_findings) for d in deltas),
            "cves_new": sum(len(d.new_cves) for d in deltas),
        }
