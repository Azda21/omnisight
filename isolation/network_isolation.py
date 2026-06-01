# Network isolation helpers - ensures your own IPs are never targeted

from typing import List


def filter_my_network(all_targets: List[str], my_ips_path: str = "config/my_network.conf") -> List[str]:
    try:
        with open(my_ips_path, "r", encoding="utf-8") as f:
            my_ips = {l.strip() for l in f if l.strip()}
    except FileNotFoundError:
        my_ips = set()

    return [t for t in all_targets if t not in my_ips]

class IsolationManager:
    def __init__(self, my_ips_path: str = "config/my_network.conf"):
        self.my_ips_path = my_ips_path

    def is_protected(self, target: str) -> bool:
        try:
            with open(self.my_ips_path, "r", encoding="utf-8") as f:
                my_ips = {l.strip() for l in f if l.strip()}
            return target in my_ips
        except FileNotFoundError:
            return False

