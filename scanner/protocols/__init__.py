from .http import HTTPProbe
from .ssh import SSHProbe
from .ftp import FTPProbe
from .smtp import SMTPProbe
from .mysql import MySQLProbe
from .rdp import RDPProbe
from .mqtt import MQTTProbe
from .modbus import ModbusProbe
from .rtsp import RTSPProbe

PROTOCOL_MAP = {
    "http": HTTPProbe,
    "https": HTTPProbe,
    "ssh": SSHProbe,
    "ftp": FTPProbe,
    "smtp": SMTPProbe,
    "mysql": MySQLProbe,
    "rdp": RDPProbe,
    "mqtt": MQTTProbe,
    "modbus": ModbusProbe,
    "rtsp": RTSPProbe,
}

__all__ = ["PROTOCOL_MAP", "HTTPProbe", "SSHProbe", "FTPProbe", "SMTPProbe",
           "MySQLProbe", "RDPProbe", "MQTTProbe", "ModbusProbe", "RTSPProbe"]
