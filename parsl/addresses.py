"""This module contains several helper functions which can be used to
find an address of the submitting system, for example to use as the
address parameter for HighThroughputExecutor.

The helper to use depends on the network environment around the submitter,
so some experimentation will probably be needed to choose the correct one.
"""

import logging
import platform
import requests
import socket
try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore
import struct
import typeguard
import psutil
from functools import lru_cache

from typing import Set, List, Callable

import parsl.ipv6 as ipv6

logger = logging.getLogger(__name__)

@lru_cache
def address_by_interface_ipv6(*,hostname=None, port=22):
    if hostname is None:
        hostname = socket.gethostname()
    all_the_interfaces = socket.getaddrinfo(hostname, port, socket.AF_INET6)
    ipv6_address = next(ip for *_,(ip, *_) in all_the_interfaces)
    return ipv6_address

def address_by_route() -> str:
    """Finds an address for the local host by querying the local routing table
       for the route to Google DNS.

       This will return an unusable value when the internet-facing address is
       not reachable from workers.
    """
    logger.debug("Finding address by querying local routing table")

    # original author unknown
    import socket
    if ipv6.DEFAULT_IP_VERSION == 'IPv6':
      ipv = socket.AF_INET6
      google_dns_ip = '2001:4860:4860::8888'
    else:
      ipv = socket.AF_INET
      google_dns_ip = '8.8.8.8'
    s = socket.socket(ipv, socket.SOCK_DGRAM)
    s.connect((google_dns_ip, 80))
    addr = s.getsockname()[0]
    s.close()
    logger.debug("Address found: {}".format(addr))
    if ipv6.DEFAULT_IP_VERSION == 'IPv6':
      assert ipv6.is_ipv6(addr), f'{addr=!r}'
    else:
      assert ipv6.is_ipv4(addr), f'{addr=!r}'
    return addr


@typeguard.typechecked
def address_by_query(timeout: float = 30) -> str:
    """Finds an address for the local host by querying ipify. This may
       return an unusable value when the host is behind NAT, or when the
       internet-facing address is not reachable from workers.
       Parameters:
       -----------

       timeout : float
          Timeout for the request in seconds. Default: 30s
    """
    logger.debug("Finding address by querying remote service")
    if ipv6.DEFAULT_IP_VERSION == 'IPv6':
      url = 'https://api64.ipify.org'
    else:
      url = 'https://api.ipify.org'
    response = requests.get(url, timeout=timeout)

    if response.status_code == 200:
        if 'or' in response.text:
          ipv4_addr, _, ipv6_addr = response.text.partition(' or ')
          assert ipv6.is_ipv4(ipv4_addr), f'{ipv4_addr=!r}, {response.text=!r}'
          assert ipv6.is_ipv6(ipv6_addr), f'{ipv6_addr=!r}, {response.text=!r}'
          if ipv6.DEFAULT_IP_VERSION == 'IPv6':
              addr = ipv6_addr
          else:
              addr = ipv4_addr
        else:
          addr=response.text
        logger.debug("Address found: {}".format(addr))
        return addr
    else:
        raise RuntimeError("Remote service returned unexpected HTTP status code {}".format(response.status_code))


def address_by_hostname() -> str:
    """Returns the hostname of the local host.

       This will return an unusable value when the hostname cannot be
       resolved from workers.
    """
    logger.debug("Finding address by using local hostname")
    addr = platform.node()
    logger.debug("Address found: {}".format(addr))
    return addr


@typeguard.typechecked
def address_by_interface(ifname: str) -> str:
    """Returns the IP address of the given interface name, e.g. 'eth0'

    This is taken from a Stack Overflow answer: https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python#24196955

    Parameters
    ----------
    ifname : str
        Name of the interface whose address is to be returned. Required.

    """
    assert fcntl is not None, "This function is not supported on your OS."
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', bytes(ifname[:15], 'utf-8'))
    )[20:24])


def get_all_addresses() -> Set[str]:
    """ Uses a combination of methods to determine possible addresses.

    Returns:
         list of addresses as strings
    """
    net_interfaces = psutil.net_if_addrs()

    s_addresses = set()
    resolution_functions = [address_by_route, address_by_query]  # type: List[Callable[[], str]]
    if ipv6.DEFAULT_IP_VERSION == 'IPv6':
        resolution_functions += [address_by_interface_ipv6]
    else:
        for interface in net_interfaces:
            try:
                s_addresses.add(address_by_interface(interface))
            except Exception:
                logger.exception("Ignoring failure to fetch address from interface {}".format(interface))
                pass
            resolution_functions += [address_by_hostname]
    for f in resolution_functions:
        try:
            s_addresses.add(f())
        except Exception:
            logger.exception("Ignoring an address finder exception")

    return s_addresses
