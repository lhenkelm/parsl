from typing import Union, Optional, Sequence, Tuple

import zmq
import socket

VALID_VERSIONS = {'IPv4', 'IPv6'}
DEFAULT_IP_VERSION = 'IPv6'
assert DEFAULT_IP_VERSION in VALID_VERSIONS

class ConflictingIPFormats(ValueError):
  pass

class UnknownIPVersion(ValueError):
  pass

def is_ipv6(address : str) -> bool:
  return ':' in address

def is_ipv4(address : str) -> bool:
  return '.' in address

def _unchecked_canonical_version(version: str) -> str:
  version = version.upper()
  version=version.replace('V', 'v')
  version=version.replace('_', '')
  version=version.replace('-', '')
  return version

def _canonical_version_is_valid(version: str) -> bool:
  return version in VALID_VERSIONS

def canonical_version(version : str) -> str:
  canonical = _unchecked_canonical_version(version)
  if not _canonical_version_is_valid(canonical):
    raise ValueError(f'not a valid version: {version!r}. Valid versions are: {VALID_VERSIONS}')
  return canonical

def is_valid_ip_version(version: str) -> bool:
  return _canonical_version_is_valid(_unchecked_canonical_version(version))

def consistent_ip_version(addresses : str, *, suggest : Optional[str] = None) -> str:
  """
  Guess the IP version to use for one or more comma-separated IP addresses,
  raise a ValueError if no consistent value may be guessed.
  """
  maybe_ipv4 = is_ipv4(addresses)
  maybe_ipv6 = is_ipv6(addresses)
 
  if suggest:
    version = canonical_version(suggest)
  elif not(maybe_ipv4 or maybe_ipv6):
    raise UnknownIPVersion(f'cannot determine IP version from {addresses=!r}, please specify using "suggest" kwarg')
  elif maybe_ipv4 and maybe_ipv6:
      raise ConflictingIPFormats(f'cannot determine IP version from {addresses=!r} (conflicting formats/versions?)')
  elif maybe_ipv4:
    version = 'IPv4'
  else:
    assert maybe_ipv6, f'{addresses=!r}'
    version = 'IPv6'
  
  if version == 'IPv6':
    if any(is_ipv4(addr) for addr in addresses.split(',')):
      raise ValueError(f'not all addresses are valid for IPv6: {addresses=!r}')
  if version == 'IPv4':
    if any(is_ipv6(addr) for addr in addresses.split(',')):
      raise ValueError(f'not all addresses are valid for IPv4: {addresses=!r}')
  assert _canonical_version_is_valid(version)
  return version

def ip_version_from_optional(addresses : Sequence[Union[str, None]]) -> str:
  """
  Guess an IP version from several adresses, all or some of which may be optional.
  """
  combined = ','.join([a for a in addresses if a])
  if combined:
    return consistent_ip_version(combined)
  else:
    return DEFAULT_IP_VERSION


def context(*args, ip_version : str = 'IPv6', **kwargs) -> zqm.Context:
  """
  0MQ Context factory that enables IPv6 by default.
  """
  context = zmq.Context(*args, **kwargs)
  if canonical_version(ip_version) == 'IPv6':
    context.setsockopt(zmq.IPV6, 1)
  return context

def socket(ip_version: str = 'IPv6', *args, **kwargs) -> socket.socket:
  if canonical_version(ip_version) == 'IPv6':
    socket_family = socket.AF_INET6
  else:
    socket_family = socket.AF_INET
  return socket.socket(socket_family, *args, **kwargs)

def loopback_address(ip_version : str = 'IPv6') -> str:
  if canonical_version(ip_version) == 'IPv6':
    return '::1'
  else:
    return '127.0.0.1'

def any_address(ip_version : str = 'IPv6') -> str:
  if canonical_version(ip_version) == 'IPv6':
    return '::'
  else:
    return '0.0.0.0'
  
def url(protocol : str, address: str, port: Union[int, str, None] = None, *, ip_version = None) -> str:
  """
  Construct a URL, taking care to disambiguate IP address and port if the IP uses IPv6 format.
    
  If no port is specified (default), the URL ends at the IP address.
  If a port is specified, it is separated from the IP by a colon (':').
  
  Specialisations for UDP (udp_url(...)) and TCP (tcp_url(...)) are provided below, 
  and probably result in more readable code than the generic implementation.
  """
  try:
    ip_version = consistent_ip_version(address, suggest=ip_version)
  except UnknownIPVersion: # todo: kinda slow, better to use flow control
    ip_version = DEFAULT_IP_VERSION

  if port is None:
    port_str = ''
  else:
    port_str = f':{port}'

  # if the address does not contain ':', there is no need to disambiguate
  if ip_version == 'IPv6' and ':' in address:
    template = '{protocol}://[{address}]{port_str}'
  else:
    template = '{protocol}://{address}{port_str}'
  return template.format(protocol=protocol, address=address, port_str=port_str)

def tcp_url(*args, **kwargs) -> str:
  return url('tcp', *args, **kwargs)

def udp_url(*args, **kwargs) -> str:
  return url('udp', *args, **kwargs)

def split_url(url : str) -> Tuple[str, str, Union[str, None]]:
  """
  Split a URL into protocol, address and port.
  
  If the URL does not contain a port, the 3rd returned value is None.
  """
  protocol, _, remainder = url.partition('://')
  if remainder.startswith('['):
    remainder = remainder.lstrip('[')
    address, _, port = remainder.partition(']:')
    assert is_ipv6(address)
  else:
    address, _, port = remainder.partition(':')
    assert is_ipv4(address)
  port = port or None
  return protocol, address, port
  
def ip_version_from_urls(urls : Sequence[Union[str, None]]) -> str:
  addresses = [split_url(url)[1] for url in urls if url is not None]
  return ip_version_from_optional(addresses)
