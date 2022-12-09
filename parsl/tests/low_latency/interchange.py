import logging
import argparse

from multiprocessing import Process
import zmq

from constants import CLIENT_IP_FILE, INTERCHANGE_IP_FILE
from parsl.addresses import address_by_interface

import parsl.ipv6 as ipv6

logger = logging.getLogger(__name__)


def dealer_interchange(manager_ip=None, manager_port=5559,
                       worker_port=5560):
    ip_version = ipv6.ip_version_from_optional([manager_ip])
    manager_ip = manager_ip or ipv6.loopback_address(ip_version)
    context = ipv6.context(ip_version) 
    incoming = context.socket(zmq.ROUTER)
    outgoing = context.socket(zmq.DEALER)

    incoming.connect(ipv6.tcp_url(manager_ip, manager_port))
    outgoing.bind("tcp://*:{}".format(worker_port))

    poller = zmq.Poller()
    poller.register(incoming, zmq.POLLIN)
    poller.register(outgoing, zmq.POLLIN)

    while True:
        socks = dict(poller.poll(1))

        if socks.get(incoming) == zmq.POLLIN:
            message = incoming.recv_multipart()
            logger.debug("[interchange] New task {}".format(message))
            outgoing.send_multipart(message)

        if socks.get(outgoing) == zmq.POLLIN:
            message = outgoing.recv_multipart()
            logger.debug("[interchange] New result {}".format(message))
            incoming.send_multipart(message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-port", default=5559, type=int,
                        help="Port for workers to communicate on")
    parser.add_argument("--client-port", default=5560, type=int,
                        help="Port for client to communicate on")
    parser.add_argument("--localhost", default=False, action="store_true",
                        help="True if communication is on localhost")
    args = parser.parse_args()

    if not args.localhost:
        with open(CLIENT_IP_FILE, "r") as fh:
            client_ip = fh.read().strip()
        print("Read IP {} from file {}".format(client_ip, CLIENT_IP_FILE))

        interchange_ip = address_by_interface("eth0")
        with open(INTERCHANGE_IP_FILE, "w") as fh:
            fh.write(interchange_ip)
        print("Wrote IP address {} to file {}"
              .format(interchange_ip, INTERCHANGE_IP_FILE))
    else:
        client_ip = ipv6.loopback_address()

    interchange = Process(target=dealer_interchange,
                          kwargs={"manager_ip": client_ip,
                                  "manager_port": args.client_port,
                                  "worker_port": args.worker_port})
    interchange.daemon = True
    interchange.start()
    interchange.join()
