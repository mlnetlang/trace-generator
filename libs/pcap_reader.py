from typing import Dict
from models.flow import Flow
import warnings
from subprocess import Popen, PIPE

import numpy as np
import pyshark.tshark.tshark
import pyshark
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class PcapReader(object):
    """Reader object for extracting features from .pcap files
    """

    def __init__(self, verbose=False):
        """Reader object for extracting features from .pcap files

        Args:
        --------
            verbose (bool, optional): Boolean indicating whether to be verbose in reading
        """
        # Set verbosity level
        self.verbose = verbose

    def read(self, path: str) -> dict:
        """Read TCP and UDP packets from .pcap file given by path.
            Automatically choses fastest available backend to use.

        Args:
        --------
            path (str): Path to .pcap file to read.

        Raises:
        -------
            ModuleNotFoundError: If TShark is not installed
            OSError: If there is problem reading file (usually caused because not being able to allocate memory)
        Returns:
        -------
            dict: Dictionary of flow_key -> Flow()
            Where features consist of:

                0) Filename of capture
                1) Protocol TCP/UDP
                2) TCP/UDP stream identifier
                3) Timestamp of packet
                4) Length of packet
                5) IP packet source
                6) IP packet destination
                7) TCP/UDP packet source port
                8) TCP/UDP packet destination port
                9) SSL/TLS certificate if exists, else None
        """
        # print(time.time(), ":\tstart reading pcap")
        # If verbose, print which file is currently being read
        if self.verbose:
            print("Reading {}...".format(path))
        # print(time.time(), ":\tend reading pcap")
        # Check if we can use fast tshark read or slow pyshark read
        packets = self.read_pyshark(path)
        return self.combine(packets)

    def read_tshark(self, path: str) -> np.ndarray:
        """Read TCP and UDP packets from file given by path using tshark backend
            Automatically choses fastest available backend to use.

        Args:
        --------
            path (str): Path to .pcap file to read.

        Returns:
        -------
            np.ndarray: Array of shape=(n_packets, n_features)
            Where features consist of:

                0) Filename of capture
                1) Protocol TCP/UDP
                2) TCP/UDP stream identifier
                3) Timestamp of packet
                4) Length of packet
                5) IP packet source
                6) IP packet destination
                7) TCP/UDP packet source port
                8) TCP/UDP packet destination port
                9) SSL/TLS certificate if exists, else None
        """
        # Create Tshark command
        command = ["tshark", "-r", path, "-Tfields",
                   "-e", "frame.time_epoch",
                   "-e", "tcp.stream",
                   "-e", "udp.stream",
                   "-e", "ip.proto",
                   "-e", "ip.src",
                   "-e", "tcp.srcport",
                   "-e", "udp.srcport",
                   "-e", "ip.dst",
                   "-e", "tcp.dstport",
                   "-e", "udp.dstport",
                   "-e", "ip.len"]
        ##"-e", "ssl.handshake.certificate"
        # Initialise result
        result = list()

        # Call Tshark on packets
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        # Get output
        out, err = process.communicate()

        # Give warning message if any
        if err:
            warnings.warn("Error reading file: '{}'".format(
                err.decode('utf-8')))

        # Read each packet
        for packet in filter(None, out.decode('utf-8').split('\n')):
            # Get all data from packets
            packet = packet.split()

            # Perform check on packets
            if len(packet) < 8: continue

            # Perform check on multiple ip addresses
            packet[3] = packet[3].split(',')[0]
            packet[5] = packet[5].split(',')[0]
            packet[7] = packet[7].replace(',', '')

            # Parse certificate
            if len(packet) > 8:
                # Get first certificate
                cert = packet[8].split(',')[0]
                # Transform to hex
                cert = bytes.fromhex(cert.replace(':', ''))
                # Read as certificate
                cert = x509.load_der_x509_certificate(cert, default_backend())
                # Set packet as serial number
                packet[8] = cert.serial_number
            else:
                packet.append(None)

            # Add packet to result
            result.append([path] + packet)

        # Get result as numpy array
        result = np.asarray(result)

        # Check if any items exist
        if not result.shape[0]:
            return np.zeros((0, 8), dtype=object)

        # Change protocol number to text
        protocols = {'17': 'udp', '6': 'tcp'}
        result[:, 3] = [protocols.get(x, 'unknown') for x in result[:, 3]]

        # Return in original order
        return result[:, [0, 3, 2, 1, 8, 4, 6, 5, 7, 9]]

    def read_pyshark(self, path: str) -> np.ndarray:
        """Read TCP and UDP packets from file given by path
            using pyshark backend

        Args:
        --------
            path (str): Path to .pcap file to read.

        Returns:
        -------
            np.ndarray: Array of shape=(n_packets, n_features)
            Where features consist of:

                0) Filename of capture
                1) Protocol TCP/UDP
                2) TCP/UDP stream identifier
                3) Timestamp of packet
                4) Length of packet
                5) IP packet source
                6) IP packet destination
                7) TCP/UDP packet source port
                8) TCP/UDP packet destination port
                9) SSL/TLS certificate if exists, else None
        """
        # If verbose, print which file is currently being read
        if self.verbose:
            counter_a = 0
            counter_b = 0

        # Read pcap file
        pcap = iter(pyshark.FileCapture(path))

        # Initialise result
        result = list()

        # Loop over packets
        while True:
            try:
                packet = next(pcap)
            except ModuleNotFoundError as ex:
                raise ex
            except OSError as ex:
                raise ex
            except Exception as ex:
                warnings.warn("Pyshark error: '{}'".format(ex))
                break

            if not ("TCP" in packet or "UDP" in packet):
                continue

            try:
                
                d = []
                # Get required packet data
                if packet.layers[1].stream:
                    d = [path,
                        packet.layers[1].layer_name,  # Get
                        packet.layers[1].stream,  # Get stream ID
                        packet.sniff_timestamp,  # Get packet timestamp
                        packet.length,  # Get packet length
                        packet.layers[0].src,  # Get source IP or IPv6 (fixed)
                        packet.layers[0].dst,  # Get destination IP or IPv6 (fixed)
                        packet.layers[1].srcport,  # Get source port
                        packet.layers[1].dstport,  # Get destination port
                        None]
                elif packet.layers[2].stream:
                    d = [path,
                        packet.layers[2].layer_name,  # Get
                        packet.layers[2].stream,  # Get stream ID
                        packet.sniff_timestamp,  # Get packet timestamp
                        packet.length,  # Get packet length
                        packet.layers[1].src,  # Get source IP or IPv6 (fixed)
                        packet.layers[1].dst,  # Get destination IP or IPv6 (fixed)
                        packet.layers[2].srcport,  # Get source port
                        packet.layers[2].dstport,  # Get destination port
                        None]
                else:
                    continue

                # Check whether SSL/TLS certificate is in packet
                if "SSL" in packet and \
                        packet.ssl.get("handshake_certificate") is not None:
                    # Get certificate
                    cert = packet.ssl.get('handshake_certificate')
                    # Parse cert to bytes
                    cert = bytes.fromhex(cert.replace(':', ''))
                    # Parse x509 certificate as DER
                    cert = x509.load_der_x509_certificate(cert,
                                                        default_backend())
                    # Get serial number - TODO extend with other features?
                    d[-1] = cert.serial_number

                # Append data item to result
                result.append(d)
            except Exception as ex:
                warnings.warn(f"Cannot read pcap: {path}")


        # Close capture
        pcap.close()

        # Return result as numpy array
        return np.array(result)

    def combine(self, packets: np.ndarray) -> dict:
        """Combine individual packets into a flow representation

            Parameters
            ----------
            packets : np.array of shape=(n_samples_packets, n_features_packets)
                Output from Reader.read

            Returns
            -------
            flows : dict
                Dictionary of flow_key -> Flow()
            """
        # Initialise result
        result = dict()

        # For each packet, add it to a flow
        for packet in packets:
            key = (packet[0], packet[1], packet[2])
            # Add packet to flow
            result[key] = result.get(key, Flow()).add(packet)

        # Return result
        return result
