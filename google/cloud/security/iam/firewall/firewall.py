# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Firewall Analyzer API. """

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc
# pylint: disable=invalid-name,no-self-use

import ipaddress

from google.cloud.security.iam.firewall import firewall_pb2


def ip_range(rangespec):
    network = ipaddress.ip_network(rangespec)
    start = int(network.network_address)
    end = int(network.broadcast_address)+1
    return start, end


def port_range(rangespec):
    if '-' in rangespec:
        start, end = rangespec.split('-')
    else:
        start = int(rangespec)
        end = start
    return int(start), int(end)+1


class Firewaller(object):
    """Firewall API implementation."""

    def __init__(self, config):
        self.config = config

    def AccessByAddressIngress(self, model_name, address):
        """Calculates the access domain to the address."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for rule in data_access.get_firewall_rules(session, address):
                network, protocol, port_specs = rule
                ip_start, ip_end = ip_range(network)
                if not port_specs:
                    result = firewall_pb2.EndpointDomain(
                        ip_range=firewall_pb2.IpRange(
                            range=network,
                            start=ip_start,
                            end_exclusive=ip_end),
                        protocols=[protocol])
                    yield result
                else:
                    for port_spec in port_specs:
                        port_start, port_end = port_range(port_spec)
                        result = firewall_pb2.EndpointDomain(
                            ip_range=firewall_pb2.IpRange(
                                range=network,
                                start=ip_start,
                                end_exclusive=ip_end),
                            port_range=firewall_pb2.PortRange(
                                start=port_start,
                                end_exclusive=port_end),
                            protocols=[protocol])
                        yield result

    def AccessByAddressEgress(self, model_name, address):
        """Calculate the access domain from the address."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for rule in data_access.get_firewall_rules(session, address):
                network, protocol, port_specs = rule
                for port_spec in port_specs:
                    ip_start, ip_end = ip_range(network)
                    port_start, port_end = port_range(port_spec)
                    result = firewall_pb2.EndpointDomain(
                        ip_range=firewall_pb2.IpRange(
                            range=network,
                            start=ip_start,
                            end_exclusive=ip_end),
                        port_range=firewall_pb2.PortRange(
                            start=port_start,
                            end_exclusive=port_end),
                        protocols=[protocol])
                    yield result
