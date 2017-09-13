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

""" Firewall Analyzer gRPC service. """

from concurrent import futures
import grpc

from google.cloud.security.iam.firewall import firewall_pb2
from google.cloud.security.iam.firewall import firewall_pb2_grpc
from google.cloud.security.iam.firewall import firewall


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


# pylint: disable=no-self-use
class GrpcFirewall(firewall_pb2_grpc.FirewallServicer):
    """Playground gRPC handler."""

    HANDLE_KEY = "handle"

    def _get_handle(self, context):
        """Extract the model handle from the gRPC context."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, firewall_api):
        super(GrpcFirewall, self).__init__()
        self.firewall = firewall_api

    def Ping(self, request, _):
        """Ping implemented to check service availability."""

        return firewall_pb2.PingReply(data=request.data)

    def AccessByAddressIngress(self, request, context):
        """Determines access to an ip address."""

        handle = self._get_handle(context)
        for domain in self.firewall.AccessByAddressIngress(handle,
                                                           request.ipaddress):
            yield domain

    def AccessByAddressEgress(self, request, context):
        """Determines access from an ip address."""

        handle = self._get_handle(context)
        for domain in self.firewall.AccessByAddressEgress(handle,
                                                          request.ipaddress):
            yield domain


class GrpcFirewallFactory(object):
    """Factory class for Firewall service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Creates a playground service and registers it in the server"""

        service = GrpcFirewall(
            firewall_api=firewall.Firewaller(
                self.config))
        firewall_pb2_grpc.add_FirewallServicer_to_server(service, server)
        return service
