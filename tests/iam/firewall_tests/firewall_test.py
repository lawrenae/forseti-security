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

"""Unit Tests for Firewall Analysis."""

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.iam.firewall.firewall import Space, \
    PortRange, ip_range, SpaceSet, ProtocolRange


class FirewallTest(ForsetiTestCase):
    """Test based on declarative model."""

    def test_space_intersect_port_dim1(self):
        """Test space intersection in one dimension."""

        self.assertTrue(
            Space(PortRange(0, 2**16))
            .intersect(Space(PortRange(0, 2**16))))

        self.assertTrue(
            Space(PortRange(0, 2**15))
            .intersect(Space(PortRange(2**14, 2**16))))

        self.assertTrue(
            Space(PortRange(0, 1))
            .intersect(Space(PortRange(0, 1))))

        self.assertTrue(
            Space(PortRange(0, 2))
            .intersect(Space(PortRange(1, 3))))

        self.assertFalse(
            Space(PortRange(2**8, 2**15))
            .intersect(Space(PortRange(2**0, 2**8))))

        self.assertFalse(
            Space(PortRange(0, 1))
            .intersect(Space(PortRange(1, 2**16))))

        self.assertFalse(
            Space(PortRange(0, 2))
            .intersect(Space(PortRange(2, 3))))

    def test_space_intersect_ipaddress_dim1(self):
        """Test space intersection in one dimension."""

        self.assertTrue(
            Space(ip_range(u'10.0.0.0/8'))
            .intersect(Space(ip_range(u'10.0.0.1/32'))))

        self.assertTrue(
            Space(ip_range(u'127.0.0.0/8'))
            .intersect(Space(ip_range(u'127.0.0.0/8'))))

        self.assertTrue(
            Space(ip_range(u'10.0.0.0/8'))
            .intersect(Space(ip_range(u'10.0.0.1/32'))))

        self.assertTrue(
            Space(ip_range(u'10.0.0.0/8'))
            .intersect(Space(ip_range(u'10.1.0.0/16'))))

        self.assertFalse(
            Space(ip_range(u'10.0.0.0/32'))
            .intersect(Space(ip_range(u'10.0.0.1/32'))))

        self.assertFalse(
            Space(ip_range(u'0.0.0.0/8'))
            .intersect(Space(ip_range(u'1.0.0.0/8'))))

        self.assertFalse(
            Space(ip_range(u'127.0.0.0/8'))
            .intersect(Space(ip_range(u'128.0.0.0/8'))))

        self.assertFalse(
            Space(ip_range(u'10.0.0.0/8'))
            .intersect(Space(ip_range(u'192.168.0.0/24'))))

    def test_space_equal_dimX(self):
        """Test equal methods in one, two and three dimensions."""

        self.assertEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32')),
                Space(ip_range(u'192.168.24.0/24'))),
            SpaceSet(
                Space(ip_range(u'192.168.24.0/24')),
                Space(ip_range(u'127.0.0.1/32'))))

        self.assertEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16)),
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1))),
            SpaceSet(
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1)),
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16))))

        self.assertEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP'])),
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP']))),
            SpaceSet(
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP'])),
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP']))))

        self.assertNotEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP'])),
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP']))),
            SpaceSet(
                Space(ip_range(u'192.168.25.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP'])),
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP']))))

        self.assertNotEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP'])),
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP']))),
            SpaceSet(
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP'])),
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**15),
                      ProtocolRange(['UDP']))))

        self.assertNotEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP'])),
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP']))),
            SpaceSet(
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP'])),
                Space(ip_range(u'127.0.0.2/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP']))))

        self.assertNotEqual(
            SpaceSet(
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP'])),
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP']))),
            SpaceSet(
                Space(ip_range(u'192.168.24.0/24'),
                      PortRange(0, 1),
                      ProtocolRange(['TCP', 'ICMP'])),
                Space(ip_range(u'127.0.0.1/32'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP', 'TCP']))))

    def test_space_difference(self):
        """Test difference method in multiple dimensions."""

        s = SpaceSet(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['TCP'])))
        s = s.difference(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['TCP'])))
        self.assertTrue(s.empty())

        s = SpaceSet(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['TCP', 'UDP', 'ICMP'])))
        self.assertFalse(s.empty())
        s = s.difference(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['ICMP'])))
        self.assertFalse(s.empty())
        s = s.difference(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['UDP'])))
        self.assertFalse(s.empty())
        s = s.difference(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['TCP'])))
        self.assertTrue(s.empty())

        s = SpaceSet(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['TCP'])))
        s = s.difference(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(1, 2**16),
                      ProtocolRange(['TCP'])))
        self.assertFalse(s.empty())

        s = SpaceSet(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(0, 2**16),
                      ProtocolRange(['TCP', 'UDP', 'ICMP'])))
        s = s.difference(
                Space(ip_range(u'127.0.0.0/8'),
                      PortRange(1, 2**16),
                      ProtocolRange(['TCP'])))
        self.assertFalse(s.empty())
