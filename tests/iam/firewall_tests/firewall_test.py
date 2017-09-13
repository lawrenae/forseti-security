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
    PortRange


class FirewallTest(ForsetiTestCase):
    """Test based on declarative model."""

    def test_space_intersect_dim1(self):
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
