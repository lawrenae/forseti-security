#!/usr/bin/env python
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

""" Firewall Analyzer. """

import ipaddress
import itertools

DEBUG = True


def assert_compatible(f):
    """Automatically perform compatibility check."""

    def wrapper(*args, **kwargs):
        """Fail with type error if objects are incompatible."""
        s = args[0]
        o = args[1]
        if not s.compatible(o):
            raise TypeError('Incompatible objects: {}, {}'.format(
                s, o))
        return f(*args, **kwargs)

    return wrapper


def instrument(f):
    """Instrument calls."""

    if not DEBUG:
        return f

    def wrapper(*args, **kwargs):
        """Print call arguments and return value."""
        result = f(*args, **kwargs)
        print '{}({},{}) -> {}'.format(
            f.__name__,
            args,
            kwargs,
            result)
        return result

    return wrapper


class Range(object):
    def __init__(self, range_type):
        self.range_type = range_type

    def get_type(self):
        return self.range_type

    def compatible(self, other):
        return self.get_type() == other.get_type()

    def intersect(self, other):
        raise NotImplementedError()

    def union(self, other):
        raise NotImplementedError()

    def contains(self, other):
        raise NotImplementedError()

    def difference(self, other):
        raise NotImplementedError()


class NominalRange(Range):
    def __init__(self, range_type, values):
        super(NominalRange, self).__init__(range_type)
        self.values = set(values)

    @assert_compatible
    @instrument
    def intersect(self, other):
        return self.range_type(self.values.intersection(other.values))

    @assert_compatible
    @instrument
    def union(self, other):
        return self.range_type(self.values.union(other.values))

    @instrument
    def contains(self, other):
        for elem in other.values:
            if elem not in self.values:
                return False
        return True

    @assert_compatible
    @instrument
    def difference(self, other):
        return self.range_type(self.values.difference(other.values))

    @instrument
    def empty(self):
        return True if not self.values else False

    def __repr__(self):
        return ','.join(self.values)


class NumericRange(Range):
    def __init__(self, range_type, start, end_exclusive):
        super(NumericRange, self).__init__(range_type)
        self.start = start
        self.end = end_exclusive

    @assert_compatible
    @instrument
    def intersect(self, other):
        if self.start >= other.end or \
           other.start >= self.end:
            return None

        return self.range_type(max(self.start, other.start),
                               min(self.end, other.end))

    @assert_compatible
    @instrument
    def union(self, other):
        if not self.intersect(other):
            return None
        return self.range_type(min(self.start, other.start),
                               max(self.end, other.end))

    @instrument
    def contains(self, other):
        return (self.start >= other.start and self.end <= other.end) or \
               (other.start >= self.start and other.end <= self.end)

    @assert_compatible
    @instrument
    def difference(self, other):
        if not self.intersect(other):
            return self.range_type(self.start, self.end)
        if self.contains(other):
            return (self.range_type(self.start, other.start),
                    self.range_type(other.end, self.end))
        if other.start < self.end:
            return self.range_type(self.start, other.start)
        return self.range_type(other.end, self.end)

    @instrument
    def empty(self):
        return self.start == self.end

    def __repr__(self):
        return '{}-{}'.format(self.start, self.end)


class PortRange(NumericRange):
    def __init__(self, start_port, end_port):
        if start_port > end_port or \
           not self._in_range(start_port) or \
           not self._in_range(end_port):
            raise TypeError('invalid range')
        super(PortRange, self).__init__(PortRange, start_port, end_port)

    def _in_range(self, port):
        return port >= 0 and port <= 2**16

    def __repr__(self):
        return 'port:({})'.format(super(PortRange, self).__repr__())


class IPRange(NumericRange):
    def __init__(self, start, end_exclusive):
        super(IPRange, self).__init__(IPRange, start, end_exclusive)

    def __repr__(self):
        return 'ip:({})'.format(super(IPRange, self).__repr__())


@instrument
def ip_range(rangespec):
    network = ipaddress.ip_network(rangespec)
    start = int(network.network_address)
    end = int(network.broadcast_address)+1
    return IPRange(start, end)


class ProtocolRange(NominalRange):
    def __init__(self, values):
        super(ProtocolRange, self).__init__(ProtocolRange, values)

    def __repr__(self):
        return 'proto:({})'.format(super(ProtocolRange, self).__repr__())


class Space(object):
    def __init__(self, *ranges):
        self.ranges = ranges

    @instrument
    def compatible(self, other):
        return self.get_type() == other.get_type()

    @instrument
    def get_type(self):
        return [r.get_type() for r in self.ranges]

    @assert_compatible
    @instrument
    def difference(self, other):
        if not self.intersect(other):
            return Space(self.ranges)

        ranges = []
        for dim_self, dim_other in zip(self.ranges, other.ranges):
            ranges.append(dim_self.difference(dim_other))

        def instanceofany(obj, *types):
            for t in types:
                if isinstance(obj, t):
                    return True
            return False

        ranges = ([[r]
                   if not instanceofany(r, list, set, tuple)
                   else r for r in ranges])

        spaces = []
        for ranges in itertools.product(*ranges):
            spaces.append(Space(*ranges))
        return spaces

    @assert_compatible
    @instrument
    def intersect(self, other):
        for dim_self, dim_other in zip(self.ranges, other.ranges):
            if not dim_self.intersect(dim_other):
                return False
        return True

    @instrument
    def empty(self):
        return any([r.empty() for r in self.ranges])

    def __repr__(self):
        return '({})'.format(';'.join([repr(r) for r in self.ranges]))


class SpaceSet(object):
    def __init__(self, *spaces):
        self.spaces = spaces

    @instrument
    def difference(self, other):
        spaces = [s.difference(other) for s in self.spaces]
        return SpaceSet(*self._flatten(spaces))

    @instrument
    def intersect(self, other):
        return any([s.intersect(other) for s in self.spaces])

    @instrument
    def _flatten(self, l):
        return [item for sublist in l for item in sublist]

    def __repr__(self):
        return '\n'.join([repr(s) for s in self.spaces])


if __name__ == '__main__':
    initial = Space(ip_range(u'0.0.0.0/0'),
                    PortRange(0, 2**16),
                    ProtocolRange(['TCP', 'UDP', 'ICMP']))

    firewall = Space(ip_range(u'10.0.0.0/8'),
                     PortRange(0, 2**16),
                     ProtocolRange(['TCP', 'ICMP']))

    mds = SpaceSet(initial)
    mds2 = mds.difference(firewall)

    print 'Space before: {}'.format(mds)
    print 'Space after: {}'.format(mds2)
    print 'Intersecting: {}'.format(mds2.intersect(firewall))
    import code
    code.interact(local=locals())

    # class FwRule(Vector):
    # rule = Vector(ip_range('10.0.0.0/8'))
    # sp = SourceSpace(ip_range())
    # mds = MultiDimSpace(Space(ip_range('10.0.0.0/8'), PortRange(0,65536)),
    #                     Space(ip_range('172.16.0.0/16'), PortRange(0,1024))
