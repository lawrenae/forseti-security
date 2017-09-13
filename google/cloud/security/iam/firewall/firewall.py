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
import collections

DEBUG = False


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


def dbg_instrument(f):
    """Instrument calls."""

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

    def __eq__(self, other):
        raise NotImplementedError()

    def __lt__(self, other):
        raise NotImplementedError()

    def __le__(self, other):
        raise NotImplementedError()

    def __ge__(self, other):
        raise NotImplementedError()

    def __gt__(self, other):
        raise NotImplementedError()

    def __ne__(self, other):
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

    @assert_compatible
    def __eq__(self, other):
        return self.values == other.values

    def _compare(self, other, comparison):
        values1 = sorted(self.values)
        values2 = sorted(other.values)

        for v1, v2 in zip(values1, values2):
            if v1 == v2:
                continue
            else:
                return comparison(v1, v2)

    def __lt__(self, other):
        return self._compare(other, lambda s, o: s < o)

    def __le__(self, other):
        return self._compare(other, lambda s, o: s <= o)

    def __ge__(self, other):
        return self._compare(other, lambda s, o: s >= o)

    def __gt__(self, other):
        return self._compare(other, lambda s, o: s > o)

    def __ne__(self, other):
        return not self == other


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

    @assert_compatible
    def __eq__(self, other):
        return self.start == other.start and self.end == other.end

    def _compare(self, other, comparison):
        if self.start == other.start:
            return comparison(self.end, other.end)
        else:
            return comparison(self.start, other.start)

    def __lt__(self, other):
        return self._compare(other, lambda s, o: s < o)

    def __le__(self, other):
        return self._compare(other, lambda s, o: s <= o)

    def __ge__(self, other):
        return self._compare(other, lambda s, o: s >= o)

    def __gt__(self, other):
        return self._compare(other, lambda s, o: s > o)

    def __ne__(self, other):
        return not self == other


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

        def instanceofany(obj, *types):
            for t in types:
                if isinstance(obj, t):
                    return True
            return False

        ranges = collections.defaultdict(set)
        for dim_self, dim_other, index in zip(self.ranges,
                                              other.ranges,
                                              xrange(len(self.ranges))):
            diff_ranges = dim_self.difference(dim_other)

            def appendIfEmpty(diff_range):
                if not diff_range.empty():
                    ranges[index].add(diff_range)

            if instanceofany(diff_ranges, list, set, tuple):
                map(appendIfEmpty, diff_ranges)
            else:
                appendIfEmpty(diff_ranges)

        spaces = []
        for index, rs in ranges.iteritems():
            for r in rs:
                new_ranges = list(self.ranges)
                new_ranges[index] = r
                spaces.append(Space(*new_ranges))

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

    def __eq__(self, other):
        for rs, ro in zip(self.ranges, other.ranges):
            if not rs == ro:
                return False
        return True

    def _compare(self, other, comparison):
        for r1, r2 in zip(self.ranges, other.ranges):
            if r1 == r2:
                continue
            else:
                return comparison(r1, r2)

    def __lt__(self, other):
        return self._compare(other, lambda s, o: s < o)

    def __le__(self, other):
        return self._compare(other, lambda s, o: s <= o)

    def __ge__(self, other):
        return self._compare(other, lambda s, o: s >= o)

    def __gt__(self, other):
        return self._compare(other, lambda s, o: s > o)

    def __ne__(self, other):
        return not self == other


class SpaceSet(object):
    def __init__(self, *spaces):
        self.spaces = sorted(spaces)

    @instrument
    def difference(self, other):
        spaces = [s.difference(other) for s in self.spaces]
        spaces = self._flatten(spaces)
        spaces = filter(lambda s: not s.empty(), spaces)
        return SpaceSet(*spaces)

    @instrument
    def intersect(self, other):
        return any([s.intersect(other) for s in self.spaces])

    @instrument
    def _flatten(self, l):
        return [item for sublist in l for item in sublist]

    def __repr__(self):
        return '\n'.join([repr(s) for s in self.spaces])

    def __eq__(self, other):
        for ss, so in zip(self.spaces, other.spaces):
            if not ss == so:
                return False
        return True

    def _compare(self, other, comparison):
        for s1, s2 in zip(self.spaces, other.spaces):
            if s1 == s2:
                continue
            else:
                return comparison(s1, s2)

    def __lt__(self, other):
        return self._compare(other, lambda s, o: s < o)

    def __le__(self, other):
        return self._compare(other, lambda s, o: s <= o)

    def __ge__(self, other):
        return self._compare(other, lambda s, o: s >= o)

    def __gt__(self, other):
        return self._compare(other, lambda s, o: s > o)

    def __ne__(self, other):
        return not self == other

    def empty(self):
        return not self.spaces or all(
            map(lambda s: s.empty(), self.spaces))


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
