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

""" Service call tracing utilities. """

import uuid
import threading
import logging

thread_local = threading.local()


def cur_trace():
    return thread_local.trace


class GrpcWrapper(object):
    def __init__(self, obj):
        self.wrapper = traced
        self.obj = obj

    def __getattr__(self, name):
        attr = getattr(self.obj, name)
        if callable(attr):
            return self.wrapper(attr)
        else:
            return attr


class Trace(object):
    def __init__(self):
        self._id = None

    def __enter__(self):
        logging.error("Trace begin")
        self._id = uuid.uuid4()
        thread_local.trace = self
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        logging.error("Trace exit")
        self._id = None


def traced(function):
    def wrapper(*args, **kwargs):
        with Trace() as _:
            try:
                return function(*args, **kwargs)
            except Exception as e:
                logging.exception(e)
                raise
    return wrapper
