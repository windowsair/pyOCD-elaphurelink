# elaphureLink backend for pyOCD
# Copyright (c) 2025 windowsair
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import struct
import queue
import threading

import logging

from .interface import Interface
from ....core import session
from ..dap_access_api import DAPAccessIntf
from ..dap_settings import DAPSettings

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

EL_LINK_IDENTIFIER = 0x8a656c70
EL_DAP_VERSION = 0x10000
EL_COMMAND_HANDSHAKE = 0x00000000
ELAPHURELINK_VENDOR_COMMAND_PREFIX = 0x88
ELAPHURELINK_VENDOR_COMMAND_PASSTHROUGH = 0x1
ELAPHURELINK_VENDOR_COMMAND_VENDOR_SCOPE_ENTER = 0x2

def VERSION_MAJOR(v: int) -> int: return (v >> 16) & 0xffff
def VERSION_MINOR(v: int) -> int: (v >> 8) & 0xff
def VERSION_REVISION(v: int) -> int: v & 0xff

class SocketWrapper(object):
    def __init__(self):
        self._socket = None
        self._send_queue = queue.Queue()
        self._work_thread = None
        self._running = False

    def connect(self, host: str):
        try:
            self._socket = socket.create_connection((host, 3240), timeout=10)
            self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            raise DAPAccessIntf.DeviceError("elaphureLink: Invalid host")
        while not self._send_queue.empty():
            try:
                self._send_queue.get_nowait()
            except queue.Empty:
                break
        self._running = True
        self._send_thread = threading.Thread(target=self._work_loop,
                                             name='elaphureLinkThread',
                                             daemon=True)
        self._send_thread.start()

    def _work_loop(self):
        try:
            while self._running:
                data = self._send_queue.get()
                if not data:
                    continue
                self._socket.sendall(data)
        except Exception as e:
            LOG.error("elaphureLink Exception: %s", e)

    def write(self, data):
        self._send_queue.put(data)

    def read(self, len: int):
        return self._socket.recv(len)

    def close(self):
        self._running = False
        self._send_queue.put(None)
        if self._work_thread and self._work_thread.is_alive():
            self._work_thread.join()
        try:
            self._socket.close()
        except Exception as e:
            LOG.error("elaphureLink close exception: %s", e)


class PyElaphureLink(Interface):
    def __init__(self):
        super().__init__()
        self.vid = 0
        self.pid = 0
        self.vendor_name = ""
        self.product_name = ""
        self.serial_number = ""
        self.packet_count = 1
        self.packet_size = 64
        self._socket = SocketWrapper()

    @property
    def is_bulk(self):
        """@brief Whether the interface uses CMSIS-DAP v2 bulk endpoints."""
        return True

    def _handshake(self, host: str) -> bool:
        self._socket.connect(host)
        # handshake
        req = struct.pack(
            '>III', EL_LINK_IDENTIFIER, EL_COMMAND_HANDSHAKE, EL_DAP_VERSION)
        self._socket.write(req)
        res = self._socket.read(12)
        if len(res) != 12:
            LOG.error('elaphureLink: Invalid handshake response')
            return False
        magic, cmd, ver = struct.unpack('>III', res[:12])
        if magic != EL_LINK_IDENTIFIER or cmd != EL_COMMAND_HANDSHAKE:
            LOG.error('elaphureLink: Invalid handshake response')
            return False
        if VERSION_MAJOR(ver) < 1:
            LOG.error('This version of elaphureLink is not support!')
            return False
        # Enter scope
        req = struct.pack(
            '>BBH', ELAPHURELINK_VENDOR_COMMAND_PREFIX,
            ELAPHURELINK_VENDOR_COMMAND_VENDOR_SCOPE_ENTER, 0)
        self._socket.write(req)
        res = self._socket.read(4)
        if len(res) != 4:
            LOG.error('elaphureLink: Invalid handshake response')
            return False
        prefix, status, length = struct.unpack('>BBH', res[:4])
        if prefix != ELAPHURELINK_VENDOR_COMMAND_PREFIX or status or length:
            LOG.error("elaphureLink Invalid response")
            return False
        return True

    @staticmethod
    def get_all_connected_interfaces():
        dev = PyElaphureLink()
        return [dev]

    def open(self):
        host = session.Session.get_current().options.get('cmsis_dap.elaphurelink.addr')
        if self._handshake(host) is False:
            raise DAPAccessIntf.DeviceError("elaphureLink: Failed to handshake")

    def close(self):
        self._socket.close()

    def write(self, data):
        if TRACE.isEnabledFor(logging.DEBUG):
            # Strip off trailing zero bytes to reduce clutter.
            TRACE.debug("  DATA OUT > (%d) %s", len(data), ' '.join([f'{i:02x}' for i in bytes(data).rstrip(b'\x00')]))
        header = struct.pack(">BBH",
                    ELAPHURELINK_VENDOR_COMMAND_PREFIX,
                    ELAPHURELINK_VENDOR_COMMAND_PASSTHROUGH,
                    len(data))
        req = header + bytes(data)
        self._socket.write(req)

    def read(self):
        header = self._socket.read(4)
        prefix, status, length = struct.unpack(">BBH", header)
        if prefix != ELAPHURELINK_VENDOR_COMMAND_PREFIX:
             raise DAPAccessIntf.DeviceError(f"elaphureLink: Invalid response {prefix}")
        if status:
            raise DAPAccessIntf.DeviceError(f"elaphureLink: Invalid response status {status}")
        data = self._socket.read(length)
        if TRACE.isEnabledFor(logging.DEBUG):
            # Strip off trailing zero bytes to reduce clutter.
            TRACE.debug("  DATA IN < (%d) %s", len(data), ' '.join([f'{i:02x}' for i in bytes(data).rstrip(b'\x00')]))
        return data
