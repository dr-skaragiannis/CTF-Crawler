# -*- coding: utf-8 -*-
"""CTF-Logger extension for Burp Suite (Community and Professional, Jython 2.7).

Logs every HTTP request/response that goes through ANY Burp tool (Proxy, Repeater,
Intruder, Scanner, Sequencer, extensions...) into the running ctf-logger session:
    <session>/burp/burp_http.log       full requests and responses
    <session>/burp/burp_requests.tsv   one line per request (time, tool, method, URL, status)
It only writes while `ctf-logger` is running, so it can stay loaded permanently.

ctf-logger installs a copy with the session marker path filled in at
/etc/ctf-logger/ctf_burp_logger.py - load THAT file in Burp:
    Extensions > Installed > Add > Extension type: Python > select the file
(Jython must be set once in Settings > Extensions > Python environment.)
"""
from burp import IBurpExtender, IHttpListener

import os
import threading
import time

MARKER = "{{MARKER}}"
MAX_BYTES = 2 * 1024 * 1024  # per request / response written to the full log
RULE = "=" * 80 + "\n"


def utf8(s):
    """Header text may be unicode (URLs); the log files are written as bytes."""
    return s.encode("utf-8") if isinstance(s, unicode) else s  # noqa: F821 (Jython 2.7)


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._lock = threading.Lock()
        self._count = 0
        callbacks.setExtensionName("CTF-Logger")
        callbacks.registerHttpListener(self)
        print("CTF-Logger loaded: all Burp HTTP traffic is saved to <session>/burp/ "
              "while ctf-logger is running (marker: %s)" % MARKER)

    def _burp_dir(self):
        try:
            with open(MARKER) as f:
                lines = f.read().splitlines()
            session, pid = lines[0], lines[1]
            path = os.path.join(session, "burp")
            if os.path.isdir("/proc/" + pid) and os.path.isdir(path):
                return path
        except Exception:
            pass
        return None

    def _raw(self, data):
        """Java byte[] -> byte string, cut to MAX_BYTES."""
        if data is None:
            return "", 0
        size = len(data)
        # bytesToString maps each byte to one char, so latin-1 gives the exact bytes back
        text = self._helpers.bytesToString(data).encode("latin-1", "replace")
        if size > MAX_BYTES:
            text = text[:MAX_BYTES] + "\n... [truncated, %d bytes total]" % size
        return text, size

    def processHttpMessage(self, tool_flag, is_request, message):
        if is_request:
            return  # logged together with its response
        out_dir = self._burp_dir()
        if out_dir is None:
            return
        try:
            tool = self._callbacks.getToolName(tool_flag)
            service = message.getHttpService()
            info = self._helpers.analyzeRequest(service, message.getRequest())
            url = str(info.getUrl())
            method = info.getMethod()
            response = message.getResponse()
            status = self._helpers.analyzeResponse(response).getStatusCode() if response else "-"
            request_raw, request_size = self._raw(message.getRequest())
            response_raw, response_size = self._raw(response)
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")

            with self._lock:
                self._count += 1
                n = self._count
                with open(os.path.join(out_dir, "burp_http.log"), "ab") as f:
                    f.write(RULE)
                    f.write(utf8("#%d [%s] %s  %s %s  -> %s\n" % (n, stamp, tool, method, url, status)))
                    f.write(">>> REQUEST (%d bytes)\n" % request_size)
                    f.write(request_raw)
                    f.write("\n<<< RESPONSE (%d bytes)\n" % response_size)
                    f.write(response_raw)
                    f.write("\n\n")
                tsv = os.path.join(out_dir, "burp_requests.tsv")
                new = not os.path.exists(tsv)
                with open(tsv, "ab") as f:
                    if new:
                        f.write("# n\ttime\ttool\tmethod\turl\tstatus\trequest_bytes\tresponse_bytes\n")
                    f.write(utf8("%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n" % (
                        n, stamp, tool, method, url, status, request_size, response_size)))
        except Exception as e:
            print("CTF-Logger: could not log message: %s" % e)
