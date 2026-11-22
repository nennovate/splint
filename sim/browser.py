"""A real browser for tests, with nothing to install: Chrome driven over its debugging socket.

It clicks with real mouse events at where an element really is, so it fails where a person would.
"""

import base64
import hashlib
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import time
import urllib.request
from pathlib import Path

CHROME_ON_MAC = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
START_SECONDS = 30
CALL_SECONDS = 30
CONTINUATION = 0x0
TEXT_FRAME = 0x1
BINARY_FRAME = 0x2
CLOSE_FRAME = 0x8
PING_FRAME = 0x9
PONG_FRAME = 0xA


def find_chrome() -> str | None:
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    return CHROME_ON_MAC if platform.system() == "Darwin" and Path(CHROME_ON_MAC).exists() else None


class Socket:
    """Just enough of a websocket for this one local connection."""

    def __init__(self, url: str) -> None:
        host_port, path = url.removeprefix("ws://").split("/", 1)
        host, port = host_port.split(":")
        self.sock = socket.create_connection((host, int(port)), timeout=CALL_SECONDS)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            f"GET /{path} HTTP/1.1\r\nHost: {host_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        reply = b""
        while b"\r\n\r\n" not in reply:
            reply += self.sock.recv(4096)
        head, self.extra = reply.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise RuntimeError(f"the browser refused the socket: {head!r}")
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if expected not in head:
            raise RuntimeError("the browser's socket answer doesn't check out")

    def send(self, text: str) -> None:
        data = text.encode()
        mask = os.urandom(4)
        if len(data) < 126:
            head = struct.pack("!BB", 0x80 | TEXT_FRAME, 0x80 | len(data))
        elif len(data) < 65536:
            head = struct.pack("!BBH", 0x80 | TEXT_FRAME, 0x80 | 126, len(data))
        else:
            head = struct.pack("!BBQ", 0x80 | TEXT_FRAME, 0x80 | 127, len(data))
        self.sock.sendall(head + mask + bytes(byte ^ mask[index % 4] for index, byte in enumerate(data)))

    def read_exactly(self, count: int) -> bytes:
        while len(self.extra) < count:
            more = self.sock.recv(1 << 16)
            if not more:
                raise RuntimeError("the browser closed the socket")
            self.extra += more
        found, self.extra = self.extra[:count], self.extra[count:]
        return found

    def receive(self) -> str:
        parts = b""
        while True:
            first, second = self.read_exactly(2)
            size = second & 0x7F
            if size == 126:
                size = struct.unpack("!H", self.read_exactly(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self.read_exactly(8))[0]
            content = self.read_exactly(size)
            kind = first & 0x0F
            if kind == PING_FRAME:
                continue
            if kind == CLOSE_FRAME:
                raise RuntimeError("the browser closed the socket")
            if kind in (CONTINUATION, TEXT_FRAME, BINARY_FRAME):
                parts += content
                if first & 0x80:
                    return parts.decode()


class Browser:
    def __init__(self, work: Path, flags: list[str] | None = None) -> None:
        chrome = find_chrome()
        if not chrome:
            raise RuntimeError("no Chrome here, and this test has to draw the page in a real browser")
        self.profile = work / "chrome-profile"
        self.profile.mkdir(parents=True, exist_ok=True)
        arguments = [
            chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-background-networking", "--disable-extensions", "--window-size=1100,1400",
            # Never the developer's own keychain or password store: on a Mac, a throwaway profile
            # otherwise puts a "Keychain Not Found" dialog in front of whoever is at the screen.
            "--use-mock-keychain", "--password-store=basic",
            f"--user-data-dir={self.profile}", "--remote-debugging-port=0", *(flags or []), "about:blank",
        ]
        # A CI runner has no user namespaces for Chrome's own sandbox. It's a throwaway machine.
        if os.environ.get("CI"):
            arguments.insert(2, "--no-sandbox")
        self.process: subprocess.Popen | None = subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port_file = self.profile / "DevToolsActivePort"
        deadline = time.monotonic() + START_SECONDS
        while not port_file.exists() or not port_file.read_text().strip():
            if time.monotonic() > deadline:
                raise RuntimeError("Chrome didn't start")
            time.sleep(0.1)
        self.port = port_file.read_text().split()[0]
        pages = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=10))
        page = next(found for found in pages if found["type"] == "page")
        self.attach(page["id"], page["webSocketDebuggerUrl"])

    def attach(self, target: str, url: str) -> None:
        self.target = target
        self.socket = Socket(url)
        self.next_id = 0
        self.problems: list[str] = []
        # Requests a test paused at the network, to look at or change, as a host or network in the way could.
        self.paused: list[dict] = []
        # Every request the page sent, by method and address, so a test can count what a click sent.
        self.requests: list[tuple[str, str]] = []
        for domain in ("Page", "Runtime", "Log", "Network"):
            self.call(f"{domain}.enable")

    def another_tab(self) -> "Browser":
        """A second tab of this browser, sharing its profile and storage, as a person opens a page twice.
        Closing it closes only the tab."""
        made = json.load(urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{self.port}/json/new?about:blank", method="PUT"), timeout=10))
        tab = Browser.__new__(Browser)
        tab.process, tab.profile, tab.port = None, self.profile, self.port
        tab.attach(made["id"], made["webSocketDebuggerUrl"])
        return tab

    def call(self, method: str, **params) -> dict:
        self.next_id += 1
        self.socket.send(json.dumps({"id": self.next_id, "method": method, "params": params}))
        while True:
            message = json.loads(self.socket.receive())
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message["result"]
            self.note(message)

    def note(self, message: dict) -> None:
        method = message.get("method")
        if method == "Fetch.requestPaused":
            self.paused.append(message["params"])
        elif method == "Network.requestWillBeSent":
            self.requests.append((message["params"]["request"]["method"], message["params"]["request"]["url"]))
        elif method == "Runtime.exceptionThrown":
            self.problems.append(json.dumps(message["params"]["exceptionDetails"])[:400])
        elif method == "Log.entryAdded":
            entry = message["params"]["entry"]
            # An answer of 4xx is a refusal a test asked for. Anything else logged as an error isn't.
            if entry["level"] == "error" and entry.get("source") != "network":
                self.problems.append(entry["text"][:400])

    def goto(self, url: str) -> None:
        self.call("Page.navigate", url=url)

    def eval(self, script: str):
        found = self.call("Runtime.evaluate", expression=script, awaitPromise=True, returnByValue=True)
        if "exceptionDetails" in found:
            raise RuntimeError(f"{script[:80]}: {found['exceptionDetails']}")
        return found["result"].get("value")

    def wait_for_paused(self, seconds: float = 30) -> dict | None:
        """The next request the network paused, by reading what the browser sends meanwhile."""
        deadline = time.monotonic() + seconds
        while not self.paused and time.monotonic() < deadline:
            self.eval("1")
            time.sleep(0.1)
        return self.paused.pop(0) if self.paused else None

    def wait_for(self, script: str, seconds: float = 30) -> bool:
        """A script that throws, as one can while the page is between two documents, counts as not yet.
        One that still throws when time's up raises, so a broken script can't pass as a plain no."""
        deadline = time.monotonic() + seconds
        failed = None
        while time.monotonic() < deadline:
            try:
                if self.eval(script):
                    return True
                failed = None
            except RuntimeError as error:
                failed = error
            time.sleep(0.2)
        if failed is not None:
            raise failed
        return False

    def text(self) -> str:
        return self.eval("document.body.innerText")

    def click_at(self, box: dict) -> None:
        x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        self.call("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y)
        self.call("Input.dispatchMouseEvent", type="mousePressed", x=x, y=y, button="left", clickCount=1)
        self.call("Input.dispatchMouseEvent", type="mouseReleased", x=x, y=y, button="left", clickCount=1)

    def box_of(self, inside: str, label: str, tag: str = "button") -> dict | None:
        script = f"""(() => {{
          const holder = document.querySelector({json.dumps(inside)});
          if (!holder) return null;
          const found = [...holder.querySelectorAll({json.dumps(tag)})].find((one) => one.textContent.trim() === {json.dumps(label)});
          if (!found) return null;
          found.scrollIntoView({{block: "center"}});
          const box = found.getBoundingClientRect();
          return {{x: box.x, y: box.y, width: box.width, height: box.height}};
        }})()"""
        return self.eval(script)

    def click(self, inside: str, label: str, tag: str = "button") -> bool:
        box = self.box_of(inside, label, tag)
        if box:
            self.click_at(box)
        return bool(box)

    def type_into(self, selector: str, text: str) -> None:
        self.eval(f"document.querySelector({json.dumps(selector)}).focus()")
        self.eval(f"document.querySelector({json.dumps(selector)}).select()")
        self.call("Input.insertText", text=text)

    def set_value(self, selector: str, value: str) -> None:
        """For a select, or anything else that says what changed only when it's left."""
        self.eval(f"""(() => {{
          const input = document.querySelector({json.dumps(selector)});
          input.value = {json.dumps(value)};
          input.dispatchEvent(new Event("change", {{bubbles: true}}));
        }})()""")

    def set_checked(self, selector: str, on: bool) -> None:
        self.eval(f"""(() => {{
          const input = document.querySelector({json.dumps(selector)});
          if (input.checked !== {json.dumps(on)}) input.click();
        }})()""")

    def size(self, width: int, height: int, dark: bool = False) -> None:
        mobile = width < 600
        self.call("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=2 if mobile else 1, mobile=mobile)
        self.call("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark" if dark else "light"}])

    def screenshot(self, path: Path) -> None:
        shot = self.call("Page.captureScreenshot", format="png", captureBeyondViewport=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(shot["data"]))

    def close(self) -> None:
        if self.process is None:
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/close/{self.target}", timeout=10).read()
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
