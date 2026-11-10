"""Killable SSH owner: probe, redispatch and collection share one connection."""
import contextlib
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from types import SimpleNamespace


class ProbeFailure(Exception):
    """Transport-independent startup failure, converted by the calling backend."""
    def __init__(self, details):
        self.details = details
        super().__init__(details.get('error', 'ProbeFailure'))


class ProbeSession:
    def __init__(self, params, checkpoint, timeout):
        self._lock = threading.RLock()
        self._checkpoint = checkpoint
        self._messages = queue.Queue()
        self._process = subprocess.Popen([sys.executable, '-u', str(Path(__file__).resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', bufsize=1)
        self.remote_conn_pre = self
        self.remote_conn = SimpleNamespace(closed=False, eof_received=False)
        def receive():
            try:
                for line in self._process.stdout:
                    self._messages.put(json.loads(line))
            except (ValueError, OSError):
                pass
            finally:
                self._messages.put({'event':'eof'})
        self._reader = threading.Thread(target=receive, daemon=True)
        self._reader.start()
        try:
            response = self._rpc({'op':'start','params':params}, timeout, checkpoint)
            if response.get('failure'):
                raise ProbeFailure(response['failure'])
            self.device_type = response['device_type']
            self._network_prompt_text = response['prompt']
            self._network_prompt_regex = r'(?m)^' + re.escape(response['prompt']) + r'[ \t]*\r?$'
            self.base_prompt = response['prompt'][:-1]
            self._network_host_key_persisted = response.get('host_key_persisted')
        except Exception:
            self.close()
            raise

    def _rpc(self, request, timeout, checkpoint):
        deadline = time.monotonic() + timeout
        partial = []
        from collector_backend import classify_error, clean_terminal
        with self._lock:
            try:
                if self._process.poll() is not None:
                    raise EOFError('SSH worker has exited')
                self._process.stdin.write(json.dumps(request) + '\n')
                self._process.stdin.flush()
                while True:
                    if checkpoint:
                        checkpoint()
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise TimeoutError('SSH worker deadline exceeded')
                    try:
                        message = self._messages.get(timeout=min(.02,left))
                    except queue.Empty:
                        continue
                    if message.get('event') == 'data':
                        partial.append(message['data'])
                    elif message.get('event') == 'eof':
                        raise EOFError('SSH worker exited before completing response')
                    else:
                        return message
            except Exception as exc:
                self.close()
                if request['op'] != 'collect':
                    raise
                # Include chunks already read by the receiver at the cutoff.
                while True:
                    try:
                        queued = self._messages.get_nowait()
                    except queue.Empty:
                        break
                    if queued.get('event') == 'data':
                        partial.append(queued['data'])
                failure = classify_error(exc, 'command')
                failure['message'] = 'SSH worker interrupted; streamed partial output retained'
                return {'output':clean_terminal(''.join(partial)), 'failure':failure}

    def collect_in_worker(self, command, timeout, pattern, quiet, checkpoint):
        response = self._rpc({'op':'collect','command':command,'timeout':timeout,'pattern':pattern,'quiet':quiet},
                             timeout + .25, checkpoint)
        return response.get('output',''), response.get('failure')

    def is_alive(self):
        if self._process.poll() is not None:
            return False
        return bool(self._rpc({'op':'alive'}, 2, self._checkpoint).get('alive'))

    def close(self):
        self.remote_conn.closed = True
        with contextlib.suppress(Exception):
            if self._process.poll() is None:
                self._process.kill()
            self._process.wait(timeout=2)
        # Let the receiver drain bytes already written before closing its pipe.
        if threading.current_thread() is not self._reader:
            self._reader.join(timeout=2)
        for pipe in (self._process.stdin, self._process.stdout):
            with contextlib.suppress(Exception):
                pipe.close()

    disconnect = close


def main():
    import collector_backend as b
    from netmiko import redispatch
    b.configure_stdio()
    conn = None
    def emit(value):
        print(json.dumps(value, ensure_ascii=True), flush=True)
    try:
        first = json.loads(sys.stdin.readline())
        params = first['params']
        auto_enable = params.pop('_auto_enable', False)
        # Install the same tolerant vendor preparation as the parent collector.
        b.install_tolerant_preparation()
        retained = []
        def keep(connection, driver):
            redispatch(connection, device_type=driver, session_prep=True)
            if auto_enable and driver.startswith('cisco_'):
                connection.enable()
            retained.append(connection)
        result = b.detection_worker(params, connection_sink=keep)
        if result.get('error'):
            emit({'failure':result})
            return
        conn = retained[0]
        prompt = b.last_prompt(conn.find_prompt())
        if not prompt:
            raise ValueError('CLI prompt could not be verified after redispatch')
        emit({'device_type':result['device_type'],'prompt':prompt,
              'host_key_persisted':getattr(conn.remote_conn_pre,'_network_host_key_persisted',None)})
        for line in sys.stdin:
            request = json.loads(line)
            if request['op'] == 'alive':
                emit({'alive':conn.is_alive()})
            elif request['op'] == 'collect':
                output, failure = b.read_cli_output(conn, request['command'], request['timeout'],
                    request['pattern'], quiet=request['quiet'],
                    on_data=lambda data:emit({'event':'data','data':data}))
                emit({'output':output,'failure':failure})
            else:
                raise ValueError('Unknown SSH worker operation')
    except Exception as exc:
        emit({'failure':b.classify_error(exc, 'autodetect')})
    finally:
        # Close transport first: never send driver cleanup text into a question.
        if conn is not None:
            with contextlib.suppress(Exception): conn.remote_conn_pre.close()
            with contextlib.suppress(Exception): conn.disconnect()


if __name__ == '__main__': main()
