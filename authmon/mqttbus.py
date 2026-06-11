#!/usr/bin/env python3
"""MQTT client wrapper: TLS, persistent session, reconnect backoff, LWT.

Resilience choices vs v4:
- clean_session=False with a stable client_id, so QoS1 events published while
  a node is offline are delivered by the broker on reconnect;
- automatic reconnect with exponential backoff (paho reconnect_delay_set);
- a signed Last Will ("node_offline") so peers can observe dead nodes.
"""
from __future__ import annotations

import json
import ssl
import sys
from typing import Any, Callable

import paho.mqtt.client as mqtt

from .events import make_event, sign_event


def _log(msg: str, *, err: bool = False) -> None:
    print(msg, file=sys.stderr if err else sys.stdout, flush=True)


class MqttBus:
    def __init__(
        self,
        cfg: dict,
        *,
        client_id_role: str,
        password: str,
        hmac_secret: str,
        on_event: Callable[[dict], None] | None = None,
    ):
        self.mqtt_cfg = cfg["mqtt"]
        self.node_id = str(cfg["node_id"])
        self.topic = str(self.mqtt_cfg["topic"])
        self.qos = int(self.mqtt_cfg["qos"])
        self.hmac_secret = hmac_secret
        self.on_event = on_event

        client_id = f"authmon5-{client_id_role}-{self.node_id}"
        if hasattr(mqtt, "CallbackAPIVersion"):
            self.client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
                clean_session=False,
                protocol=mqtt.MQTTv311,
            )
        else:
            self.client = mqtt.Client(client_id=client_id, clean_session=False)

        username = str(self.mqtt_cfg.get("username", "")).strip()
        if username:
            self.client.username_pw_set(username, password)

        if bool(self.mqtt_cfg.get("tls", True)):
            ca = str(self.mqtt_cfg.get("tls_ca", "")).strip() or None
            self.client.tls_set(ca_certs=ca, cert_reqs=ssl.CERT_REQUIRED,
                                tls_version=ssl.PROTOCOL_TLS_CLIENT)
            if bool(self.mqtt_cfg.get("tls_insecure", False)):
                self.client.tls_insecure_set(True)
                _log("warn: TLS certificate verification DISABLED (tls_insecure)", err=True)

        will = sign_event(make_event("node_offline", self.node_id), self.hmac_secret)
        self.client.will_set(self.topic, json.dumps(will, separators=(",", ":")),
                             qos=self.qos, retain=False)

        self.client.reconnect_delay_set(min_delay=1, max_delay=120)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    # -- callbacks -------------------------------------------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        rc = getattr(reason_code, "value", reason_code)
        try:
            rc = int(rc)
        except (TypeError, ValueError):
            rc = 0 if str(reason_code).lower() == "success" else 1
        if rc != 0:
            _log(f"error: mqtt connect failed rc={reason_code}", err=True)
            return
        if self.on_event is not None:
            client.subscribe(self.topic, qos=self.qos)
        _log(f"mqtt connected host={self.mqtt_cfg['host']} topic={self.topic}")

    def _on_disconnect(self, client, userdata, *args):
        _log("warn: mqtt disconnected; auto-reconnect engaged", err=True)

    def _on_message(self, client, userdata, msg):
        if self.on_event is None:
            return
        try:
            payload = json.loads(msg.payload.decode("utf-8", "ignore"))
        except json.JSONDecodeError:
            _log("warn: dropped non-JSON mqtt payload", err=True)
            return
        try:
            self.on_event(payload)
        except Exception as exc:  # never let a handler kill the network loop
            _log(f"error: event handler failed: {exc}", err=True)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        host = str(self.mqtt_cfg["host"])
        port = int(self.mqtt_cfg["port"])
        keepalive = int(self.mqtt_cfg["keepalive"])
        # connect_async + loop_start: if the broker is down at boot, the
        # client keeps retrying instead of crashing the daemon (v4 crashed).
        self.client.connect_async(host, port, keepalive)
        self.client.loop_start()

    def stop(self) -> None:
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass

    def publish_signed(self, event: dict[str, Any], timeout: float = 10.0) -> str | None:
        """Sign and publish; returns error string or None on success."""
        signed = sign_event(event, self.hmac_secret)
        body = json.dumps(signed, separators=(",", ":"), sort_keys=True)
        try:
            info = self.client.publish(self.topic, body, qos=self.qos, retain=False)
            info.wait_for_publish(timeout=timeout)
        except (ValueError, RuntimeError) as exc:
            return f"publish failed: {exc}"
        if info.rc != mqtt.MQTT_ERR_SUCCESS or not info.is_published():
            return f"publish failed rc={info.rc}"
        return None
