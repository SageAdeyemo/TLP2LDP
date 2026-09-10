"""
kafka_pipeline.py

The Data Transport Infrastructure layer (Section 3.3.3 / 3.4.2): wraps
TLPAnonymizerMiddleware in a stream-processing loop that mirrors the
sequence diagram in Section 3.2.2:

    raw-logs (Kafka topic) -> TLPAnonymizerMiddleware -> secure-logs (Kafka topic)

Two interchangeable runner backends are provided, both exposing the
same `run()` interface:

  - KafkaStreamRunner:   real Apache Kafka via kafka-python. Use this
                         against a live broker (e.g. `docker compose up`
                         with a Kafka + Zookeeper stack).

  - InMemoryStreamRunner: a dependency-free, in-process pub/sub broker
                         that mirrors the same topic-based interface.
                         Useful for local development, unit tests, and
                         demos without standing up Zookeeper + Kafka.

Both backends route every message through `AnonymizerPipeline.process_record`,
which also implements the System Performance / latency measurement
described in Section 3.7.3 (Delta t = t_export - t_ingest).
"""

from __future__ import annotations

import json
import queue
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from tlp_anonymizer import TLPAnonymizerMiddleware


# ----------------------------------------------------------------------
# Latency tracking (Section 3.7.3: System Performance)
# ----------------------------------------------------------------------
class LatencyTracker:
    """
    Tracks per-record end-to-end processing latency (t_export - t_ingest)
    and reports summary statistics against the 500ms operational
    threshold defined in Section 3.7.3.
    """

    LATENCY_THRESHOLD_MS = 500.0

    def __init__(self):
        self._samples_ms: list[float] = []

    def record(self, ingest_time: float, export_time: float) -> float:
        delta_ms = (export_time - ingest_time) * 1000.0
        self._samples_ms.append(delta_ms)
        return delta_ms

    @property
    def count(self) -> int:
        return len(self._samples_ms)

    def summary(self) -> dict:
        if not self._samples_ms:
            return {"count": 0}

        samples = sorted(self._samples_ms)
        n = len(samples)
        mean = sum(samples) / n
        p95 = samples[min(n - 1, int(0.95 * n))]

        return {
            "count": n,
            "mean_ms": round(mean, 3),
            "min_ms": round(samples[0], 3),
            "max_ms": round(samples[-1], 3),
            "p95_ms": round(p95, 3),
            "within_threshold": mean < self.LATENCY_THRESHOLD_MS,
            "threshold_ms": self.LATENCY_THRESHOLD_MS,
        }


# ----------------------------------------------------------------------
# Core pipeline: middleware + latency instrumentation
# ----------------------------------------------------------------------
@dataclass
class PipelineResult:
    raw: dict
    anonymized: dict
    policy: dict
    pii_detected: Optional[dict]
    latency_ms: float


class AnonymizerPipeline:
    """
    Wraps TLPAnonymizerMiddleware with JSON (de)serialization and
    latency instrumentation, so it can sit directly in a Kafka
    consume -> transform -> produce loop.
    """

    def __init__(self, middleware: Optional[TLPAnonymizerMiddleware] = None):
        self.middleware = middleware or TLPAnonymizerMiddleware()
        self.latency = LatencyTracker()

    def process_record(self, raw_message: bytes,
                        stream_key: str = "default") -> tuple[bytes, PipelineResult]:
        """
        Process a single raw Kafka message (JSON bytes).

        Returns the serialized anonymized message (bytes) ready to be
        published to the secure-logs topic, plus a PipelineResult
        with the policy, PII report, and measured latency.
        """
        t_ingest = time.perf_counter()

        log_entry = json.loads(raw_message.decode("utf-8"))
        result = self.middleware.anonymize(log_entry, stream_key=stream_key)

        t_export = time.perf_counter()
        latency_ms = self.latency.record(t_ingest, t_export)

        secure_record = result["anonymized"]
        secure_bytes = json.dumps(secure_record).encode("utf-8")

        pipeline_result = PipelineResult(
            raw=log_entry,
            anonymized=secure_record,
            policy=result["policy"],
            pii_detected=result.get("pii_detected"),
            latency_ms=latency_ms,
        )
        return secure_bytes, pipeline_result


# ----------------------------------------------------------------------
# Backend 1: Real Apache Kafka (kafka-python)
# ----------------------------------------------------------------------
class KafkaStreamRunner:
    """
    Connects the AnonymizerPipeline to a live Apache Kafka cluster.

    Topics default to "raw-logs" (input) and "secure-logs" (output),
    matching the sequence diagram in Section 3.2.2.
    """

    def __init__(self, bootstrap_servers: str = "localhost:9092",
                 raw_topic: str = "raw-logs",
                 secure_topic: str = "secure-logs",
                 group_id: str = "tlp-anonymizer-middleware",
                 pipeline: Optional[AnonymizerPipeline] = None):
        try:
            from kafka import KafkaConsumer, KafkaProducer
        except ImportError as exc:
            raise RuntimeError(
                "kafka-python is required for KafkaStreamRunner "
                "(pip install kafka-python)"
            ) from exc

        self.raw_topic = raw_topic
        self.secure_topic = secure_topic
        self.pipeline = pipeline or AnonymizerPipeline()

        try:
            self.consumer = KafkaConsumer(
                raw_topic,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
            )
            self.producer = KafkaProducer(bootstrap_servers=bootstrap_servers)
        except Exception as exc:
            raise ConnectionError(
                f"Could not connect to Kafka broker at {bootstrap_servers}. "
                "Make sure a Kafka cluster is running (e.g. via "
                "`docker compose up` with a Kafka + Zookeeper stack) "
                "before starting KafkaStreamRunner."
            ) from exc

    def run(self, max_messages: Optional[int] = None,
            on_record: Optional[Callable[[PipelineResult], None]] = None) -> None:
        """
        Consume from raw_topic, anonymize, and publish to secure_topic.

        Args:
            max_messages: stop after processing this many messages
                           (None = run forever).
            on_record: optional callback invoked with each PipelineResult
                       (e.g. for logging, metrics, or PII auditing).
        """
        processed = 0
        for msg in self.consumer:
            stream_key = msg.key.decode("utf-8") if msg.key else "default"
            secure_bytes, result = self.pipeline.process_record(
                msg.value, stream_key=stream_key
            )

            self.producer.send(self.secure_topic, value=secure_bytes, key=msg.key)
            self.producer.flush()

            if on_record:
                on_record(result)

            processed += 1
            if max_messages is not None and processed >= max_messages:
                break

    def close(self) -> None:
        self.consumer.close()
        self.producer.close()


# ----------------------------------------------------------------------
# Backend 2: In-memory broker (no infrastructure required)
# ----------------------------------------------------------------------
class InMemoryBroker:
    """
    Minimal in-process pub/sub broker. Topics are FIFO queues of raw
    bytes payloads (optionally with a key), mirroring just enough of
    Kafka's interface for InMemoryStreamRunner.
    """

    def __init__(self):
        self._topics: dict[str, queue.Queue] = {}

    def _topic(self, name: str) -> queue.Queue:
        return self._topics.setdefault(name, queue.Queue())

    def produce(self, topic: str, value: bytes, key: Optional[bytes] = None) -> None:
        self._topic(topic).put((key, value))

    def consume(self, topic: str) -> Iterable[tuple[Optional[bytes], bytes]]:
        """Drain all currently-queued messages on `topic`."""
        q = self._topic(topic)
        while not q.empty():
            yield q.get_nowait()

    def topic_size(self, topic: str) -> int:
        return self._topic(topic).qsize()


class InMemoryStreamRunner:
    """
    Drop-in replacement for KafkaStreamRunner that requires no external
    infrastructure. Useful for local development, unit tests, and
    demoing the end-to-end pipeline.
    """

    def __init__(self, broker: Optional[InMemoryBroker] = None,
                 raw_topic: str = "raw-logs",
                 secure_topic: str = "secure-logs",
                 pipeline: Optional[AnonymizerPipeline] = None):
        self.broker = broker or InMemoryBroker()
        self.raw_topic = raw_topic
        self.secure_topic = secure_topic
        self.pipeline = pipeline or AnonymizerPipeline()

    def publish_raw(self, log_entry, key=None):
        # convert datetimes / pandas.Timestamp to ISO strings
        if "utc_date_time" in log_entry and hasattr(log_entry["utc_date_time"], "isoformat"):
            log_entry["utc_date_time"] = log_entry["utc_date_time"].isoformat()
        raw_bytes = json.dumps(log_entry).encode("utf-8")
        key_bytes = key.encode("utf-8") if key else None
        self.broker.produce(self.raw_topic, raw_bytes, key_bytes)

    def run(self, on_record: Optional[Callable[[PipelineResult], None]] = None) -> int:
        """
        Drain everything currently on raw_topic, anonymize each
        message, and publish the result to secure_topic.

        Returns the number of records processed.
        """
        processed = 0
        for key, raw_bytes in self.broker.consume(self.raw_topic):
            stream_key = key.decode("utf-8") if key else "default"
            secure_bytes, result = self.pipeline.process_record(
                raw_bytes, stream_key=stream_key
            )
            self.broker.produce(self.secure_topic, secure_bytes, key)

            if on_record:
                on_record(result)

            processed += 1

        return processed

    def drain_secure_logs(self) -> list[dict]:
        """Consume and return all anonymized records from secure_topic."""
        return [
            json.loads(value.decode("utf-8"))
            for _, value in self.broker.consume(self.secure_topic)
        ]


if __name__ == "__main__":
    # End-to-end demo using the in-memory broker -- no Kafka/Docker
    # required. Generates a few synthetic NetFlow-style records across
    # different TLP levels, runs them through the full middleware, and
    # reports the secure-logs output plus latency stats (Section 3.7.3).
    runner = InMemoryStreamRunner()

    sample_records = [
        {
            "tlp": "TLP:RED",
            "src_ip": "192.168.1.50",
            "dst_ip": "203.0.113.42",
            "src_port": 51422,
            "dst_port": 443,
            "bytes": 15234,
            "packets": 12,
            "timestamp": 1718000000.123,
            "user_id": "jdoe",
            "message": "Failed password for user jdoe from 192.168.1.50 port 51422 ssh2",
        },
        {
            "tlp": "TLP:AMBER",
            "src_ip": "10.0.0.7",
            "dst_ip": "198.51.100.9",
            "src_port": 33891,
            "dst_port": 22,
            "bytes": 842,
            "packets": 6,
            "timestamp": 1718000001.500,
            "user_id": "alice.smith",
            "message": "PortScan detected from 10.0.0.7 targeting host=db-prod-2",
        },
        {
            "tlp": "TLP:CLEAR",
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "src_port": 53,
            "dst_port": 53000,
            "bytes": 128,
            "packets": 1,
            "timestamp": 1718000002.900,
            "user_id": "system",
            "message": "Benign DNS response from 8.8.8.8",
        },
    ]

    for i, record in enumerate(sample_records):
        runner.publish_raw(record, key=f"flow-{i}")

    def report(result: PipelineResult) -> None:
        print(f"[{result.policy['tlp']:<5} eps={result.policy['epsilon']:<5} "
              f"{result.latency_ms:6.3f} ms]  ", end="")
        print(result.anonymized)
        if result.pii_detected:
            for field_name, entities in result.pii_detected.items():
                for ent in entities:
                    print(f"    PII[{field_name}] {ent['entity_type']:<10} "
                          f"'{ent['original']}' -> '{ent['anonymized']}'")

    processed = runner.run(on_record=report)
    print(f"\nProcessed {processed} record(s).")
    print("Latency summary:", runner.pipeline.latency.summary())

    print("\nSecure-logs topic contents:")
    for rec in runner.drain_secure_logs():
        print(" ", rec)