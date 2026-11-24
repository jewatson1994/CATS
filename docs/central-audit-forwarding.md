# Central audit forwarding

Open **Admin → General Policy → Log forwarding** on the authoritative CATS Portal/HQ and choose **Add destination**. The same controls are available at `/admin/audit`. They require global audit access and global configuration authority. HQ commits each accepted event to its operational database before its forwarding worker contacts an external destination. Multiple destinations can run simultaneously. Replicas queue their events for HQ.

1. Name the destination and enter the receiver settings below. Select **Security audit** for the CATS audit trail, **Diagnostics** for structured errors, and **Operational logs** for component activity. Choose all three to receive all three streams.
2. Save the destination. Use **Send test event** to generate a searchable event ID, including while the destination is paused. Search for that ID on the receiver to verify end-to-end delivery.
3. Enable forwarding and use **Refresh status** to see the pending count, last successful send and last error. Use **Replay retained audit** to include security events already stored in the portal database. This includes events older than the Audit Policy page’s display window.

| Receiver | Configuration |
| --- | --- |
| Syslog | Enter the collector’s IP address or DNS name, port, and transport. TLS defaults to 6514. TCP and UDP default to 514. TCP and TLS use RFC 5424 messages with octet-counted framing. The collector must accept that framing. For TLS, the certificate must cover the hostname or IP entered. Supply a public CA certificate in PEM format for an internal CA. |
| Splunk HTTP Event Collector | Enable a token with access to the intended index. Use a token with indexer acknowledgment turned off. Enter the HTTPS HEC URL (for example, `https://splunk.example:8088`) and token. The index is optional. The source type defaults to `cats:audit`. An existing enterprise syslog collector that feeds Splunk can also receive the Syslog output. |
| Azure Log Analytics | Create a workspace table and a data collection rule (DCR) that routes its input stream to that table. Grant the Entra application **Monitoring Metrics Publisher** on the DCR. Enter the DCR or data collection endpoint’s **logs ingestion** URL, DCR immutable ID, input stream, tenant ID, client ID, client secret and cloud. The worker must reach the chosen cloud’s Entra authority and ingestion endpoint. |

For Azure, declare the input stream with `event_id` (string), `timestamp` (datetime), `category` (string), and `data` (dynamic). For a table with those event fields and the standard Azure time column, use this DCR transform and match the projected columns to the table schema.

```kusto
source | project TimeGenerated = timestamp, event_id, category, data
```

To find a test event in an example table named `CatsAudit_CL`, use the ID displayed by CATS.

```kusto
CatsAudit_CL | where event_id == "<test-event-id>"
```

Receiver setup details are available in [Syslog over TLS](https://www.rfc-editor.org/rfc/rfc5425), [Splunk HEC setup](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/set-up-and-use-http-event-collector-in-splunk-web), and [Azure Monitor Logs Ingestion](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview).

## How components reach HQ

| Source | Collection and verification |
| --- | --- |
| Portal, OCI proxy, Compose workers and supporting services | Database triggers capture committed security audit events and structured diagnostics. The Compose log collector receives service stdout and stderr over a private Docker logging socket, spools them locally, then stores them using CATS. This covers the databases, backup and initialization jobs, and the included nginx ingress when deployed. On HQ, use **Received by HQ** to see actual receipt times and inspect operational events. |
| Replica sites | Enroll a source at HQ for each replica and enable all source categories for it. Supply its one-time token in `CATS_AUDIT_HQ_TOKEN` and set `CATS_AUDIT_HQ_URL` to the HTTPS origin of HQ. For internal PKI, set `CATS_AUDIT_HQ_CA_B64` to the base64-encoded public CA PEM. Apply the replica Compose configuration. The reporter sends its queued audit, diagnostic and operational records to HQ. The replica page shows the link state and queue depth. |
| Linked runtime agents | The agent uses its existing CATS URL, linked identity and state volume to journal and retry its own operational events. When linked to a replica, the replica relays the events to HQ. These are the CATS agent's own reports. Application container output from monitored workloads is a separate data source. |
| Validator appliances | The validator journals its job, security and server events locally. HQ reads the journal over the existing mTLS validation connection, commits the records, then acknowledges them. If the appliance trusts several client fingerprints, configure `CATS_VALIDATOR_LOG_CLIENT_SHA256` on it to identify the HQ certificate authorized to read the complete journal. |
| Standalone or disconnected scanner CLI | Pushing an assessment creates the normal HQ scan audit record. To include the individual prepare/evaluate/patch runs, set `CATS_COMPONENT_LOG_SPOOL` to a persistent journal directory before running those commands. Carry that directory across offline stages. On a connected runner, set `CATS_PORTAL_URL` and its HQ-enrolled `CATS_COMPONENT_LOG_TOKEN`, then run `cats push logs --input /path/to/journal`. Only structured phase records are sent. Repeating the upload preserves the event IDs. |

An additional component can use an individually enrolled, revocable source credential to POST an event to the HTTPS HQ endpoint `/api/v1/component-logs/events`. Supply the bearer token, a source-unique `event_id`, a timezone-aware `timestamp`, a permitted `category`, and a JSON object in `data`. Retain the record until HQ returns `accepted` or `duplicate` with the same ID. HQ binds attribution to the authenticated source. Use a separate token for each independent reporter and retain the same enrollment when rotating credentials.

## Event coverage and recovery

Each committed HQ security audit row generates a copy for each enabled audit destination. That includes recorded user and robot actions, worker actions, approval changes, OCI access decisions and attributed remote audit records. The envelope carries an event ID, timestamp, category and redacted data. A reported audit preserves the remote event ID and reporting source. Reported operational events include the time HQ received them as well as the event's source timestamp.

The portal queues events in the same database transaction that records them. The `audit-forward-worker` service uses the existing CATS image, retries delivery in the background, and resumes after restart. Credentials are encrypted using the portal configuration encryption key. The worker and portal must use the same key.

During an outage, pending copies accumulate in the operational database. Monitor available disk space and the destination's pending count. Pausing a destination stops live capture and pauses regular delivery. Re-enable it to resume and request a replay to fill the paused interval from retained security records. Replay deduplicates captured events for that destination. If a receiver accepts an event just before the worker restarts, the retry can repeat its stable event ID. Receivers can deduplicate on that ID.

Component operational history defaults to seven days and 50,000 records. Each destination can hold 50,000 pending operational log copies by default and records an overflow count. Committed security audit copies remain queued during a receiver outage. Monitor free disk space on HQ, replicas and validator appliances. Docker buffers a limited number of service output records in daemon memory before the local collector acknowledges them. Restarting Docker during a collection outage can lose this buffered output. The collector filters successful collection requests, sensitive database statement text and credentials.

A successful UDP send only establishes that CATS sent the datagram. A successful TCP/TLS write, HEC acceptance, or Azure ingestion response is also distinct from finding the event in the final index or table. Use the test ID to verify indexing. To change recipients, add and test the new destination. Removing a paused destination with pending copies requires confirmation of the current count and records that count in the local audit trail.
