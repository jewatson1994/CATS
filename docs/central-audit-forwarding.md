# Central audit forwarding

Open **Admin → General Policy → Log forwarding** and choose **Add destination**. The same controls are available at `/admin/audit`. They require global audit access and global configuration authority. Each portal, including a replica, manages its own destinations. Destinations start receiving new events when enabled and can run simultaneously.

1. Name the destination and enter the receiver settings below. Select **Security audit** for the full CATS audit trail. Select **Diagnostics** to include errors recorded by the Diagnostics Center.
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

Receiver references: [Syslog over TLS](https://www.rfc-editor.org/rfc/rfc5425), [Splunk HEC setup](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/set-up-and-use-http-event-collector-in-splunk-web), and [Azure Monitor Logs Ingestion](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview).

## Event coverage and recovery

Each committed security audit row generates a copy for each enabled audit destination. That includes user and robot actions, worker actions, approval changes, and recorded OCI access decisions. The event includes the original timestamp, event ID, action, actor identity when recorded, target, and redacted details. The diagnostics option forwards structured diagnostic records. Host journals, raw container output, remote validator logs and per-document intelligence-import telemetry have separate sources.

The portal queues events in the same database transaction that records them. The `audit-forward-worker` service uses the existing CATS image, retries delivery in the background, and resumes after restart. Credentials are encrypted using the portal configuration encryption key. The worker and portal must use the same key.

During an outage, pending copies accumulate in the operational database. Monitor available disk space and the destination's pending count. Pausing a destination stops live capture and pauses regular delivery. Re-enable it to resume and request a replay to fill the paused interval from retained security records. Replay deduplicates captured events for that destination. If a receiver accepts an event just before the worker restarts, the retry can repeat its stable event ID. Receivers can deduplicate on that ID.

A successful UDP send only establishes that CATS sent the datagram. A successful TCP/TLS write, HEC acceptance, or Azure ingestion response is also distinct from finding the event in the final index or table. Use the test ID to verify indexing. To change recipients, add and test the new destination. Removing a paused destination with pending copies requires confirmation of the current count and records that count in the local audit trail.
