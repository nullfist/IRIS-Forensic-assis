// Investigation upsert
MERGE (i:Investigation {investigation_id: $investigation_id})
ON CREATE SET
  i.name = $name,
  i.status = coalesce($status, 'open'),
  i.created_at = datetime($created_at)
ON MATCH SET
  i.updated_at = datetime($updated_at),
  i.summary = coalesce($summary, i.summary);

// Event upsert
UNWIND $events AS event
MERGE (e:Event {event_id: event.event_id})
SET
  e.timestamp = datetime(event.timestamp),
  e.source = event.source,
  e.category = event.category,
  e.action = event.action,
  e.severity = event.severity,
  e.confidence = event.confidence,
  e.message = event.message,
  e.host_name = event.host_name,
  e.user_name = event.user_name,
  e.raw_event_id = event.raw_event_id,
  e.parser_name = event.parser_name,
  e.parser_version = event.parser_version
WITH e, event
MATCH (i:Investigation {investigation_id: $investigation_id})
MERGE (i)-[:CONTAINS_EVENT]->(e);

// Generic entity upsert pattern
UNWIND $entities AS entity
CALL {
  WITH entity
  WITH entity,
       CASE entity.type
         WHEN 'host' THEN 'Host'
         WHEN 'user' THEN 'User'
         WHEN 'process' THEN 'Process'
         WHEN 'file' THEN 'File'
         WHEN 'registry' THEN 'Registry'
         WHEN 'ip' THEN 'IP'
         WHEN 'domain' THEN 'Domain'
         ELSE 'Indicator'
       END AS label
  CALL apoc.merge.node([label], {entity_id: entity.entity_id}, entity.properties, entity.properties) YIELD node
  RETURN node
}
RETURN count(*) AS entities_upserted;

// Event to entity linkage
UNWIND $links AS link
MATCH (e:Event {event_id: link.event_id})
MATCH (n {entity_id: link.entity_id})
MERGE (e)-[r:INVOLVES {investigation_id: $investigation_id}]->(n)
ON CREATE SET
  r.first_seen = datetime(link.timestamp),
  r.count = 1,
  r.confidence = coalesce(link.confidence, 0.8)
ON MATCH SET
  r.last_seen = datetime(link.timestamp),
  r.count = coalesce(r.count, 1) + 1;

// Parent-child process edge
UNWIND $process_edges AS edge
MATCH (child:Process {entity_id: edge.child_entity_id})
MATCH (parent:Process {entity_id: edge.parent_entity_id})
MERGE (child)-[r:CHILD_OF {investigation_id: $investigation_id}]->(parent)
ON CREATE SET
  r.first_seen = datetime(edge.timestamp),
  r.event_ids = [edge.event_id]
ON MATCH SET
  r.last_seen = datetime(edge.timestamp),
  r.event_ids = apoc.coll.toSet(coalesce(r.event_ids, []) + edge.event_id);

// Network edge from process to IP/domain
UNWIND $network_edges AS edge
MATCH (p:Process {entity_id: edge.process_entity_id})
MATCH (ip:IP {entity_id: edge.ip_entity_id})
MERGE (p)-[r:CONNECTED_TO {investigation_id: $investigation_id, port: edge.port, protocol: edge.protocol}]->(ip)
ON CREATE SET
  r.first_seen = datetime(edge.timestamp),
  r.bytes_out = coalesce(edge.bytes_out, 0),
  r.bytes_in = coalesce(edge.bytes_in, 0)
ON MATCH SET
  r.last_seen = datetime(edge.timestamp),
  r.bytes_out = coalesce(r.bytes_out, 0) + coalesce(edge.bytes_out, 0),
  r.bytes_in = coalesce(r.bytes_in, 0) + coalesce(edge.bytes_in, 0);

// Alert upsert and support linkage
UNWIND $alerts AS alert
MERGE (a:Alert {alert_id: alert.alert_id})
SET
  a.name = alert.name,
  a.family = alert.family,
  a.severity = alert.severity,
  a.phase = alert.phase,
  a.confidence = alert.confidence,
  a.risk_score = alert.risk_score,
  a.status = alert.status,
  a.created_at = datetime(alert.created_at)
WITH a, alert
MATCH (i:Investigation {investigation_id: $investigation_id})
MERGE (i)-[:CONTAINS_ALERT]->(a)
WITH a, alert
UNWIND alert.supporting_event_ids AS supporting_event_id
MATCH (e:Event {event_id: supporting_event_id})
MERGE (a)-[:SUPPORTED_BY]->(e);