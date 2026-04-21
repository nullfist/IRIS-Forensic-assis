// Attack path between two entities within an investigation scope
MATCH (source {entity_id: $source_entity_id})
MATCH (target {entity_id: $target_entity_id})
CALL apoc.algo.allSimplePaths(source, target, 'INVOLVES|CHILD_OF|CONNECTED_TO|AUTHENTICATED_TO|ACTED_AS|OBSERVED_ON|TARGETS|SUPPORTED_BY|COMMUNICATED_WITH>', 6)
YIELD path
WITH path
WHERE all(rel IN relationships(path) WHERE coalesce(rel.investigation_id, $investigation_id) = $investigation_id)
RETURN path
ORDER BY length(path) ASC
LIMIT 10;

// Host pivot: all suspicious remote destinations from a host in a time window
MATCH (h:Host {entity_id: $host_entity_id})<-[:OBSERVED_ON]-(e:Event)-[:INVOLVES]->(p:Process)-[r:CONNECTED_TO]->(ip:IP)
WHERE e.timestamp >= datetime($start_time)
  AND e.timestamp <= datetime($end_time)
RETURN h, p, r, ip
ORDER BY e.timestamp ASC
LIMIT 200;

// Alert evidence expansion
MATCH (a:Alert {alert_id: $alert_id})-[:SUPPORTED_BY]->(e:Event)
OPTIONAL MATCH (e)-[:INVOLVES]->(n)
RETURN a, e, collect(DISTINCT n) AS entities
ORDER BY e.timestamp ASC;

// User to remote host authentication pivot
MATCH (u:User {entity_id: $user_entity_id})-[r:AUTHENTICATED_TO]->(h:Host)
WHERE coalesce(r.investigation_id, $investigation_id) = $investigation_id
RETURN u, r, h
ORDER BY coalesce(r.last_seen, r.first_seen) DESC;

// Process ancestry and descendant fan-out
MATCH path = (p:Process {entity_id: $process_entity_id})-[:CHILD_OF*0..4]-(related:Process)
RETURN path
LIMIT 100;

// Domain and exfil pivot
MATCH (p:Process)-[r:CONNECTED_TO]->(ip:IP)-[:RESOLVES_TO]->(d:Domain)
WHERE d.name CONTAINS $domain_fragment
  AND r.bytes_out > $min_bytes_out
RETURN p, r, ip, d
ORDER BY r.bytes_out DESC
LIMIT 100;