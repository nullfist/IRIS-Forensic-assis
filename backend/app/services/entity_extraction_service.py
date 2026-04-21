from __future__ import annotations

from backend.app.models.enums import EntityType
from backend.app.schemas.events import EntityRef, NormalizedEvent


class EntityExtractionService:
    """Derive canonical entity references from normalized events."""

    def extract_entities(self, event: NormalizedEvent) -> list[EntityRef]:
        entities: dict[str, EntityRef] = {entity.entity_id: entity for entity in event.entities}

        if event.host:
            entity = EntityRef(
                entity_id=f"host:{event.host.lower()}",
                entity_type=EntityType.HOST,
                name=event.host,
                display_name=event.host,
            )
            entities[entity.entity_id] = entity

        if event.user:
            entity = EntityRef(
                entity_id=f"user:{event.user.lower()}",
                entity_type=EntityType.USER,
                name=event.user,
                display_name=event.user,
                host=event.host,
            )
            entities[entity.entity_id] = entity

        if event.process and event.process.image:
            process_key = event.process.process_guid or f"{event.process.image}:{event.process.pid or 'unknown'}"
            entity = EntityRef(
                entity_id=f"process:{process_key}",
                entity_type=EntityType.PROCESS,
                name=event.process.image,
                display_name=event.process.image.rsplit("\\", 1)[-1],
                host=event.host,
                attributes={
                    "pid": event.process.pid,
                    "image": event.process.image,
                    "command_line": event.process.command_line,
                    "parent_image": event.process.parent_image,
                },
            )
            entities[entity.entity_id] = entity

        if event.network:
            if event.network.dst_ip:
                entities[f"ip:{event.network.dst_ip}"] = EntityRef(
                    entity_id=f"ip:{event.network.dst_ip}",
                    entity_type=EntityType.IP,
                    name=event.network.dst_ip,
                    attributes={"port": event.network.dst_port, "direction": event.network.direction},
                )
            if event.network.src_ip:
                entities[f"ip:{event.network.src_ip}"] = EntityRef(
                    entity_id=f"ip:{event.network.src_ip}",
                    entity_type=EntityType.IP,
                    name=event.network.src_ip,
                    attributes={"port": event.network.src_port, "direction": event.network.direction},
                )
            if event.network.domain:
                entities[f"domain:{event.network.domain.lower()}"] = EntityRef(
                    entity_id=f"domain:{event.network.domain.lower()}",
                    entity_type=EntityType.DOMAIN,
                    name=event.network.domain,
                )

        if event.file and event.file.path:
            entities[f"file:{event.file.path.lower()}"] = EntityRef(
                entity_id=f"file:{event.file.path.lower()}",
                entity_type=EntityType.FILE,
                name=event.file.path,
                host=event.host,
                attributes={"operation": event.file.operation},
            )

        if event.registry and event.registry.key_path:
            entities[f"registry:{event.registry.key_path.lower()}"] = EntityRef(
                entity_id=f"registry:{event.registry.key_path.lower()}",
                entity_type=EntityType.REGISTRY_KEY,
                name=event.registry.key_path,
                host=event.host,
                attributes={"operation": event.registry.operation, "value_name": event.registry.value_name},
            )

        event.entities = list(entities.values())
        return event.entities