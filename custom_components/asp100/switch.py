"""Switch entities: child lock, ionization, night, backlight auto-off."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .commands import (
    CMD_CHILD_LOCK,
    CMD_IONIZATION,
    CMD_NIGHT,
    CMD_BACKLIGHT,
)
from .const import DOMAIN
from .entity import Asp100Entity


@dataclass(frozen=True, kw_only=True)
class Asp100SwitchDescription(SwitchEntityDescription):
    value_key: str = ""
    opcode: int = 0


SWITCHES: tuple[Asp100SwitchDescription, ...] = (
    Asp100SwitchDescription(key="child_lock", value_key="child_lock", opcode=CMD_CHILD_LOCK, translation_key="child_lock", icon="mdi:lock"),
    Asp100SwitchDescription(key="ionization", value_key="ionization", opcode=CMD_IONIZATION, translation_key="ionization", icon="mdi:atom"),
    Asp100SwitchDescription(key="night", value_key="night", opcode=CMD_NIGHT, translation_key="night", icon="mdi:weather-night"),
    Asp100SwitchDescription(key="backlight", value_key="backlight", opcode=CMD_BACKLIGHT, translation_key="backlight", icon="mdi:led-outline",),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    data = coordinator.data or {}
    async_add_entities(
        Asp100Switch(coordinator, desc) for desc in SWITCHES if desc.value_key in data
    )


class Asp100Switch(Asp100Entity, SwitchEntity):
    entity_description: Asp100SwitchDescription

    def __init__(self, coordinator, description: Asp100SwitchDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.device.mac}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        val = self._state.get(self.entity_description.value_key)
        return None if val is None else bool(val)

    async def async_turn_on(self, **kwargs) -> None:
        await self.coordinator.async_send(
            self.coordinator.device.set_bool, self.entity_description.opcode, True
        )

    async def async_turn_off(self, **kwargs) -> None:
        await self.coordinator.async_send(
            self.coordinator.device.set_bool, self.entity_description.opcode, False
        )
