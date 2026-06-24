"""Switch platform for EV Charger Modbus."""
import logging
import asyncio
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry

from . import EVChargerEntity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class EVChargerSwitch(EVChargerEntity, SwitchEntity):
    """Switch for enabling/disabling EV charging."""

    def __init__(
        self,
        coordinator,
        device_name: str,
        device: Any,
        unique_base: str
    ):
        """Initialize the switch."""
        super().__init__(coordinator, device_name, unique_base)

        self._device = device
        self._last_current = 16

        self._attr_name = f"{device_name} Charging Enable"
        self._attr_unique_id = f"{DOMAIN}_{self._unique_base}_charging_enable"

        _LOGGER.debug(
            "Switch initialized with name: %s, unique_id: %s",
            self._attr_name,
            self._attr_unique_id
        )

    @property
    def extra_state_attributes(self):
        """Return state attributes."""
        if self.coordinator.data is None:
            return {"state_description": "Unknown"}

        return {
            "state_description": self.coordinator.data
            .get("state", {})
            .get("description", "Unknown")
        }

    @property
    def is_on(self) -> bool | None:
        """Return true if charging is enabled."""

        if self.coordinator.data is None:
            return None

        current = (
            self.coordinator.data
            .get("charging", {})
            .get("current")
        )

        if current is None:
            return None

        return current > 0


    async def async_turn_on(self, **kwargs):
        """Resume charging."""

        _LOGGER.info(
            "Turning charging ON (restore current %sA)",
            self._last_current
        )

        try:
            success = await self._device.set_charging_current(
                self._last_current
            )

            if success:
                await asyncio.sleep(2)
                await self.coordinator.async_request_refresh()

            else:
                _LOGGER.error(
                    "Failed to restore charging current"
                )

        except Exception as e:
            _LOGGER.exception(
                "Error enabling charging: %s",
                e
            )


    async def async_turn_off(self, **kwargs):
        """Pause charging without disabling EVSE."""

        _LOGGER.info(
            "Turning charging OFF (set current to 0A)"
        )

        try:
            current = (
                self.coordinator.data
                .get("charging", {})
                .get("current")
            )

            if current and current > 0:
                self._last_current = current

            success = await self._device.set_charging_current(0)

            if success:
                _LOGGER.info(
                    "Charging paused, EVSE remains enabled"
                )

                await asyncio.sleep(2)
                await self.coordinator.async_request_refresh()

            else:
                _LOGGER.error(
                    "Failed to set charging current to 0"
                )

        except Exception as e:
            _LOGGER.exception(
                "Error pausing charging: %s",
                e
            )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up EV charger switch."""

    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    device = hass.data[DOMAIN][entry.entry_id]["device"]
    device_name = hass.data[DOMAIN][entry.entry_id][CONF_NAME]
    unique_base = coordinator.unique_base

    if not device:
        _LOGGER.error(
            "Device not initialized in hass.data[%s][%s]",
            DOMAIN,
            entry.entry_id
        )
        return

    async_add_entities(
        [
            EVChargerSwitch(
                coordinator=coordinator,
                device_name=device_name,
                device=device,
                unique_base=unique_base,
            )
        ]
    )
