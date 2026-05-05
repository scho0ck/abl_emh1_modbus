"""The EV Charger Modbus integration."""
import logging
from typing import Any
from datetime import timedelta
import voluptuous as vol
import async_timeout
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME, CONF_PORT, CONF_SLAVE, Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import device_registry as dr
from .const import (
    DOMAIN,
    CONF_BAUDRATE,
    CONF_MAX_CURRENT,
    DEFAULT_NAME,
    DEFAULT_SLAVE,
    DEFAULT_BAUDRATE,
    DEFAULT_MAX_CURRENT,
    CONF_CONNECTION_TYPE,
    CONNECTION_TYPE_SERIAL,
    CONNECTION_TYPE_TCP,
)
from .modbus_device import ModbusASCIIDevice
from datetime import datetime
import asyncio
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[Platform] = [Platform.NUMBER, Platform.SENSOR, Platform.SWITCH]

# Add device specific constants
MANUFACTURER = "ABL"
MODEL = "eMH1"

SET_CHARGING_CURRENT_SERVICE = "set_charging_current"
# Update the service schema to enforce that 'target' (if provided) contains an 'entity_id' as a list of strings
# Update service schema to accept entity_id as string or a list of strings
SET_CHARGING_CURRENT_SCHEMA = vol.Schema({
    vol.Optional("target"): vol.Schema({
        vol.Required("entity_id"): vol.All(cv.ensure_list, [cv.string])
    }),
    vol.Required("current"): vol.All(
        vol.Coerce(int),
        vol.Range(min=0, max=32)  # We'll validate the actual max in the handler
    )
}, extra=vol.ALLOW_EXTRA)

class EVChargerEntity(CoordinatorEntity):
    """Base class for EV Charger entities."""
    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        device_name: str,
        unique_base: str,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        serial_number = getattr(coordinator, "serial_number", None)
        firmware_version = getattr(coordinator, "firmware_version", None)
        hardware_version = getattr(coordinator, "hardware_version", None)
        self._unique_base = unique_base

        # Use the same identifiers as the registered device
        identifiers = {(DOMAIN, serial_number)} if serial_number else {(DOMAIN, device_name)}

        self._attr_device_info = DeviceInfo(
            identifiers=identifiers,
            name=device_name,
            manufacturer=MANUFACTURER,
            model=MODEL,
            sw_version=firmware_version,
            hw_version=hardware_version,
        )
        self._attr_has_entity_name = True

async def async_update_data(coordinator, device, device_info, hass):
    """Fetch data from the device."""
    now = datetime.now()
    last_update = device_info.get("last_update", now)
    
    # Weekly update for device info (already correct)
    if (now - last_update).days > 7:
        _LOGGER.debug("Updating serial number and firmware info (weekly)")
        updated_info = {
            "serial_number": await device.read_serial_number(),
            "firmware_info": await device.read_firmware_info(),
        }
        if updated_info["serial_number"]:
            coordinator.serial_number = updated_info["serial_number"]
        if updated_info["firmware_info"]:
            coordinator.firmware_version = updated_info["firmware_info"].get("firmware_version")
            coordinator.hardware_version = updated_info["firmware_info"].get("hardware_version")
        device_info["last_update"] = now

    async with async_timeout.timeout(10):
        # Read current data ONCE
        current_data = await device.read_current()
        
        if current_data is None:
            _LOGGER.debug("Device unavailable, trying wake-up")
            await device.wake_up_device()
            current_data = await device.read_current()
        
        if current_data is None:
            return {
                "available": False,
                "error": "Failed to read data from device"
            }
        
        # Read duty cycle ONCE
        duty_cycle = await device.read_duty_cycle()
        
        # Calculate power from already-read values (no additional reads)
        total_current = (current_data.get('ict1', 0) + 
                        current_data.get('ict2', 0) + 
                        current_data.get('ict3', 0))
        power_consumption = total_current * 230  # Simple calculation, no re-reading
        
        # Determine charging state from state_code (no additional reads)
        state_code = current_data.get('state_code')
        if isinstance(state_code, str) and state_code.startswith('0x'):
            state_code_int = int(state_code, 16)
        else:
            state_code_int = state_code
        
        charging_enabled = state_code_int in [0xB1, 0xB2, 0xC2] if state_code_int else False
        
        return {
            "available": True,
            "state": {
                "code": current_data["state_code"],
                "description": current_data["state_description"],
            },
            "charging": {
                "enabled": charging_enabled,
                "max_current": current_data["max_current"]
            },
            "current_measurements": {
                "ict1": current_data["ict1"],
                "ict2": current_data["ict2"],
                "ict3": current_data["ict3"]
            },
            "duty_cycle": duty_cycle,
            "power_consumption": power_consumption
        }

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the EV Charger Modbus component."""
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up EV Charger from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    # Default to serial for backward compatibility with old configs
    connection_type = entry.data.get(CONF_CONNECTION_TYPE, CONNECTION_TYPE_SERIAL)
    device = ModbusASCIIDevice(
        port=entry.data[CONF_PORT],
        slave_id=entry.data.get(CONF_SLAVE, DEFAULT_SLAVE),
        baudrate=entry.data.get(CONF_BAUDRATE, DEFAULT_BAUDRATE),
        max_current=entry.data.get(CONF_MAX_CURRENT, DEFAULT_MAX_CURRENT),
        connection_type=connection_type,
    )

    await device.connect()
    await device.wake_up_device()
    device_info = {
        "serial_number": await device.read_serial_number(),
        "firmware_info": await device.read_firmware_info(),
        "max_current_from_device": await device.read_max_current_setting(),
    }
    serial_number = device_info["serial_number"]
    firmware_info = device_info["firmware_info"]

    # Update device max_current with actual reading from device, fallback to config
    device_max_current = device_info["max_current_from_device"]
    if device_max_current:
        device.max_current = device_max_current
        _LOGGER.info("Using max current from device: %dA", device_max_current)
        actual_max_current = device_max_current
    else:
        # Fallback to config value if reading fails
        config_max_current = entry.data.get(CONF_MAX_CURRENT, DEFAULT_MAX_CURRENT)
        device.max_current = config_max_current
        _LOGGER.warning("Could not read max current from device, using config value: %dA", config_max_current)
        actual_max_current = config_max_current
    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=DOMAIN,
        update_method=lambda: async_update_data(coordinator, device, device_info, hass),
        update_interval=timedelta(seconds=15),
    )
    coordinator.device = device
    coordinator.serial_number = serial_number if serial_number else None
    coordinator.firmware_info = firmware_info  # Store the whole dictionary
    coordinator.firmware_version = firmware_info.get("firmware_version") if firmware_info else None
    coordinator.hardware_version = firmware_info.get("hardware_version") if firmware_info else None
    coordinator.max_current = actual_max_current
    coordinator.unique_base = serial_number or entry.entry_id
    await coordinator.async_config_entry_first_refresh()
    device_name = entry.data.get(CONF_NAME, DEFAULT_NAME)

    # Register the device in the device registry
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, serial_number)},
        name=device_name,
        manufacturer=MANUFACTURER,
        model=MODEL,
        sw_version=firmware_info.get("firmware_version") if firmware_info else None,
        hw_version=firmware_info.get("hardware_version") if firmware_info else None,
    )

    hass.data[DOMAIN][entry.entry_id] = {
        "device": device,
        "coordinator": coordinator,
        CONF_NAME: device_name,
        "max_current": actual_max_current,
        "entities": {},  # Add this to store entities
    }

    if not hass.services.has_service(DOMAIN, SET_CHARGING_CURRENT_SERVICE):
        async def handle_set_charging_current(call: ServiceCall) -> None:
            """Handle setting the charging current."""
            current = int(call.data["current"])
            _LOGGER.debug("Service call data: %s", call.data)

            entity_ids = []
            if "target" in call.data and call.data["target"] is not None:
                target = call.data["target"]
                if "entity_id" in target:
                    eids = target["entity_id"]
                    if isinstance(eids, list):
                        entity_ids = eids
                    elif isinstance(eids, str) and eids.strip():
                        entity_ids = [eids.strip()]

            if not entity_ids:
                e = call.data.get("entity_id")
                if isinstance(e, list):
                    entity_ids = e
                elif isinstance(e, str) and e.strip():
                    entity_ids = [e.strip()]

            if not entity_ids:
                _LOGGER.error("No target specified. Call data: %s", call.data)
                return

            entity_registry = er.async_get(hass)
            target_entry_ids = set()
            for entity_id in entity_ids:
                entity_entry = entity_registry.async_get(entity_id)
                if entity_entry is None:
                    _LOGGER.error("Unknown entity_id in service call: %s", entity_id)
                    continue
                if entity_entry.config_entry_id is None:
                    _LOGGER.error("Entity %s is not tied to a config entry", entity_id)
                    continue
                target_entry_ids.add(entity_entry.config_entry_id)

            if not target_entry_ids:
                return

            for target_entry_id in target_entry_ids:
                entry_data = hass.data[DOMAIN].get(target_entry_id)
                if entry_data is None:
                    _LOGGER.error("Config entry %s is not loaded", target_entry_id)
                    continue

                device = entry_data["device"]
                max_current = entry_data["max_current"]
                if current > max_current:
                    _LOGGER.error(
                        "Requested current %d exceeds maximum allowed current %d",
                        current,
                        max_current,
                    )
                    continue

                try:
                    result = await device.write_current(current)
                    if result:
                        _LOGGER.info(
                            "Successfully set current to %dA for %s",
                            current,
                            target_entry_id,
                        )
                    else:
                        _LOGGER.error(
                            "Device did not accept current value %dA for %s",
                            current,
                            target_entry_id,
                        )
                except Exception as ex:
                    _LOGGER.error(
                        "Failed to set current for %s: %s",
                        target_entry_id,
                        str(ex),
                    )

        hass.services.async_register(
            DOMAIN,
            SET_CHARGING_CURRENT_SERVICE,
            handle_set_charging_current,
            schema=SET_CHARGING_CURRENT_SCHEMA,
        )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        device = hass.data[DOMAIN][entry.entry_id]["device"]
        if device.transport and device.transport.is_open:
            device.transport.close()
        hass.data[DOMAIN].pop(entry.entry_id)
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SET_CHARGING_CURRENT_SERVICE)
    return unload_ok
