"""12123 系统集成."""
import logging
from typing import Final, Any, Dict

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# 集成支持的平台
PLATFORMS: Final[Platform] = [Platform.SENSOR]

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """设置12123集成."""
    _LOGGER.debug("12123集成从configuration.yaml设置")
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """设置12123集成配置项."""
    _LOGGER.info("设置12123集成配置项: %s", entry.title)

    # 前向设置平台
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """卸载12123集成配置项."""
    _LOGGER.info("卸载12123集成配置项: %s", entry.title)

    # 反向设置平台
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

# 需要脱敏的敏感字段
TO_REDACT = ["accessToken", "JSESSIONID-L", "acw_tc", "url"]


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> Dict[str, Any]:
    """Return diagnostics for a config entry."""
    _LOGGER.debug("收集12123集成诊断信息")

    # 手动实现数据脱敏
    def redact_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """脱敏敏感数据"""
        redacted = {}
        for key, value in data.items():
            if key in TO_REDACT:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        return redacted

    diagnostics_data = {
        "entry_id": entry.entry_id,
        "title": entry.title,
        "data": redact_data(entry.data),
        "options": redact_data(entry.options),
        "domain": DOMAIN,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "modified_at": entry.modified_at.isoformat() if entry.modified_at else None,
    }

    return diagnostics_data

