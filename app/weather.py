"""Clima de hoy en Santiago usando Open-Meteo (gratis, sin API key)."""
import time

import requests

API_URL = "https://api.open-meteo.com/v1/forecast"
PARAMS = {
    "latitude": -33.45,
    "longitude": -70.66,
    "current": "temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code",
    "daily": "temperature_2m_max,temperature_2m_min,precipitation_probability_max",
    "timezone": "America/Santiago",
    "forecast_days": 1,
}
CACHE_SECONDS = 600

# Códigos WMO usados por Open-Meteo
DESCRIPTIONS = {
    0: "Despejado", 1: "Mayormente despejado", 2: "Parcialmente nublado", 3: "Nublado",
    45: "Niebla", 48: "Niebla con escarcha",
    51: "Llovizna ligera", 53: "Llovizna", 55: "Llovizna intensa",
    61: "Lluvia ligera", 63: "Lluvia", 65: "Lluvia intensa",
    71: "Nieve ligera", 73: "Nieve", 75: "Nieve intensa",
    80: "Chubascos ligeros", 81: "Chubascos", 82: "Chubascos fuertes",
    95: "Tormenta", 96: "Tormenta con granizo", 99: "Tormenta fuerte con granizo",
}

_cache = {"time": 0.0, "data": None}


def get_santiago_weather():
    """Devuelve un dict con el clima o None si la API no responde."""
    if _cache["data"] and time.time() - _cache["time"] < CACHE_SECONDS:
        return _cache["data"]
    try:
        resp = requests.get(API_URL, params=PARAMS, timeout=5)
        resp.raise_for_status()
        raw = resp.json()
        current, daily = raw["current"], raw["daily"]
        data = {
            "temperature": current["temperature_2m"],
            "humidity": current["relative_humidity_2m"],
            "wind": current["wind_speed_10m"],
            "description": DESCRIPTIONS.get(current["weather_code"], "Desconocido"),
            "max": daily["temperature_2m_max"][0],
            "min": daily["temperature_2m_min"][0],
            "rain_probability": daily["precipitation_probability_max"][0],
            "updated": current["time"].replace("T", " "),
        }
    except (requests.RequestException, KeyError, IndexError, ValueError):
        return None
    _cache.update(time=time.time(), data=data)
    return data
