/**
 * Compact MAC OUI (first 3 octets) -> vendor lookup for LAN device discovery.
 *
 * This is intentionally a small, hand-picked subset of the IEEE OUI registry
 * covering the manufacturers most common on a home/SMB network (routers, phones,
 * IoT, computers). It is best-effort labeling only — an unknown prefix simply
 * yields no vendor. Keys are the uppercase 6-hex-digit OUI with no separators.
 */
export const OUI_VENDORS: Record<string, string> = {
  // Ubiquiti (UniFi gateways, APs, switches, cameras)
  "002722": "Ubiquiti",
  "0418D6": "Ubiquiti",
  "044F8A": "Ubiquiti",
  "245A4C": "Ubiquiti",
  "687251": "Ubiquiti",
  "744D28": "Ubiquiti",
  "788A20": "Ubiquiti",
  "802AA8": "Ubiquiti",
  "B4FBE4": "Ubiquiti",
  "DC9FDB": "Ubiquiti",
  "E063DA": "Ubiquiti",
  "F09FC2": "Ubiquiti",
  "FCECDA": "Ubiquiti",

  // Apple
  "001451": "Apple",
  "0017F2": "Apple",
  "0019E3": "Apple",
  "001EC2": "Apple",
  "0023DF": "Apple",
  "0025BC": "Apple",
  "0026BB": "Apple",
  "3035AD": "Apple",
  "3C0754": "Apple",
  "40A6D9": "Apple",
  "5855CA": "Apple",
  "7CD1C3": "Apple",
  "881FA1": "Apple",
  "A4D1D2": "Apple",
  "AC87A3": "Apple",
  "F0DBF8": "Apple",
  "F40F24": "Apple",

  // Samsung
  "002454": "Samsung",
  "0021D1": "Samsung",
  "08373D": "Samsung",
  "0C715D": "Samsung",
  "5001BB": "Samsung",
  "5CF6DC": "Samsung",
  "8425DB": "Samsung",
  "BC8CCD": "Samsung",
  "E8508B": "Samsung",

  // Google / Nest
  "001A11": "Google",
  "3C5AB4": "Google",
  "54600E": "Google",
  "6466B3": "Google",
  "94EB2C": "Google",
  "A4775B": "Google",
  "F4F5D8": "Google",
  "F4F5E8": "Google",

  // Amazon (Echo, Fire, Ring)
  "0C47C9": "Amazon",
  "40B4CD": "Amazon",
  "44650D": "Amazon",
  "68543B": "Amazon",
  "747548": "Amazon",
  "84D6D0": "Amazon",
  "A002DC": "Amazon",
  "F0272D": "Amazon",
  "FCA183": "Amazon",

  // Intel (NICs / laptops)
  "001517": "Intel",
  "0024D7": "Intel",
  "3CA9F4": "Intel",
  "7C7A91": "Intel",
  "8CA982": "Intel",
  "94659C": "Intel",
  "A0A8CD": "Intel",
  "E4A471": "Intel",

  // Raspberry Pi Foundation
  "B827EB": "Raspberry Pi",
  "DCA632": "Raspberry Pi",
  "E45F01": "Raspberry Pi",
  "28CDC1": "Raspberry Pi",

  // Espressif (ESP8266/ESP32 IoT)
  "240AC4": "Espressif",
  "3C71BF": "Espressif",
  "5CCF7F": "Espressif",
  "84F3EB": "Espressif",
  "A020A6": "Espressif",
  "B4E62D": "Espressif",
  "BCDDC2": "Espressif",
  "ECFABC": "Espressif",

  // TP-Link
  "0027CE": "TP-Link",
  "1CFA68": "TP-Link",
  "50C7BF": "TP-Link",
  "5C628B": "TP-Link",
  "A42BB0": "TP-Link",
  "C006C3": "TP-Link",
  "EC086B": "TP-Link",

  // Netgear
  "00146C": "Netgear",
  "20E52A": "Netgear",
  "9C3DCF": "Netgear",
  "A040A0": "Netgear",
  "C03F0E": "Netgear",

  // Cisco / Meraki
  "00000C": "Cisco",
  "001A2F": "Cisco",
  "00259C": "Cisco",
  "881DFC": "Cisco Meraki",
  "E0CB4E": "Cisco Meraki",

  // Sonos
  "000E58": "Sonos",
  "347E5C": "Sonos",
  "5CAAFD": "Sonos",
  "B8E937": "Sonos",

  // Microsoft (Surface / Xbox)
  "0017FA": "Microsoft",
  "1CBF74": "Microsoft",
  "28186F": "Microsoft",
  "C83F26": "Microsoft",
  "E8B1FC": "Microsoft",

  // Synology / QNAP (NAS)
  "001132": "Synology",
  "245EBE": "QNAP",
  "00089B": "QNAP",

  // Hikvision / Dahua (cameras)
  "4CBD8F": "Hikvision",
  "BCAD28": "Hikvision",
  "3CEF8C": "Dahua",
  "9CC960": "Dahua",
};
