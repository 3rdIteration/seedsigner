"""
NDEF (NFC Data Exchange Format) helper module for encoding and decoding NDEF records.
Provides utilities for working with Text, URI, and Android App Launch NDEF record types.
"""

import ndef
from typing import List, Tuple, Optional, Dict, Any


class NdefRecordType:
    """NDEF Record type constants."""
    TEXT = "text"
    URI = "uri"
    ANDROID_APP = "android_app"


def decode_ndef_bytes(ndef_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Decode NDEF bytes into human-readable records.
    
    Args:
        ndef_bytes: Raw NDEF data bytes
        
    Returns:
        List of dictionaries describing each NDEF record with type and content
        
    Raises:
        Exception: If NDEF data is invalid or cannot be decoded
    """
    if not ndef_bytes or len(ndef_bytes) == 0:
        return []
    
    try:
        records = ndef.message_decoder(ndef_bytes)
        decoded_records = []
        
        for record in records:
            record_info = {
                "type": record.type.decode() if isinstance(record.type, bytes) else record.type,
                "raw_type": record.type,
            }
            
            # Handle Text records
            if record.type == b'T':
                try:
                    text_data = record.data.decode('utf-8')
                    # First byte contains language code length
                    if len(record.data) > 0:
                        lang_len = record.data[0] & 0x3F
                        language = record.data[1:1+lang_len].decode('ascii', errors='ignore')
                        text = record.data[1+lang_len:].decode('utf-8')
                        record_info.update({
                            "record_type": NdefRecordType.TEXT,
                            "text": text,
                            "language": language,
                        })
                    else:
                        record_info.update({
                            "record_type": NdefRecordType.TEXT,
                            "text": "",
                            "language": "en",
                        })
                except Exception as e:
                    record_info.update({
                        "record_type": NdefRecordType.TEXT,
                        "error": f"Failed to decode text: {str(e)[:50]}",
                    })
            
            # Handle URI records
            elif record.type == b'U':
                try:
                    # First byte is URI scheme
                    if len(record.data) > 0:
                        scheme_byte = record.data[0]
                        # URI scheme codes (0x00 = http://, 0x01 = https://, etc.)
                        schemes = {
                            0x00: "",
                            0x01: "http://",
                            0x02: "https://",
                            0x03: "http://www.",
                            0x04: "https://www.",
                            0x05: "tel:",
                            0x06: "mailto:",
                            0x07: "ftp://",
                        }
                        scheme = schemes.get(scheme_byte, "")
                        uri = scheme + record.data[1:].decode('utf-8')
                        record_info.update({
                            "record_type": NdefRecordType.URI,
                            "uri": uri,
                        })
                    else:
                        record_info.update({
                            "record_type": NdefRecordType.URI,
                            "uri": "",
                        })
                except Exception as e:
                    record_info.update({
                        "record_type": NdefRecordType.URI,
                        "error": f"Failed to decode URI: {str(e)[:50]}",
                    })
            
            # Handle Android App Launch records (U record with special format or custom record)
            elif record.type == b'a' and record.name == b'android.com:pkg':
                try:
                    package_name = record.data.decode('utf-8')
                    record_info.update({
                        "record_type": NdefRecordType.ANDROID_APP,
                        "package_name": package_name,
                    })
                except Exception as e:
                    record_info.update({
                        "record_type": NdefRecordType.ANDROID_APP,
                        "error": f"Failed to decode Android app: {str(e)[:50]}",
                    })
            
            else:
                # Generic record type
                record_info["data_hex"] = record.data.hex().upper()
            
            decoded_records.append(record_info)
        
        return decoded_records
    
    except Exception as e:
        raise Exception(f"Failed to decode NDEF: {str(e)}")


def create_text_record(text: str, language: str = "en") -> bytes:
    """
    Create an NDEF Text record.
    
    Args:
        text: Text content
        language: Language code (default: "en")
        
    Returns:
        NDEF-encoded bytes for this record
    """
    # Create Text record using ndeflib
    record = ndef.TextRecord(text=text, language=language)
    # Encode as message (single record)
    return ndef.message_encoder([record])


def create_uri_record(uri: str) -> bytes:
    """
    Create an NDEF URI record.
    
    Args:
        uri: URI to encode (e.g., "https://example.com")
        
    Returns:
        NDEF-encoded bytes for this record
    """
    # Create URI record using ndeflib
    record = ndef.UriRecord(uri=uri)
    # Encode as message (single record)
    return ndef.message_encoder([record])


def create_android_app_record(package_name: str) -> bytes:
    """
    Create an NDEF record to launch an Android application.
    
    Args:
        package_name: Android package name (e.g., "org.satochip.seedkeeper")
        
    Returns:
        NDEF-encoded bytes for this record
    """
    # Create a custom Android App Launch record
    # Type: 'a' (external), Name: 'android.com:pkg'
    record = ndef.Record(
        type='android.com:pkg',
        data=package_name.encode('utf-8')
    )
    # Encode as message (single record)
    return ndef.message_encoder([record])


def decode_ndef_for_display(ndef_bytes: bytes) -> str:
    """
    Decode NDEF bytes into a human-readable string for display.
    
    Args:
        ndef_bytes: Raw NDEF data bytes
        
    Returns:
        Human-readable string representation of the NDEF records
    """
    if not ndef_bytes or len(ndef_bytes) == 0:
        return "(empty)"
    
    try:
        records = decode_ndef_bytes(ndef_bytes)
        if not records:
            return "(empty)"
        
        display_lines = []
        for i, record in enumerate(records):
            display_lines.append(f"Record {i+1}:")
            
            if "record_type" in record:
                if record["record_type"] == NdefRecordType.TEXT:
                    display_lines.append(f"  Type: Text")
                    display_lines.append(f"  Text: {record.get('text', '')}")
                    display_lines.append(f"  Language: {record.get('language', 'N/A')}")
                
                elif record["record_type"] == NdefRecordType.URI:
                    display_lines.append(f"  Type: URI")
                    display_lines.append(f"  URI: {record.get('uri', '')}")
                
                elif record["record_type"] == NdefRecordType.ANDROID_APP:
                    display_lines.append(f"  Type: Android App Launch")
                    display_lines.append(f"  Package: {record.get('package_name', '')}")
            
            if "error" in record:
                display_lines.append(f"  Error: {record['error']}")
            elif "data_hex" in record and "record_type" not in record:
                display_lines.append(f"  Type: {record.get('type', 'Unknown')}")
                display_lines.append(f"  Data: {record['data_hex'][:64]}...")
        
        return "\n".join(display_lines)
    
    except Exception:
        # Fallback to hex display if decoding fails
        return ndef_bytes.hex().upper()
