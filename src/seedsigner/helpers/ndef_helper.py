"""
NDEF (NFC Data Exchange Format) helper module for encoding and decoding NDEF records.
Provides utilities for working with Text, URI, and Android App Launch NDEF record types.
"""

import ndef
from typing import List, Dict, Any


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
            
            # Handle TextRecord
            if isinstance(record, ndef.TextRecord):
                try:
                    record_info.update({
                        "record_type": NdefRecordType.TEXT,
                        "text": record.text or "",
                        "language": record.language or "en",
                    })
                except Exception as e:
                    record_info.update({
                        "record_type": NdefRecordType.TEXT,
                        "error": f"Failed to decode text: {str(e)[:50]}",
                    })
            
            # Handle UriRecord
            elif isinstance(record, ndef.UriRecord):
                try:
                    record_info.update({
                        "record_type": NdefRecordType.URI,
                        "uri": record.uri or "",
                    })
                except Exception as e:
                    record_info.update({
                        "record_type": NdefRecordType.URI,
                        "error": f"Failed to decode URI: {str(e)[:50]}",
                    })
            
            else:
                # Generic record type - try to get attributes
                try:
                    # Check if it's an external type Android app record
                    if hasattr(record, 'type') and record.type == 'android.com:pkg':
                        try:
                            package_name = record.data.decode('utf-8')
                            record_info.update({
                                "record_type": NdefRecordType.ANDROID_APP,
                                "package_name": package_name,
                            })
                        except Exception:
                            record_info["data_hex"] = record.data.hex().upper()
                    else:
                        record_info["data_hex"] = record.data.hex().upper()
                except Exception:
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
    return b''.join(ndef.message_encoder([record]))


def create_uri_record(uri: str) -> bytes:
    """
    Create an NDEF URI record.
    
    Args:
        uri: URI to encode (e.g., "https://example.com")
        
    Returns:
        NDEF-encoded bytes for this record
    """
    # Create URI record using ndeflib (uses 'iri' parameter)
    record = ndef.UriRecord(iri=uri)
    # Encode as message (single record)
    return b''.join(ndef.message_encoder([record]))


def create_android_app_record(package_name: str) -> bytes:
    """
    Create an NDEF record to launch an Android application using Android App Launch Record format.
    
    This creates a custom external NDEF record (TNF=5) with type "android.com:pkg"
    which Android devices can use to launch the specified package.
    
    Args:
        package_name: Android package name (e.g., "org.satochip.seedkeeper")
        
    Returns:
        NDEF-encoded bytes for this record
    """
    # Manual construction of Android App Launch record (external type, TNF=5)
    # Format: Header | Type Length | Payload Length | Type | Payload
    # Header byte for external type with MB=1, ME=1, SR=1: 0xD5
    header = 0xD5
    app_type = b"android.com:pkg"
    payload = package_name.encode('utf-8')
    
    record_bytes = (
        bytes([header, len(app_type), len(payload)]) +
        app_type +
        payload
    )
    
    return record_bytes


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
        # Try to decode as standard NDEF
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

