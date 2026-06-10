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


def save_ndef_to_seedkeeper(connector, ndef_bytes: bytes, label: str = "NDEF Record") -> tuple:
    """
    Save NDEF bytes to SeedKeeper as a secret with NDEF_ prefix.
    
    Args:
        connector: CardConnector instance for SeedKeeper
        ndef_bytes: Raw NDEF data bytes to save
        label: Optional label for the secret (will be prefixed with "NDEF_")
        
    Returns:
        Tuple of (secret_id, fingerprint) returned by seedkeeper_import_secret
        
    Raises:
        Exception: If the save operation fails
    """
    if not ndef_bytes or len(ndef_bytes) == 0:
        raise ValueError("NDEF bytes cannot be empty")
    
    # Create label with NDEF_ prefix
    secret_label = f"NDEF_{label}"
    
    # Convert NDEF bytes to secret_list format (with length prefix)
    # For data < 256 bytes, use single byte length
    if len(ndef_bytes) <= 255:
        secret_list = [len(ndef_bytes)] + list(ndef_bytes)
    else:
        # For data >= 256 bytes, use 2-byte big-endian length
        secret_list = list(len(ndef_bytes).to_bytes(2, "big")) + list(ndef_bytes)
    
    # Create header using generic "Password" type (suitable for binary data)
    header = connector.make_header("Password", "Plaintext export allowed", secret_label)
    
    # Create secret dictionary
    secret_dic = {
        "header": header,
        "secret_list": secret_list
    }
    
    # Import secret to SeedKeeper
    (sid, fingerprint) = connector.seedkeeper_import_secret(secret_dic)
    
    return (sid, fingerprint)


def load_ndef_from_seedkeeper(connector, secret_id: int) -> bytes:
    """
    Load NDEF bytes from SeedKeeper secret.
    
    Args:
        connector: CardConnector instance for SeedKeeper
        secret_id: The ID of the secret to load
        
    Returns:
        Raw NDEF data bytes
        
    Raises:
        Exception: If the load operation fails
    """
    # Export secret from SeedKeeper
    secret_dict = connector.seedkeeper_export_secret(secret_id, None)
    
    if not secret_dict or "secret_list" not in secret_dict:
        raise ValueError("Invalid secret format or secret not found")
    
    secret_list = secret_dict["secret_list"]
    
    if len(secret_list) < 2:
        raise ValueError("Invalid NDEF secret: list too short")
    
    # Check if it's a 2-byte length (first byte would be 0, second byte is actual length)
    # or a 1-byte length (first byte is the length)
    length_byte = secret_list[0]
    
    if length_byte == 0 and len(secret_list) > 2:
        # 2-byte length format
        length = (secret_list[0] << 8) | secret_list[1]
        ndef_bytes = bytes(secret_list[2:2+length])
    else:
        # 1-byte length format
        length = length_byte
        ndef_bytes = bytes(secret_list[1:1+length])
    
    return ndef_bytes

