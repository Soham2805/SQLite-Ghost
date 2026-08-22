import re
import datetime
from typing import Dict, Any, List

DEFAULT_MARKERS = ["deflator", "balloon", "needle", "espn", "leak", "reporter", "tom", "brady", "shoes", "psi"]

def match_markers(carved_text: str, custom_keywords: List[str] = None) -> List[Dict[str, Any]]:
    hits = []
    text_lower = carved_text.lower()
    keywords = custom_keywords if custom_keywords is not None else DEFAULT_MARKERS
    
    for kw in keywords:
        try:
            for match in re.finditer(r'\b' + kw + r'\b', text_lower):
                confidence = "LOW"
                if len(carved_text) < 50:
                    confidence = "HIGH"
                elif len(carved_text) < 150:
                    confidence = "MEDIUM"
                    
                hits.append({
                    'marker': kw,
                    'confidence': confidence,
                    'match_index': match.start()
                })
        except re.error:
            if kw in text_lower:
                hits.append({
                    'marker': kw,
                    'confidence': 'LOW',
                    'match_index': text_lower.find(kw)
                })
    return hits

def find_suspicious_hits(records: List[Dict[str, Any]], custom_keywords: List[str] = None) -> List[Dict[str, Any]]:
    suspicious_hits = []
    for rec in records:
        text_payload = ""
        for val in rec.get('data', []):
            if isinstance(val, (bytes, str)):
                try:
                    s = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else val
                    text_payload += s + " "
                except:
                    pass
        
        text_payload = text_payload.strip()
        if not text_payload:
            continue
            
        hits = match_markers(text_payload, custom_keywords)
        if hits:
            best_confidence = "LOW"
            matched_kws = set()
            for h in hits:
                matched_kws.add(h['marker'])
                if h['confidence'] == 'HIGH':
                    best_confidence = "HIGH"
                elif h['confidence'] == 'MEDIUM' and best_confidence == 'LOW':
                    best_confidence = "MEDIUM"
            
            timestamp = "Unknown"
            for val in rec.get('data', []):
                if isinstance(val, int) or isinstance(val, float):
                    if 946684800 <= val <= 1893456000:
                        try:
                            timestamp = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                            break
                        except: pass
                    elif 0 <= val <= 946684800:
                        try:
                            timestamp = datetime.datetime.fromtimestamp(val + 978307200, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                            break
                        except: pass
                    
            suspicious_hits.append({
                'source': rec.get('source', 'Unknown'),
                'offset': rec['offset'],
                'payload': text_payload,
                'markers': list(matched_kws),
                'confidence': best_confidence,
                'raw': rec['raw']
            })
    return suspicious_hits
