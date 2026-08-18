from typing import Dict, Any, List, Tuple
from sqlite_ghost.core.btree_parser import BTreePage

def calculate_anomaly_score(
    page: BTreePage, 
    page_size: int,
    slack_carved: List[Dict[str, Any]], 
    file_mtime: float = 0.0,
    is_page_1: bool = False
) -> Tuple[str, List[Dict[str, str]]]:
    anomalies = []
    max_severity_weight = 0
    
    weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    
    # 1. Corrupted Pointer Offsets
    header_offset = 100 if is_page_1 else 0
    pointer_end = header_offset + (12 if page.page_type in (0x05, 0x02) else 8) + (page.cell_count * 2)
    
    for ptr in page.cell_pointers:
        if ptr < header_offset + 8:
            anomalies.append({'severity': 'HIGH', 'desc': f"Corrupted Pointer: Points into header space ({ptr})"})
            max_severity_weight = max(max_severity_weight, weights['HIGH'])
        elif ptr >= page_size:
            anomalies.append({'severity': 'HIGH', 'desc': f"Corrupted Pointer: Out of bounds ({ptr})"})
            max_severity_weight = max(max_severity_weight, weights['HIGH'])
        elif ptr < pointer_end:
            anomalies.append({'severity': 'HIGH', 'desc': f"Corrupted Pointer: Points into pointer array space ({ptr})"})
            max_severity_weight = max(max_severity_weight, weights['HIGH'])
            
    # 2. Structural Overlap
    if pointer_end > page.cell_content_start and page.cell_content_start != 65536:
        anomalies.append({'severity': 'CRITICAL', 'desc': f"Structural Anomaly: Cell pointer array overlaps with cell content area."})
        max_severity_weight = max(max_severity_weight, weights['CRITICAL'])
            
    # 3. Orphaned Payload Cells
    if slack_carved:
        anomalies.append({'severity': 'LOW', 'desc': f"Orphaned Payloads: Found {len(slack_carved)} valid records hidden in unallocated slack space"})
        max_severity_weight = max(max_severity_weight, weights['LOW'])
        
    # 4. Out-of-Order RowIDs (Tampering detection)
    last_row_id = None
    for cell in page.cells:
        row_id = cell.get('row_id')
        if row_id is not None:
            if last_row_id is not None and row_id <= last_row_id:
                anomalies.append({'severity': 'CRITICAL', 'desc': f"RowID Tampering Anomaly: Cell {row_id} appears after {last_row_id} (not strictly increasing)"})
                max_severity_weight = max(max_severity_weight, weights['CRITICAL'])
            last_row_id = row_id
        
    # 5. Timestamp Contradictions
    for cell in page.cells:
        for val in cell['data']:
            if isinstance(val, int):
                # Rough check for Unix timestamps between 2000 and 2030
                if 946684800 <= val <= 1893456000:
                    if file_mtime > 0 and val > file_mtime + 3600:
                        anomalies.append({'severity': 'CRITICAL', 'desc': f"Timestamp Contradiction: Record timestamp ({val}) is in the future compared to file system mtime ({file_mtime})"})
                        max_severity_weight = max(max_severity_weight, weights['CRITICAL'])
                        
    # Determine Threat Level
    threat_level = "CLEAN"
    if max_severity_weight == 4:
        threat_level = "CRITICAL"
    elif max_severity_weight == 3:
        threat_level = "HIGH"
    elif max_severity_weight == 2:
        threat_level = "MEDIUM"
    elif max_severity_weight == 1:
        threat_level = "LOW"
                        
    return threat_level, anomalies
