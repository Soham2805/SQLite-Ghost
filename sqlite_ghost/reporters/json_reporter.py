import json

def generate_json(data: dict, output_path: str):
    def serialize_hit(hit):
        clean_hit = hit.copy()
        if 'raw' in clean_hit:
            del clean_hit['raw']
        return clean_hit
    
    clean_data = data.copy()
    if 'suspicious_hits' in clean_data:
        clean_data['suspicious_hits'] = [serialize_hit(h) for h in clean_data['suspicious_hits']]
        
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(clean_data, f, indent=4)
