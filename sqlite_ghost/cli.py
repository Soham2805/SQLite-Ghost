import click
import os
import tempfile
import shutil
import datetime
import zipfile
from sqlite_ghost.core.btree_parser import parse_database_header, parse_page
from sqlite_ghost.core.wal_engine import parse_wal_header, read_wal_frames
from sqlite_ghost.core.carver import carve_slack_space, carve_freelist
from sqlite_ghost.analyzers.anomaly import calculate_anomaly_score
from sqlite_ghost.reporters.json_reporter import generate_json
from sqlite_ghost.reporters.html_reporter import generate_html
from sqlite_ghost.utils.secure_handler import secure_copy, generate_hashes, generate_hex_dump
from sqlite_ghost.analyzers.markers import find_suspicious_hits

def print_progress_bar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 50, fill = '=', printEnd = "\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    click.echo(f'\r{prefix} |{bar}| {percent}% {suffix}', nl=False)
    if iteration == total: 
        click.echo()

@click.group()
def cli():
    """SQLite-Ghost: Schema-agnostic forensic tool for SQLite databases."""
    pass

@cli.command()
@click.argument('db_path', type=click.Path(exists=True))
@click.option('--wal', type=click.Path(exists=False), help='Path to WAL file for differential analysis')
def parse(db_path, wal):
    click.echo(f"Parsing {db_path}...")
    secure_db = secure_copy(db_path)
    with open(secure_db, 'rb') as f:
        db_data = f.read()
        
    header = parse_database_header(db_data[:100])
    click.echo(f"DB Page Size: {header['page_size']}")
    
    page1 = parse_page(db_data[:header['page_size']], is_page_1=True)
    click.echo(f"Page 1 Type: {page1.page_type}, Cells: {page1.cell_count}")
    
    if wal and os.path.exists(wal):
        secure_wal = secure_copy(wal)
        click.echo(f"Analyzing WAL: {wal}")
        with open(secure_wal, 'rb') as f:
            wal_data = f.read()
        wal_header = parse_wal_header(wal_data[:32])
        frames = read_wal_frames(wal_data, wal_header['page_size'], wal_header['endian'])
        click.echo(f"Found {len(frames)} WAL frames.")

@cli.command()
@click.argument('db_path', type=click.Path(exists=True))
def carve(db_path):
    click.echo(f"Carving {db_path}...")
    secure_db = secure_copy(db_path)
    with open(secure_db, 'rb') as f:
        db_data = f.read()
        
    header = parse_database_header(db_data[:100])
    page_size = header['page_size']
    page1 = parse_page(db_data[:page_size], is_page_1=True)
    
    slack = carve_slack_space(db_data[:page_size], page1, is_page_1=True)
    click.echo(f"Found {len(slack)} records in Page 1 slack space.")

@cli.command()
@click.argument('db_path', type=click.Path(exists=True))
@click.option('--html', type=click.Path(), required=False, help='Path for output HTML report')
@click.option('--json-out', type=click.Path(), help='Path for output JSON export')
@click.option('--package', is_flag=True, help='Zip up evidence and reports into a sealed archive')
@click.option('--keywords', type=click.Path(exists=True), help='Path to custom keyword dict (.txt)')
def report(db_path, html, json_out, package, keywords):
    """Generates interactive single-page HTML report and automated exports."""
    if not html and not json_out:
        click.echo("Error: You must specify at least one output format (--html or --json-out).", err=True)
        return
    click.echo(f"Initializing forensic pipeline for {db_path}...")
    
    custom_kws = None
    if keywords:
        with open(keywords, 'r', encoding='utf-8') as f:
            custom_kws = [line.strip().lower() for line in f if line.strip()]
        click.echo(f"Loaded {len(custom_kws)} custom regex/keywords.")

    acquisition_metadata = {}
    secure_db = secure_copy(db_path)
    acquisition_metadata['db_original'] = db_path
    acquisition_metadata['db_hashes'] = generate_hashes(db_path)
    
    wal_path = db_path + "-wal"
    secure_wal = None
    if os.path.exists(wal_path):
        secure_wal = secure_copy(wal_path)
        acquisition_metadata['wal_original'] = wal_path
        acquisition_metadata['wal_hashes'] = generate_hashes(wal_path)
    
    with open(secure_db, 'rb') as f:
        db_data = f.read()
        
    mtime = os.path.getmtime(db_path)
    header = parse_database_header(db_data[:100])
    page_size = header['page_size']
    num_pages = len(db_data) // page_size
    
    all_anomalies = []
    total_slack = 0
    max_severity_weight = 0
    weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    all_carved_records = []
    
    click.echo(f"Carving B-Tree Leaf Pages (Total: {num_pages})")
    print_progress_bar(0, num_pages, prefix='Progress:', suffix='Complete')
    
    for i in range(num_pages):
        is_p1 = (i == 0)
        page_data = db_data[i*page_size : (i+1)*page_size]
        try:
            page = parse_page(page_data, is_page_1=is_p1)
            slack = carve_slack_space(page_data, page, is_page_1=is_p1)
            total_slack += len(slack)
            
            for rec in slack:
                rec['source'] = os.path.basename(db_path) + f" (Pg {i+1} Slack)"
            all_carved_records.extend(slack)
            for cell in page.cells:
                c = cell.copy()
                c['source'] = os.path.basename(db_path) + f" (Pg {i+1} Active)"
                c['offset'] = f"RowID {c.get('row_id', '?')}"
                c['raw'] = c.get('raw_payload', b'')
                all_carved_records.append(c)
            
            _, page_anoms = calculate_anomaly_score(page, page_size, slack, file_mtime=mtime, is_page_1=is_p1)
            
            for anom in page_anoms:
                anom['desc'] = f"[Page {i+1}] {anom['desc']}"
                all_anomalies.append(anom)
                max_severity_weight = max(max_severity_weight, weights.get(anom['severity'], 0))
                
        except Exception:
            pass 
        print_progress_bar(i + 1, num_pages, prefix='Progress:', suffix='Complete')
            
    if secure_wal:
        try:
            with open(secure_wal, 'rb') as f:
                wal_data = f.read()
            wal_header = parse_wal_header(wal_data[:32])
            frames = read_wal_frames(wal_data, wal_header['page_size'], wal_header['endian'])
            
            click.echo(f"Carving WAL Segments (Total: {len(frames)})")
            print_progress_bar(0, len(frames), prefix='Progress:', suffix='Complete')
            
            for idx, frame in enumerate(frames):
                is_p1 = (frame.page_number == 1)
                try:
                    page = parse_page(frame.data, is_page_1=is_p1)
                    slack = carve_slack_space(frame.data, page, is_page_1=is_p1)
                    total_slack += len(slack)
                    
                    for rec in slack:
                        rec['source'] = os.path.basename(wal_path) + f" (Frame {idx+1} Slack)"
                    all_carved_records.extend(slack)
                    for cell in page.cells:
                        c = cell.copy()
                        c['source'] = os.path.basename(wal_path) + f" (Frame {idx+1} Active)"
                        c['offset'] = f"RowID {c.get('row_id', '?')}"
                        c['raw'] = c.get('raw_payload', b'')
                        all_carved_records.append(c)
                    
                    _, page_anoms = calculate_anomaly_score(page, wal_header['page_size'], slack, file_mtime=mtime, is_page_1=is_p1)
                    for anom in page_anoms:
                        anom['desc'] = f"[WAL Frame {idx+1}] {anom['desc']}"
                        all_anomalies.append(anom)
                        max_severity_weight = max(max_severity_weight, weights.get(anom['severity'], 0))
                except:
                    pass
                print_progress_bar(idx + 1, len(frames), prefix='Progress:', suffix='Complete')
        except Exception as e:
            click.echo(f"Warning: WAL parsing failed - {str(e)}")

    suspicious_hits = find_suspicious_hits(all_carved_records, custom_keywords=custom_kws)
    
    threat_level = "CLEAN"
    if max_severity_weight == 4:
        threat_level = "CRITICAL"
    elif max_severity_weight == 3:
        threat_level = "HIGH"
    elif max_severity_weight == 2:
        threat_level = "MEDIUM"
    elif max_severity_weight == 1:
        threat_level = "LOW"
        
    for hit in suspicious_hits:
        hit['hex_dump'] = generate_hex_dump(hit['raw'])
    
    report_data = {
        'db_path': db_path,
        'page_size': page_size,
        'anomalies': all_anomalies,
        'anomaly_score': threat_level,
        'slack_records': total_slack,
        'suspicious_hits': suspicious_hits,
        'acquisition': acquisition_metadata
    }
    
    if html:
        generate_html(report_data, html)
        click.echo(f"HTML Report generated at {html}.")
    
    if json_out:
        generate_json(report_data, json_out)
        click.echo(f"JSON Export generated at {json_out}.")
        
    if package:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        zip_path = f"sqlite_ghost_evidence_{timestamp}.zip"
        click.echo(f"Packaging evidence into {zip_path}...")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(secure_db, arcname=os.path.basename(db_path))
            if secure_wal:
                zipf.write(secure_wal, arcname=os.path.basename(wal_path))
            if html:
                zipf.write(html, arcname=os.path.basename(html))
            if json_out:
                zipf.write(json_out, arcname=os.path.basename(json_out))
        
        final_hash = generate_hashes(zip_path)['sha256']
        click.echo(f"Package SHA-256: {final_hash}")
    
    if html:
        import webbrowser
        webbrowser.open('file://' + os.path.abspath(html))

if __name__ == '__main__':
    cli()
