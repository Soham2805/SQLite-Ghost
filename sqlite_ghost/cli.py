import click
import os
from sqlite_ghost.core.btree_parser import parse_database_header, parse_page
from sqlite_ghost.core.wal_engine import parse_wal_header, read_wal_frames
from sqlite_ghost.core.carver import carve_slack_space, carve_freelist
from sqlite_ghost.analyzers.anomaly import calculate_anomaly_score
from sqlite_ghost.reporters.json_reporter import generate_json
from sqlite_ghost.reporters.html_reporter import generate_html

@click.group()
def cli():
    """SQLite-Ghost: Schema-agnostic forensic tool for SQLite databases."""
    pass

@cli.command()
@click.argument('db_path', type=click.Path(exists=True))
@click.option('--wal', type=click.Path(exists=True), help='Path to WAL file for differential analysis')
def parse(db_path, wal):
    """Parse standard extraction output to terminal."""
    click.echo(f"Parsing {db_path}...")
    with open(db_path, 'rb') as f:
        db_data = f.read()
        
    header = parse_database_header(db_data[:100])
    click.echo(f"DB Page Size: {header['page_size']}")
    
    page1 = parse_page(db_data[:header['page_size']], is_page_1=True)
    click.echo(f"Page 1 Type: {page1.page_type}, Cells: {page1.cell_count}")
    
    if wal:
        click.echo(f"Analyzing WAL: {wal}")
        with open(wal, 'rb') as f:
            wal_data = f.read()
        wal_header = parse_wal_header(wal_data[:32])
        frames = read_wal_frames(wal_data, wal_header['page_size'], wal_header['endian'])
        click.echo(f"Found {len(frames)} WAL frames.")

@cli.command()
@click.argument('db_path', type=click.Path(exists=True))
def carve(db_path):
    """Deep scan of unallocated slack space."""
    click.echo(f"Carving {db_path}...")
    with open(db_path, 'rb') as f:
        db_data = f.read()
        
    header = parse_database_header(db_data[:100])
    page_size = header['page_size']
    page1 = parse_page(db_data[:page_size], is_page_1=True)
    
    slack = carve_slack_space(db_data[:page_size], page1, is_page_1=True)
    click.echo(f"Found {len(slack)} records in Page 1 slack space.")
    
    freelist_carved = carve_freelist(db_data, header['freelist_trunk'], page_size)
    click.echo(f"Found {len(freelist_carved)} records in Freelist unallocated pages.")

@cli.command()
@click.argument('db_path', type=click.Path(exists=True))
@click.option('--html', type=click.Path(), required=True, help='Path for output HTML report')
def report(db_path, html):
    """Generates interactive single-page HTML report."""
    click.echo(f"Generating report for {db_path} -> {html}")
    
    with open(db_path, 'rb') as f:
        db_data = f.read()
        
    mtime = os.path.getmtime(db_path)
    header = parse_database_header(db_data[:100])
    page1 = parse_page(db_data[:header['page_size']], is_page_1=True)
    slack = carve_slack_space(db_data[:header['page_size']], page1, is_page_1=True)
    
    score, anomalies = calculate_anomaly_score(page1, header['page_size'], slack, file_mtime=mtime, is_page_1=True)
    
    report_data = {
        'db_path': db_path,
        'page_size': header['page_size'],
        'anomalies': anomalies,
        'anomaly_score': score,
        'slack_records': len(slack)
    }
    
    generate_html(report_data, html)
    click.echo("Report generated.")
