import asyncio
import logging
import sys
from pathlib import Path

import click
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.logging import RichHandler

from .config import Config
from .scanner.engine import ScanEngine, ScanResult
from .fingerprint.service_detector import ServiceDetector
from .fingerprint.ssl_analyzer import SSLAnalyzer
from .fingerprint.honeypot_detector import HoneypotDetector
from .enrichment.geoip import GeoIPEnricher
from .enrichment.dns_resolver import DNSEnricher
from .enrichment.cve_correlator import CVECorrelator
from .storage.database import Database

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
logger = logging.getLogger("omnisight")


@click.group()
@click.option("--config", "-c", default=None, help="Config file path")
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config.load(config)


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="21-23,25,53,80,110,443,993,3306,3389,5432,8080,8443")
@click.option("--protocol", default="tcp", type=click.Choice(["tcp", "udp"]))
@click.option("--banners/--no-banners", default=True)
@click.option("--enrich/--no-enrich", default=True)
@click.option("--save/--no-save", default=True)
@click.pass_context
def scan(ctx, target, ports, protocol, banners, enrich, save):
    """Scan target for open ports and services."""
    config = ctx.obj["config"]

    console.print(Panel.fit(
        f"[bold blue]OmniSight Scanner[/]\n"
        f"Target: [cyan]{target}[/]\n"
        f"Ports: [cyan]{ports}[/]\n"
        f"Protocol: [cyan]{protocol}[/]",
        border_style="blue",
    ))

    asyncio.run(_run_scan(config, target, ports, protocol, banners, enrich, save))


async def _run_scan(config, target, ports, protocol, banners, enrich, save):
    engine = ScanEngine(config)
    service_detector = ServiceDetector()
    geoip = GeoIPEnricher()
    dns_enricher = DNSEnricher()
    cve_correlator = CVECorrelator()
    db = None

    if save:
        db = Database()
        await db.connect()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        results = await engine.scan(
            targets=target,
            ports=ports,
            protocol=protocol,
            grab_banners=banners,
        )

        progress.update(task, description="Processing results...", completed=50, total=100)

        table = Table(title=f"Scan Results: {target}", show_lines=False, border_style="dim")
        table.add_column("IP", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("Proto", style="dim")
        table.add_column("Service", style="yellow")
        table.add_column("Product", style="white")
        table.add_column("Version", style="dim")
        table.add_column("Banner", style="dim", max_width=40)
        table.add_column("Country", style="blue")
        table.add_column("Latency", style="dim")

        for sr in results:
            svc = service_detector.detect(sr.banner, sr.port)

            country = ""
            if enrich:
                geo = geoip.lookup(sr.ip)
                country = geo.country_code

            table.add_row(
                sr.ip,
                str(sr.port),
                sr.protocol,
                svc.name or sr.service or "-",
                svc.product or "-",
                svc.version or "-",
                (sr.banner[:40].replace("\n", " ").replace("\r", "")) if sr.banner else "-",
                country or "-",
                f"{sr.latency_ms:.1f}ms",
            )

            if save and db:
                from .storage.models import ScanRecord
                record = ScanRecord(
                    ip=sr.ip, port=sr.port, protocol=sr.protocol,
                    state=sr.state, service=svc.name, product=svc.product,
                    version=svc.version, banner=sr.banner,
                    country_code=country, latency_ms=sr.latency_ms,
                )
                await db.save_result(record.to_dict())

        progress.update(task, description="Done!", completed=100, total=100)

    console.print(table)
    console.print(f"\n[bold green]{len(results)}[/] open ports found on [cyan]{target}[/]")

    if db:
        await db.close()


@cli.command()
@click.option("--host", "-h", default="0.0.0.0")
@click.option("--port", "-p", default=8000)
@click.option("--reload", is_flag=True)
@click.pass_context
def server(ctx, host, port, reload):
    """Start the OmniSight web server."""
    console.print(Panel.fit(
        f"[bold blue]OmniSight Server[/]\n"
        f"URL: [cyan]http://{host}:{port}[/]\n"
        f"API Docs: [cyan]http://{host}:{port}/docs[/]",
        border_style="blue",
    ))
    uvicorn.run(
        "omnisight.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.command()
@click.argument("query")
@click.option("--port", "-p", type=int, default=None)
@click.option("--service", "-s", default=None)
@click.option("--country", default=None)
@click.option("--limit", "-l", default=20)
@click.pass_context
def search(ctx, query, port, service, country, limit):
    """Search stored scan results."""
    asyncio.run(_search(query, port, service, country, limit))


async def _search(query, port, service, country, limit):
    db = Database()
    await db.connect()

    filters = {}
    if port:
        filters["port"] = port
    if service:
        filters["service"] = service
    if country:
        filters["country_code"] = country

    results = await db.search(query=query, filters=filters, size=limit)

    table = Table(title=f"Search: {query}", show_lines=False, border_style="dim")
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Product", style="white")
    table.add_column("Country", style="blue")
    table.add_column("Banner", style="dim", max_width=50)

    for r in results["results"]:
        table.add_row(
            r.get("ip", ""),
            str(r.get("port", "")),
            r.get("service", "-"),
            r.get("product", "-"),
            r.get("country_code", "-"),
            (r.get("banner", "")[:50].replace("\n", " ")) if r.get("banner") else "-",
        )

    console.print(table)
    console.print(f"\n[bold]{results['total']}[/] total results")
    await db.close()


@cli.command()
@click.pass_context
def stats(ctx):
    """Show scan statistics."""
    asyncio.run(_stats())


async def _stats():
    db = Database()
    await db.connect()
    stats = await db.get_stats()

    console.print(Panel.fit(
        f"[bold]Total Records:[/] [cyan]{stats.get('total_records', 0)}[/]\n"
        f"[bold]Unique Hosts:[/] [cyan]{stats.get('unique_hosts', 0)}[/]",
        title="OmniSight Statistics",
        border_style="blue",
    ))

    if stats.get("top_services"):
        table = Table(title="Top Services", border_style="dim")
        table.add_column("Service", style="yellow")
        table.add_column("Count", style="cyan")
        for svc, cnt in stats["top_services"].items():
            table.add_row(svc, str(cnt))
        console.print(table)

    if stats.get("top_ports"):
        table = Table(title="Top Ports", border_style="dim")
        table.add_column("Port", style="green")
        table.add_column("Count", style="cyan")
        for port, cnt in stats["top_ports"].items():
            table.add_row(str(port), str(cnt))
        console.print(table)

    await db.close()


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
