"""ClueScan command-line interface.

Subcommands import their backing modules lazily so `cluescan --help` works
before every subsystem is wired up.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import click

from cluescan import __version__
from cluescan.config import load_config


@click.group()
@click.version_option(__version__, prog_name="cluescan")
def main() -> None:
    """ClueScan — AI-native shift-left security review (local MCP + Review Center)."""


# -- init ---------------------------------------------------------------------

@main.command()
@click.option("--path", "path_", default="cluescan.yaml", show_default=True,
              help="Where to write the config file.")
def init(path_: str) -> None:
    """Create a starter cluescan.yaml next to the example and data dirs."""
    target = Path(path_).resolve()
    if target.exists():
        click.echo(f"{target} already exists; leaving it untouched.")
    else:
        example = Path(__file__).resolve().parents[2] / "cluescan.yaml.example"
        text = example.read_text(encoding="utf-8") if example.exists() else "# cluescan config\n"
        target.write_text(text, encoding="utf-8")
        click.echo(f"Wrote {target}")
    data_dir = Path(os.path.expanduser("~/.cluescan"))
    data_dir.mkdir(parents=True, exist_ok=True)
    click.echo(f"Ensured data dir: {data_dir}")


# -- serve-mcp ----------------------------------------------------------------

@main.command("serve-mcp")
@click.option("--config", "config_path", default=None, help="Path to cluescan.yaml")
def serve_mcp(config_path: str | None) -> None:
    """Run the local MCP Server (stdio) — what AI agents connect to."""
    from cluescan.mcp_server import run_stdio
    cfg = load_config(config_path)
    run_stdio(cfg)


# -- serve-web ----------------------------------------------------------------

@main.command("serve-web")
@click.option("--config", "config_path", default=None, help="Path to cluescan.yaml")
def serve_web(config_path: str | None) -> None:
    """Run the Review Center (FastAPI + single-page web UI)."""
    from cluescan.review_center import run_server
    cfg = load_config(config_path)
    run_server(cfg)


# -- review (one-shot, handy for CLI / testing) -------------------------------

@main.command("review")
@click.option("--repo", "repo", default=".", help="Repository path to review.")
@click.option("--base", "base_ref", default=None, help="Base git ref (default: stored baseline).")
@click.option("--head", "head_ref", default="HEAD", show_default=True)
@click.option("--config", "config_path", default=None, help="Path to cluescan.yaml")
def review(repo: str, base_ref: str | None, head_ref: str, config_path: str | None) -> None:
    """Run a single review over a repo's diff and print the summary."""
    import asyncio
    from cluescan.pipeline import run_review
    cfg = load_config(config_path)
    result = asyncio.run(run_review(cfg, repo_path=repo, base_ref=base_ref, head_ref=head_ref))
    click.echo(result.summary())
    if result.error:
        sys.exit(1)


# -- sync (drain outbox to center) --------------------------------------------

@main.command("sync")
@click.option("--config", "config_path", default=None, help="Path to cluescan.yaml")
def sync(config_path: str | None) -> None:
    """Drain the local outbox to the Review Center (offline-first retry)."""
    import asyncio
    from cluescan.sync import drain_once
    cfg = load_config(config_path)
    n = asyncio.run(drain_once(cfg))
    click.echo(f"Synced {n} outbox record(s).")


# -- register / install-skill (helpers) --------------------------------------

@main.command("register")
@click.argument("repo", default=".")
@click.option("--name", default=None, help="Project name (default: repo dir name).")
@click.option("--center", "center_url", default=None, help="Review Center URL.")
@click.option("--config", "config_path", default=None)
def register(repo: str, name: str | None, center_url: str | None, config_path: str | None) -> None:
    """Register a repo as a project with the Review Center."""
    import asyncio
    from cluescan.sync import register_project
    cfg = load_config(config_path)
    res = asyncio.run(register_project(cfg, repo_path=repo, name=name, center_url=center_url))
    click.echo(f"Registered project '{res['project']}' (token saved locally).")


@main.command("install-skill")
@click.option("--dest", default=None, help="Target skills directory (default: ~/.claude/skills).")
def install_skill(dest: str | None) -> None:
    """Copy the security-review skill into a skills directory."""
    src = Path(__file__).resolve().parents[2] / "skills" / "security-review"
    target_dir = Path(dest).expanduser() if dest else Path("~/.claude/skills").expanduser()
    if not src.exists():
        click.echo(f"Skill source not found: {src}", err=True)
        sys.exit(1)
    target = target_dir / "security-review"
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, target)
    click.echo(f"Installed skill to {target}")


if __name__ == "__main__":
    main()
