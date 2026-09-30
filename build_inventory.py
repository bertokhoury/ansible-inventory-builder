#!/usr/bin/env python3
"""Ask for hosts, groups, and connection settings, then write an Ansible inventory.

The questions follow the Ansible inventory guide:
https://docs.ansible.com/projects/ansible/latest/inventory_guide/index.html

YAML is the default. INI is available as well. Passwords can be left for
--ask-pass / --ask-become-pass, or written into group_vars and host_vars and
encrypted with ansible-vault. ansible_group_priority stays in the inventory
file, because Ansible does not honor it from group_vars.
"""

from __future__ import annotations

import argparse
import ast
import getpass
import json
import keyword
import os
import re
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path


DOCS = "https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_inventory.html"
CONNECTION_DOCS = "https://docs.ansible.com/projects/ansible/latest/inventory_guide/connection_details.html"

JINJA_KEYWORDS = frozenset({"true", "false", "none", "True", "False", "None", "not"})
IMPLICIT_GROUPS = frozenset({"all", "ungrouped"})
PLAY_RESERVED = frozenset(
    {
        "action",
        "always",
        "any_errors_fatal",
        "args",
        "async",
        "async_val",
        "become",
        "become_exe",
        "become_flags",
        "become_method",
        "become_user",
        "block",
        "changed_when",
        "check_mode",
        "collections",
        "connection",
        "cycler",
        "debugger",
        "delay",
        "delegate_facts",
        "delegate_to",
        "dict",
        "diff",
        "environment",
        "fact_path",
        "failed_when",
        "force_handlers",
        "gather_facts",
        "gather_timeout",
        "handlers",
        "hosts",
        "ignore_errors",
        "ignore_unreachable",
        "joiner",
        "lipsum",
        "local_action",
        "lookup",
        "loop",
        "loop_control",
        "max_fail_percentage",
        "module_defaults",
        "name",
        "namespace",
        "no_log",
        "notify",
        "now",
        "omit",
        "order",
        "poll",
        "port",
        "post_tasks",
        "pre_tasks",
        "q",
        "query",
        "range",
        "register",
        "remote_user",
        "rescue",
        "retries",
        "roles",
        "run_once",
        "serial",
        "strategy",
        "tags",
        "tasks",
        "throttle",
        "timeout",
        "undef",
        "until",
        "validate_argspec",
        "vars",
        "vars_files",
        "vars_prompt",
        "when",
        "with_",
    }
)
MAGIC_VARIABLES = frozenset(
    {
        "ansible_check_mode",
        "ansible_collection_name",
        "ansible_config_file",
        "ansible_dependent_role_names",
        "ansible_diff_mode",
        "ansible_facts",
        "ansible_forks",
        "ansible_index_var",
        "ansible_inventory_sources",
        "ansible_limit",
        "ansible_loop",
        "ansible_loop_var",
        "ansible_parent_role_names",
        "ansible_play_batch",
        "ansible_play_hosts",
        "ansible_play_name",
        "ansible_play_role_names",
        "ansible_role_name",
        "ansible_role_names",
        "ansible_verbosity",
        "ansible_version",
        "group_names",
        "groups",
        "hostvars",
        "inventory_dir",
        "inventory_file",
        "inventory_hostname",
        "inventory_hostname_short",
        "playbook_dir",
        "role_name",
        "role_names",
        "role_path",
    }
)
BECOME_METHODS = ("sudo", "su", "pbrun", "pfexec", "doas", "dzdo", "ksu", "runas", "machinectl")
NETWORK_OS = (
    "cisco.ios.ios",
    "cisco.nxos.nxos",
    "cisco.iosxr.iosxr",
    "arista.eos.eos",
    "junipernetworks.junos.junos",
    "vyos.vyos.vyos",
)
VAR_ORDER = (
    "ansible_connection",
    "ansible_host",
    "ansible_port",
    "ansible_user",
    "ansible_password",
    "ansible_ssh_private_key_file",
    "ansible_ssh_common_args",
    "ansible_ssh_extra_args",
    "ansible_sftp_extra_args",
    "ansible_scp_extra_args",
    "ansible_ssh_pipelining",
    "ansible_ssh_executable",
    "ansible_become",
    "ansible_become_method",
    "ansible_become_user",
    "ansible_become_password",
    "ansible_become_exe",
    "ansible_become_flags",
    "ansible_shell_type",
    "ansible_shell_executable",
    "ansible_python_interpreter",
    "ansible_network_os",
    "ansible_winrm_scheme",
    "ansible_winrm_transport",
    "ansible_winrm_server_cert_validation",
    "ansible_winrm_connection_timeout",
    "ansible_winrm_kinit_mode",
    "ansible_winrm_kinit_cmd",
    "ansible_winrm_path",
    "ansible_group_priority",
)
SECRET_KEY = re.compile(
    r"(^|_)(password|passwd|pass|secret|token|credential)s?($|_)",
    re.IGNORECASE,
)
SAFE_YAML_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
IDENT_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Cancelled(Exception):
    """The user stopped the questionnaire before any files were written."""


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text with LF newlines. Path.write_text(newline=) needs Python 3.10+."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def say(text: str) -> None:
    print(textwrap.fill(text, width=78, break_long_words=False, break_on_hyphens=False))


def section(title: str) -> None:
    print()
    print(title)
    print("-" * min(len(title), 72))


def read_line(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError as exc:
        print()
        raise Cancelled("End of input.") from exc
    except KeyboardInterrupt as exc:
        print()
        raise Cancelled("Cancelled.") from exc


def prompt(message: str, default: str | None = None, *, allow_empty: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        raw = read_line(f"{message}{suffix}: ").strip()
        if raw == "" and default is not None:
            return default
        if raw == "" and allow_empty:
            return ""
        if raw:
            return raw
        print("  Enter a value, or press Ctrl+C to cancel.")


def prompt_optional(message: str) -> str:
    return prompt(message, allow_empty=True)


def prompt_yes_no(message: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = read_line(f"{message} [{hint}]: ").strip().lower()
        if raw == "":
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("  Enter y or n.")


def prompt_choice(title: str, labels: list[str], default: int | None = None) -> int:
    print(title)
    for index, label in enumerate(labels, start=1):
        print(f"  {index}) {label}")
    while True:
        hint = f" [{default}]" if default else ""
        raw = read_line(f"Choice{hint}: ").strip().lower()
        if raw == "" and default is not None:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(labels):
            return int(raw)
        print(f"  Enter a number from 1 to {len(labels)}.")


def prompt_secret(label: str) -> str:
    """Read a secret twice. Empty input skips it."""
    while True:
        if sys.stdin.isatty():
            first = getpass.getpass(f"{label}: ")
            if first == "":
                return ""
            second = getpass.getpass(f"Confirm {label}: ")
        else:
            first = read_line(f"{label}: ")
            if first.strip() == "":
                return ""
            second = read_line(f"Confirm {label}: ")
            first = first.rstrip("\n")
            second = second.rstrip("\n")
        if "\n" in first or "\r" in first:
            print("  Passwords cannot contain line breaks.")
            continue
        if first == second:
            return first
        print("  Those entries did not match.")


def split_names(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def is_secret_key(key: str) -> bool:
    if key in {"ansible_ssh_private_key_file", "ansible_ssh_pass"}:
        return key == "ansible_ssh_pass"
    return SECRET_KEY.search(key) is not None


def is_valid_identifier(name: str) -> bool:
    return bool(name) and name.isascii() and name.isidentifier() and name not in JINJA_KEYWORDS and not keyword.iskeyword(name)


def variable_name_error(name: str) -> str | None:
    if name in MAGIC_VARIABLES or name in PLAY_RESERVED or name in JINJA_KEYWORDS or keyword.iskeyword(name):
        return f"{name} is reserved by Ansible. Connection settings use the ansible_ prefix, for example ansible_port or ansible_user."
    if not is_valid_identifier(name):
        return "Variable names start with a letter or underscore and contain only letters, numbers, and underscores."
    if "inventory_hostname" in name:
        return "inventory_hostname is set by Ansible. Do not define it."
    return None


def group_name_error(name: str) -> str | None:
    if name in IMPLICIT_GROUPS:
        return "all and ungrouped already exist. Ansible adds every host to all, and hosts with no other group to ungrouped."
    if name in PLAY_RESERVED or name in JINJA_KEYWORDS or keyword.iskeyword(name):
        return "Group names follow variable-name rules, and Ansible reserves this word."
    if not is_valid_identifier(name):
        return "Use letters, numbers, and underscores only. Do not start with a number or use a hyphen."
    return None


def coerce_scalar(raw: str) -> object:
    lowered = raw.lower()
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    if re.fullmatch(r"-?(0|[1-9]\d*)", raw):
        return int(raw)
    return raw


def expand_hostname_range(line: str) -> list[str]:
    """Expand one Ansible host pattern. Matches ansible.plugins.inventory.expand_hostname_range."""
    if "[" not in line:
        return [line]
    try:
        head, nrange, tail = line.replace("[", "|", 1).replace("]", "|", 1).split("|")
    except ValueError as exc:
        raise ValueError("Host range must look like name[start:end] or name[start:end:step].") from exc
    bounds = nrange.split(":")
    if len(bounds) not in {2, 3}:
        raise ValueError("Host range must be begin:end or begin:end:step.")
    beg, end = bounds[0], bounds[1]
    step = bounds[2] if len(bounds) == 3 else "1"
    if not beg:
        beg = "0"
    if not end:
        raise ValueError("Host range must specify an end value.")
    try:
        step_n = int(step)
    except ValueError as exc:
        raise ValueError("Host range step must be an integer.") from exc
    if step_n < 1:
        raise ValueError("Host range step must be 1 or greater.")
    if beg[0] == "0" and len(beg) > 1:
        if len(beg) != len(end):
            raise ValueError("Zero-padded ranges need begin and end of equal length, such as [01:50].")

        def fill(value: object) -> str:
            return str(value).zfill(len(beg))

    else:
        fill = str
    try:
        i_beg = string.ascii_letters.index(beg)
        i_end = string.ascii_letters.index(end)
        if i_beg > i_end:
            raise ValueError("Letter ranges must have begin before end, such as [a:f].")
        sequence: list[object] = list(string.ascii_letters[i_beg : i_end + 1 : step_n])
    except ValueError as exc:
        if "Letter ranges" in str(exc):
            raise
        try:
            start_n = int(beg)
            end_n = int(end)
        except ValueError as inner:
            raise ValueError("Host range bounds must both be numbers or both be letters.") from inner
        if start_n > end_n:
            raise ValueError("Numeric ranges must have begin less than or equal to end.")
        sequence = list(range(start_n, end_n + 1, step_n))
    if not sequence:
        raise ValueError("That range expands to no hosts.")
    hosts: list[str] = []
    for item in sequence:
        hostname = "".join((head, fill(item), tail))
        if "[" in hostname:
            hosts.extend(expand_hostname_range(hostname))
        else:
            hosts.append(hostname)
    return hosts


def split_host_port(token: str) -> tuple[str, int | None]:
    depth = 0
    colons = 0
    colon_at = -1
    for index, char in enumerate(token):
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        elif char == ":" and depth == 0:
            colons += 1
            colon_at = index
    if colons == 1 and token[colon_at + 1 :].isdigit() and colon_at > 0:
        return token[:colon_at], int(token[colon_at + 1 :])
    return token, None


def host_name_error(name: str) -> str | None:
    if not name or any(char.isspace() for char in name):
        return "Host names cannot be blank or contain whitespace."
    if name in IMPLICIT_GROUPS or name.startswith("[") or name.endswith(":"):
        return f"{name} is not a valid inventory hostname."
    if "[" in name:
        try:
            expand_hostname_range(name)
        except ValueError as exc:
            return str(exc)
    return None


def parse_host_line(line: str, *, expand_ranges: bool) -> list[tuple[str, dict[str, object]]]:
    text = line.strip()
    if not text or text.startswith("#"):
        return []
    variables: dict[str, object] = {}
    if " " not in text and text.count("=") == 1:
        left, right = text.split("=", 1)
        if left.startswith("ansible_"):
            raise ValueError("Start the line with the inventory hostname. Example: web1 ansible_host=192.0.2.10")
        name, port = split_host_port(left)
        if port is not None:
            variables["ansible_port"] = port
        variables["ansible_host"] = right
        return _finish_host_specs(name, variables, expand_ranges=expand_ranges)
    try:
        tokens = shlex.split(text, comments=True, posix=True)
    except ValueError as exc:
        raise ValueError(f"Could not parse that host line: {exc}") from exc
    if not tokens:
        return []
    name, port = split_host_port(tokens[0])
    if port is not None:
        variables["ansible_port"] = port
    for token in tokens[1:]:
        if "=" not in token:
            raise ValueError(f"Expected key=value after the hostname, got {token!r}.")
        key, raw_value = token.split("=", 1)
        error = variable_name_error(key)
        if error and not key.startswith("ansible_"):
            raise ValueError(error)
        if key == "ansible_host" and "inventory_hostname" in raw_value and "inventory_hostname_short" not in raw_value:
            raise ValueError("Do not set ansible_host from inventory_hostname. If you need a short name, use inventory_hostname_short.")
        variables[key] = raw_value if is_secret_key(key) else coerce_scalar(raw_value)
    return _finish_host_specs(name, variables, expand_ranges=expand_ranges)


def _finish_host_specs(name: str, variables: dict[str, object], *, expand_ranges: bool) -> list[tuple[str, dict[str, object]]]:
    error = host_name_error(name)
    if error:
        raise ValueError(error)
    address = variables.get("ansible_host")
    address_text = str(address) if address is not None else ""
    name_is_range = "[" in name
    address_is_range = "[" in address_text
    if name_is_range and address_is_range:
        names = expand_hostname_range(name)
        addresses = expand_hostname_range(address_text)
        if len(names) != len(addresses):
            raise ValueError(
                f"{name} expands to {len(names)} hosts, but {address_text} expands to {len(addresses)} addresses."
            )
        specs = []
        for hostname, host_address in zip(names, addresses):
            host_vars = dict(variables)
            host_vars["ansible_host"] = host_address
            specs.append((hostname, host_vars))
        return specs
    if name_is_range and address_text and not address_is_range:
        raise ValueError("A range of hosts cannot share one ansible_host. Give an address range of the same length, or omit ansible_host.")
    if name_is_range and expand_ranges:
        return [(hostname, dict(variables)) for hostname in expand_hostname_range(name)]
    if address_text == name:
        variables.pop("ansible_host", None)
    return [(name, variables)]


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    text = str(value)
    if text == "":
        return '""'
    # Strings that look like numbers, booleans, or null stay quoted so YAML
    # does not change their type. Secret values such as a numeric password
    # are strings on purpose.
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        return text
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_./@+-]*", text) and text.lower() not in {
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "null",
        "y",
        "n",
        "~",
    }:
        return text
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def yaml_key(key: str) -> str:
    if IDENT_KEY.fullmatch(key) or SAFE_YAML_KEY.fullmatch(key):
        return key
    return yaml_scalar(key)


def order_items(data: dict[str, object]) -> list[tuple[str, object]]:
    rank = {name: index for index, name in enumerate(VAR_ORDER)}
    return sorted(data.items(), key=lambda item: (rank.get(item[0], len(VAR_ORDER)), item[0]))


def shown_value(key: str, value: object, *, mask: bool) -> object:
    if mask and is_secret_key(key):
        return "********"
    return value


def ini_host_assignment(key: str, value: object) -> str:
    """Format one host-line assignment. Ansible shlex-splits the line, then literal_eval's the value."""
    if isinstance(value, bool):
        return f"{key}={'True' if value else 'False'}"
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{key}={value}"
    text = str(value)
    if _literal_keeps_string(text) and re.fullmatch(r"[A-Za-z0-9_./@+:-]+", text):
        return f"{key}={text}"
    if _literal_keeps_string(text):
        return f"{key}={shlex.quote(text)}"
    return f"{key}={shlex.quote(json.dumps(text))}"


def ini_vars_assignment(key: str, value: object) -> str:
    """Format one :vars assignment. The raw text after = is literal_eval'd, with no shell splitting."""
    if isinstance(value, bool):
        return f"{key}={'True' if value else 'False'}"
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{key}={value}"
    text = str(value)
    if text and _literal_keeps_string(text) and "\n" not in text and not text.startswith((" ", "\t")):
        return f"{key}={text}"
    return f"{key}={json.dumps(text)}"


def _literal_keeps_string(text: str) -> bool:
    try:
        parsed = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return True
    return parsed == text


def dump_yaml_vars(data: dict[str, object], indent: int, *, mask: bool) -> list[str]:
    pad = " " * indent
    lines = []
    for key, value in order_items(data):
        lines.append(f"{pad}{yaml_key(key)}: {yaml_scalar(shown_value(key, value, mask=mask))}")
    return lines


@dataclass
class ConnectionAnswers:
    variables: dict[str, object] = field(default_factory=dict)
    ask_pass: bool = False
    ask_become_pass: bool = False


@dataclass
class Group:
    name: str
    parents: list[str] = field(default_factory=list)
    variables: dict[str, object] = field(default_factory=dict)
    priority: int | None = None
    ask_pass: bool = False
    ask_become_pass: bool = False


@dataclass
class Host:
    name: str
    groups: list[str] = field(default_factory=list)
    variables: dict[str, object] = field(default_factory=dict)
    ask_pass: bool = False
    ask_become_pass: bool = False


@dataclass
class OutputFile:
    path: Path
    content: str
    contains_secrets: bool = False


@dataclass
class Inventory:
    all_variables: dict[str, object] = field(default_factory=dict)
    all_ask_pass: bool = False
    all_ask_become_pass: bool = False
    groups: dict[str, Group] = field(default_factory=dict)
    hosts: dict[str, Host] = field(default_factory=dict)

    def add_group(self, name: str) -> Group:
        error = group_name_error(name)
        if error:
            raise ValueError(error)
        if name not in self.groups:
            self.groups[name] = Group(name)
        return self.groups[name]

    def ancestors(self, name: str) -> set[str]:
        found: set[str] = set()
        stack = list(self.groups[name].parents)
        while stack:
            current = stack.pop()
            if current in found or current not in self.groups:
                continue
            found.add(current)
            stack.extend(self.groups[current].parents)
        return found

    def link(self, child: str, parent: str) -> None:
        if child not in self.groups or parent not in self.groups:
            raise ValueError("Both groups have to exist before they can be linked.")
        if child == parent:
            raise ValueError("A group cannot be its own parent.")
        if child in self.ancestors(parent):
            raise ValueError(f"Linking {child} under {parent} would create a cycle.")
        if parent not in self.groups[child].parents:
            self.groups[child].parents.append(parent)

    def children_of(self, name: str) -> list[str]:
        return [group.name for group in self.groups.values() if name in group.parents]

    def hosts_in(self, name: str) -> list[Host]:
        return [host for host in self.hosts.values() if name in host.groups]

    def ungrouped_hosts(self) -> list[Host]:
        return [host for host in self.hosts.values() if not host.groups]

    def remove_group(self, name: str) -> None:
        self.groups.pop(name, None)
        for group in self.groups.values():
            group.parents = [parent for parent in group.parents if parent != name]
        for host in self.hosts.values():
            host.groups = [group for group in host.groups if group != name]

    def remove_host(self, name: str) -> None:
        self.hosts.pop(name, None)

    def ask_pass(self) -> bool:
        return (
            self.all_ask_pass
            or any(group.ask_pass for group in self.groups.values())
            or any(host.ask_pass for host in self.hosts.values())
        )

    def ask_become_pass(self) -> bool:
        return (
            self.all_ask_become_pass
            or any(group.ask_become_pass for group in self.groups.values())
            or any(host.ask_become_pass for host in self.hosts.values())
        )

    def iter_scopes(self) -> list[tuple[str, str, dict[str, object]]]:
        scopes: list[tuple[str, str, dict[str, object]]] = [("group", "all", dict(self.all_variables))]
        for group in self.groups.values():
            scopes.append(("group", group.name, dict(group.variables)))
        for host in self.hosts.values():
            scopes.append(("host", host.name, dict(host.variables)))
        return scopes

    def has_secrets(self) -> bool:
        return any(is_secret_key(key) for _kind, _name, variables in self.iter_scopes() for key in variables)

    def expanded_host_count(self) -> int:
        total = 0
        for host in self.hosts.values():
            if "[" in host.name:
                try:
                    total += len(expand_hostname_range(host.name))
                except ValueError:
                    total += 1
            else:
                total += 1
        return total


def split_secrets(variables: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    normal: dict[str, object] = {}
    secret: dict[str, object] = {}
    for key, value in variables.items():
        if is_secret_key(key):
            secret[key] = value
        else:
            normal[key] = value
    return normal, secret


def render_var_yaml(variables: dict[str, object], *, mask: bool = False, header: list[str] | None = None) -> str:
    lines = ["---"]
    if header:
        lines.extend(header)
    lines.extend(dump_yaml_vars(variables, 0, mask=mask))
    return "\n".join(lines) + "\n"


def render_yaml(inventory: Inventory, header: list[str], *, mask: bool = False, drop_secrets: bool = False) -> str:
    lines = ["---", *header]
    all_vars = _scope_vars(inventory.all_variables, drop_secrets=drop_secrets)
    if all_vars:
        lines.append("all:")
        lines.append("  vars:")
        lines.extend(dump_yaml_vars(all_vars, 4, mask=mask))
    ungrouped = inventory.ungrouped_hosts()
    if ungrouped:
        lines.append("ungrouped:")
        lines.append("  hosts:")
        for host in ungrouped:
            _emit_yaml_host(lines, host, indent=4, mask=mask, drop_secrets=drop_secrets)
    for group in inventory.groups.values():
        lines.append(f"{yaml_key(group.name)}:")
        members = inventory.hosts_in(group.name)
        if members:
            lines.append("  hosts:")
            for host in members:
                _emit_yaml_host(lines, host, indent=4, mask=mask, drop_secrets=drop_secrets)
        group_vars = _scope_vars(group.variables, drop_secrets=drop_secrets)
        if group.priority is not None:
            group_vars["ansible_group_priority"] = group.priority
        if group_vars:
            lines.append("  vars:")
            lines.extend(dump_yaml_vars(group_vars, 4, mask=mask))
        children = inventory.children_of(group.name)
        if children:
            lines.append("  children:")
            for child in children:
                lines.append(f"    {yaml_key(child)}: {{}}")
    if len(lines) == len(header) + 1:
        lines.extend(["all:", "  hosts: {}"])
    return "\n".join(lines) + "\n"


def _scope_vars(variables: dict[str, object], *, drop_secrets: bool) -> dict[str, object]:
    if not drop_secrets:
        return dict(variables)
    normal, _secret = split_secrets(variables)
    return normal


def _emit_yaml_host(lines: list[str], host: Host, *, indent: int, mask: bool, drop_secrets: bool) -> None:
    # A range pattern is one inventory key that Ansible expands. Its variables
    # have to stay on that key; a host_vars file named after the pattern would
    # not apply to the expanded hosts.
    variables = _scope_vars(host.variables, drop_secrets=drop_secrets and "[" not in host.name)
    pad = " " * indent
    lines.append(f"{pad}{yaml_key(host.name)}:")
    lines.extend(dump_yaml_vars(variables, indent + 2, mask=mask))


def render_ini(inventory: Inventory, header: list[str], *, mask: bool = False, drop_secrets: bool = False) -> str:
    lines = list(header)
    lines.append("# Values are Python literals, so True, False, numbers, and quoted strings keep their type.")
    for host in inventory.ungrouped_hosts():
        lines.append(_ini_host_line(host, mask=mask, drop_secrets=drop_secrets))
    all_vars = _scope_vars(inventory.all_variables, drop_secrets=drop_secrets)
    if all_vars:
        lines.append("")
        lines.append("[all:vars]")
        lines.extend(_ini_var_lines(all_vars, mask=mask))
    for group in inventory.groups.values():
        lines.append("")
        lines.append(f"[{group.name}]")
        members = inventory.hosts_in(group.name)
        if members:
            for host in members:
                lines.append(_ini_host_line(host, mask=mask, drop_secrets=drop_secrets))
        group_vars = _scope_vars(group.variables, drop_secrets=drop_secrets)
        if group.priority is not None:
            group_vars["ansible_group_priority"] = group.priority
        if group_vars:
            lines.append("")
            lines.append(f"[{group.name}:vars]")
            lines.extend(_ini_var_lines(group_vars, mask=mask))
        children = inventory.children_of(group.name)
        if children:
            lines.append("")
            lines.append(f"[{group.name}:children]")
            lines.extend(children)
    return "\n".join(lines).rstrip() + "\n"


def _ini_host_line(host: Host, *, mask: bool, drop_secrets: bool) -> str:
    variables = _scope_vars(host.variables, drop_secrets=drop_secrets and "[" not in host.name)
    parts = [host.name]
    for key, value in order_items(variables):
        shown = shown_value(key, value, mask=mask)
        if mask and is_secret_key(key):
            parts.append(f"{key}=********")
        else:
            parts.append(ini_host_assignment(key, shown if not is_secret_key(key) else str(value)))
    return " ".join(parts)


def _ini_var_lines(variables: dict[str, object], *, mask: bool) -> list[str]:
    lines = []
    for key, value in order_items(variables):
        if mask and is_secret_key(key):
            lines.append(f"{key}=********")
            continue
        lines.append(ini_vars_assignment(key, str(value) if is_secret_key(key) else value))
    return lines


def ask_become_password(answers: ConnectionAnswers, *, default: int) -> None:
    labels = [
        "Not required",
        "Prompt at runtime with --ask-become-pass",
        "Save a become password for later vault encryption",
    ]
    if answers.variables.get("ansible_password") or answers.ask_pass:
        labels.append("Same as the login password")
    choice = prompt_choice("Privilege escalation password", labels, default=default)
    if choice == 2:
        answers.ask_become_pass = True
        say("Ansible will ask for it with --ask-become-pass. It is separate from --ask-pass.")
    elif choice == 3:
        secret = prompt_secret("Become password (empty to skip)")
        if secret:
            answers.variables["ansible_become_password"] = secret
        else:
            print("  Become password was not stored.")
    elif choice == 4:
        if answers.variables.get("ansible_password"):
            answers.variables["ansible_become_password"] = answers.variables["ansible_password"]
        else:
            answers.ask_become_pass = True
            say("The login password is not stored, so the become password will be prompted with --ask-become-pass.")


def ask_login_password(answers: ConnectionAnswers, *, purpose: str) -> None:
    secret = prompt_secret(f"{purpose} (empty to skip)")
    if secret:
        answers.variables["ansible_password"] = secret
    else:
        print("  Login password was not stored.")


def ask_user(answers: ConnectionAnswers, *, blank_means: str) -> None:
    user = prompt_optional(f"Remote user ({blank_means})")
    if not user:
        return
    if any(char.isspace() for char in user):
        print("  User names cannot contain whitespace. Leaving ansible_user unset.")
        return
    answers.variables["ansible_user"] = user


def ask_port(answers: ConnectionAnswers, *, default_port: int | None) -> None:
    hint = f"blank keeps {default_port}" if default_port else "blank to leave unset"
    while True:
        raw = prompt_optional(f"Connection port ({hint})")
        if raw == "":
            return
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            answers.variables["ansible_port"] = int(raw)
            return
        print("  Enter a port from 1 to 65535, or leave it blank.")


def ask_extra(answers: ConnectionAnswers) -> None:
    say("Extra variables apply to this same scope. Enter key=value, then a blank line.")
    say("Examples from the inventory guide: http_port=80, ntp_server=ntp.atlanta.example.com. true/false/yes/no become booleans, and whole numbers become integers.")
    while True:
        raw = prompt_optional("Variable")
        if raw == "":
            return
        if "=" not in raw:
            print("  Use key=value.")
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "ansible_group_priority":
            print("  Set ansible_group_priority on the group prompt. It is only read from the inventory source, not from group_vars.")
            continue
        if key == "ansible_host" and "inventory_hostname" in value and "inventory_hostname_short" not in value:
            say("Do not set ansible_host from inventory_hostname. The inventory guide says to use inventory_hostname_short when a template is unavoidable.")
            continue
        error = None if key.startswith("ansible_") and is_valid_identifier(key) else variable_name_error(key)
        if key.startswith("ansible_") and not is_valid_identifier(key):
            error = "That ansible_ name is not a valid variable name."
        if error:
            print(f"  {error}")
            continue
        if is_secret_key(key):
            secret = prompt_secret(key)
            if secret:
                answers.variables[key] = secret
            continue
        answers.variables[key] = coerce_scalar(value)


def ask_ssh_auth(answers: ConnectionAnswers) -> None:
    say("Ansible expects SSH keys. ssh-agent is the supported way to unlock a key, because the SSH connection plugin cannot prompt for a key passphrase.")
    choice = prompt_choice(
        "Authentication",
        [
            "SSH agent, ssh_config, or default keys",
            "A private key file (ansible_ssh_private_key_file)",
            "A private key file and a saved login password",
            "A login password saved for vault encryption",
            "A login password prompted with --ask-pass",
        ],
        default=1,
    )
    if choice in {2, 3}:
        key = prompt("Private key file", default="~/.ssh/id_ed25519")
        answers.variables["ansible_ssh_private_key_file"] = key
        say("The path is stored as entered. Ansible expands ~ on the control node. If this key has a passphrase, load it into ssh-agent first.")
    if choice in {3, 4}:
        ask_login_password(answers, purpose="Login password")
    if choice == 5:
        answers.ask_pass = True
        say("The password will not be written. Run playbooks with --ask-pass.")


def ask_become(answers: ConnectionAnswers, profile: str) -> None:
    if profile == "network":
        if not prompt_yes_no("Use enable mode (ansible_become_method=enable)?", False):
            return
        answers.variables["ansible_become"] = True
        answers.variables["ansible_become_method"] = "enable"
        ask_become_password(answers, default=2)
        return
    if profile == "winrm":
        say("Windows privilege escalation uses become method runas, and ansible_become_user is required. The seclogon service must be running on the host.")
        if not prompt_yes_no("Enable runas for these hosts?", False):
            return
        user = prompt("Become user (DOMAIN\\user or user@domain)")
        answers.variables["ansible_become"] = True
        answers.variables["ansible_become_method"] = "runas"
        answers.variables["ansible_become_user"] = user
        ask_become_password(answers, default=2)
        flags = prompt_optional("ansible_become_flags (blank to skip)")
        if flags:
            answers.variables["ansible_become_flags"] = flags
        return
    choice = prompt_choice(
        "Privilege escalation",
        [
            "Leave unset",
            "sudo to root",
            "Choose a become method and user",
            "Set ansible_become to false",
        ],
        default=1,
    )
    if choice == 1:
        return
    if choice == 4:
        answers.variables["ansible_become"] = False
        return
    if choice == 2:
        answers.variables["ansible_become"] = True
        answers.variables["ansible_become_method"] = "sudo"
        answers.variables["ansible_become_user"] = "root"
        ask_become_password(answers, default=1)
        return
    method_index = prompt_choice("Become method", list(BECOME_METHODS), default=1)
    method = BECOME_METHODS[method_index - 1]
    user = prompt("Become user", default="root")
    answers.variables["ansible_become"] = True
    answers.variables["ansible_become_method"] = method
    answers.variables["ansible_become_user"] = user
    ask_become_password(answers, default=1)


def ask_jump_host(answers: ConnectionAnswers) -> None:
    say("OpenSSH can jump through a bastion. Leave this blank to rely on ~/.ssh/config, which Ansible uses by default.")
    raw = prompt_optional("ProxyJump bastion, or full ansible_ssh_common_args")
    if not raw:
        return
    if raw.startswith("-"):
        answers.variables["ansible_ssh_common_args"] = raw
    else:
        answers.variables["ansible_ssh_common_args"] = f"-o ProxyJump={raw}"


def ask_advanced_ssh(answers: ConnectionAnswers) -> None:
    say("These are the remaining SSH behavioral parameters: pipelining, extra args, sftp args, scp args, the ssh executable, become exe, become flags, the remote shell, and other interpreters.")
    if not prompt_yes_no("Set those SSH parameters?", False):
        return
    pipelining = prompt_choice("SSH pipelining (ansible_ssh_pipelining)", ["Leave unset", "Enable", "Disable"], default=1)
    if pipelining == 2:
        answers.variables["ansible_ssh_pipelining"] = True
    elif pipelining == 3:
        answers.variables["ansible_ssh_pipelining"] = False
    for key, label in (
        ("ansible_ssh_extra_args", "ansible_ssh_extra_args"),
        ("ansible_sftp_extra_args", "ansible_sftp_extra_args"),
        ("ansible_scp_extra_args", "ansible_scp_extra_args"),
        ("ansible_ssh_executable", "ansible_ssh_executable"),
        ("ansible_become_exe", "ansible_become_exe"),
        ("ansible_become_flags", "ansible_become_flags"),
        ("ansible_shell_executable", "ansible_shell_executable"),
    ):
        value = prompt_optional(f"{label} (blank to skip)")
        if value:
            answers.variables[key] = value
    if "ansible_ssh_common_args" not in answers.variables:
        common = prompt_optional("ansible_ssh_common_args (blank to skip)")
        if common:
            answers.variables["ansible_ssh_common_args"] = common
    shell = prompt_choice(
        "Remote shell type. Only change this when the host cannot run sh.",
        ["Leave unset (sh)", "csh", "fish"],
        default=1,
    )
    if shell == 2:
        answers.variables["ansible_shell_type"] = "csh"
    elif shell == 3:
        answers.variables["ansible_shell_type"] = "fish"
    other = prompt_optional("Other interpreter, as key=value (example ansible_ruby_interpreter=/usr/bin/ruby)")
    if other and "=" in other:
        key, value = other.split("=", 1)
        key = key.strip()
        if key.startswith("ansible_") and key.endswith("_interpreter") and is_valid_identifier(key):
            answers.variables[key] = value.strip()
        else:
            print("  Expected an ansible_*_interpreter variable. It was not stored.")


def interview_ssh(answers: ConnectionAnswers, *, connection: str | None) -> None:
    if connection:
        answers.variables["ansible_connection"] = connection
    elif prompt_yes_no("Write ansible_connection: ssh explicitly? SSH is already the default.", False):
        answers.variables["ansible_connection"] = "ssh"
    ask_user(answers, blank_means="blank uses the user on the control node")
    ask_ssh_auth(answers)
    ask_port(answers, default_port=22)
    ask_become(answers, "ssh")
    ask_jump_host(answers)
    interpreter = prompt_optional("ansible_python_interpreter (blank to discover Python on the host)")
    if interpreter:
        answers.variables["ansible_python_interpreter"] = interpreter
    ask_advanced_ssh(answers)


def interview_local(answers: ConnectionAnswers) -> None:
    say("ansible_connection=local runs modules on the control node. Implicit localhost already exists; set this on a host named localhost when you need an explicit interpreter.")
    answers.variables["ansible_connection"] = "local"
    if prompt_yes_no("Set ansible_python_interpreter for this scope?", True):
        answers.variables["ansible_python_interpreter"] = prompt(
            "Python interpreter",
            default="/usr/bin/env python",
        )
    ask_become(answers, "local")


def interview_winrm(answers: ConnectionAnswers) -> None:
    say("WinRM is ansible.builtin.winrm. The default port is 5986 for HTTPS and 5985 for HTTP. A username like user@domain uses Kerberos unless you set a transport.")
    answers.variables["ansible_connection"] = "ansible.builtin.winrm"
    ask_user(answers, blank_means="blank leaves ansible_user unset")
    auth = prompt_choice(
        "WinRM authentication",
        [
            "Save a password for later vault encryption",
            "Prompt for the password with --ask-pass",
            "Kerberos ticket already on the control node (no password stored)",
        ],
        default=1,
    )
    if auth == 1:
        ask_login_password(answers, purpose="WinRM password")
    elif auth == 2:
        answers.ask_pass = True
    scheme = prompt_choice("WinRM scheme", ["HTTPS on port 5986", "HTTP on port 5985", "Leave port and scheme unset"], default=1)
    if scheme == 1:
        answers.variables["ansible_winrm_scheme"] = "https"
        answers.variables["ansible_port"] = 5986
    elif scheme == 2:
        answers.variables["ansible_winrm_scheme"] = "http"
        answers.variables["ansible_port"] = 5985
    ask_port(answers, default_port=None)
    transport = prompt_choice(
        "WinRM transport",
        ["Let the plugin choose", "ntlm", "kerberos", "credssp", "basic", "certificate"],
        default=1,
    )
    if transport > 1:
        answers.variables["ansible_winrm_transport"] = ["ntlm", "kerberos", "credssp", "basic", "certificate"][transport - 2]
    if prompt_yes_no("Ignore WinRM server certificate validation? This disables a TLS check.", False):
        answers.variables["ansible_winrm_server_cert_validation"] = "ignore"
    ask_become(answers, "winrm")
    if prompt_yes_no("Set advanced WinRM parameters (timeout, Kerberos kinit, path)?", False):
        timeout = prompt_optional("ansible_winrm_connection_timeout seconds (blank to skip)")
        if timeout.isdigit():
            answers.variables["ansible_winrm_connection_timeout"] = int(timeout)
        mode = prompt_choice("Kerberos kinit mode", ["Leave unset", "managed", "manual"], default=1)
        if mode == 2:
            answers.variables["ansible_winrm_kinit_mode"] = "managed"
        elif mode == 3:
            answers.variables["ansible_winrm_kinit_mode"] = "manual"
        kinit = prompt_optional("ansible_winrm_kinit_cmd (blank keeps kinit)")
        if kinit:
            answers.variables["ansible_winrm_kinit_cmd"] = kinit
        path = prompt_optional("ansible_winrm_path (blank keeps /wsman)")
        if path:
            answers.variables["ansible_winrm_path"] = path


def interview_network(answers: ConnectionAnswers) -> None:
    say("Network platforms use ansible_connection=ansible.netcommon.network_cli plus ansible_network_os. Group devices by platform when they share an OS.")
    answers.variables["ansible_connection"] = "ansible.netcommon.network_cli"
    labels = list(NETWORK_OS) + ["Another ansible_network_os value"]
    choice = prompt_choice("Network platform", labels, default=1)
    if choice == len(labels):
        os_name = prompt("ansible_network_os (collection FQCN)")
    else:
        os_name = NETWORK_OS[choice - 1]
    answers.variables["ansible_network_os"] = os_name
    ask_user(answers, blank_means="blank leaves ansible_user unset")
    auth = prompt_choice(
        "Device login",
        [
            "Save a password for later vault encryption",
            "Prompt with --ask-pass (-k)",
        ],
        default=1,
    )
    if auth == 1:
        ask_login_password(answers, purpose="Device password")
    else:
        answers.ask_pass = True
        say("Run the playbook with -k or --ask-pass.")
    ask_port(answers, default_port=22)
    ask_become(answers, "network")


def interview_custom(answers: ConnectionAnswers) -> None:
    plugin = prompt("Connection plugin name (example community.docker.docker)")
    answers.variables["ansible_connection"] = plugin
    ask_user(answers, blank_means="blank leaves ansible_user unset")
    ask_port(answers, default_port=None)
    auth = prompt_choice(
        "Login password",
        ["Do not set one", "Save a password", "Prompt with --ask-pass"],
        default=1,
    )
    if auth == 2:
        ask_login_password(answers, purpose="Login password")
    elif auth == 3:
        answers.ask_pass = True
    ask_become(answers, "ssh")


def interview_profile(scope_label: str) -> ConnectionAnswers:
    answers = ConnectionAnswers()
    while True:
        choice = prompt_choice(
            f"Connection profile for {scope_label}",
            [
                "Linux or Unix over SSH",
                "Paramiko, when OpenSSH has no ControlPersist",
                "Local actions on the control node",
                "Windows over WinRM",
                "Network device (ansible.netcommon.network_cli)",
                "Another connection plugin",
            ],
            default=1,
        )
        if choice == 3 and scope_label.startswith("all ") and not prompt_yes_no(
            "Local connection on all hosts runs every module on the control node. Use it only for a localhost inventory. Continue?",
            False,
        ):
            continue
        break
    print()
    if choice == 1:
        interview_ssh(answers, connection=None)
    elif choice == 2:
        say("Paramiko is Ansible's Python SSH fallback. Host key checking is slower in this mode, so the SSH connection is preferable when OpenSSH is new enough.")
        interview_ssh(answers, connection="paramiko")
    elif choice == 3:
        interview_local(answers)
    elif choice == 4:
        interview_winrm(answers)
    elif choice == 5:
        interview_network(answers)
    else:
        interview_custom(answers)
    print()
    ask_extra(answers)
    return answers


def interview_overrides(scope_label: str) -> ConnectionAnswers:
    answers = ConnectionAnswers()
    say(f"Overrides for {scope_label} replace inherited values only where you set them. Host variables win over child groups, which win over parent groups, which win over all.")
    while True:
        choice = prompt_choice(
            "Which setting should change?",
            [
                "Remote user",
                "Port",
                "Authentication",
                "Privilege escalation",
                "Private key or jump host",
                "Python interpreter",
                "Extra variables",
                "Answer the full connection questionnaire",
                "Done",
            ],
            default=9,
        )
        if choice == 9:
            return answers
        if choice == 1:
            ask_user(answers, blank_means="blank leaves the inherited user")
        elif choice == 2:
            ask_port(answers, default_port=None)
        elif choice == 3:
            ask_ssh_auth(answers)
        elif choice == 4:
            ask_become(answers, "ssh")
        elif choice == 5:
            key = prompt_optional("ansible_ssh_private_key_file (blank to skip)")
            if key:
                answers.variables["ansible_ssh_private_key_file"] = key
            ask_jump_host(answers)
        elif choice == 6:
            interpreter = prompt_optional("ansible_python_interpreter (blank to skip)")
            if interpreter:
                answers.variables["ansible_python_interpreter"] = interpreter
        elif choice == 7:
            ask_extra(answers)
        else:
            return interview_profile(scope_label)


def apply_answers(target_vars: dict[str, object], answers: ConnectionAnswers) -> None:
    target_vars.update(answers.variables)


class Wizard:
    def __init__(self) -> None:
        self.inventory = Inventory()
        self.output_format = "yaml"
        self.output_path = Path("inventory.yml")
        self.reveal_secrets = False
        self.vault_label = "dev"
        self.encrypted = False

    def welcome(self) -> None:
        section("Ansible inventory builder")
        say("This writes a static inventory of managed nodes. It asks for groups, parent groups, hosts, usernames, passwords, privilege escalation, and the connection variables documented in the Ansible inventory guide.")
        say(DOCS)
        say("Press Enter to accept a default in [brackets]. Ctrl+C cancels before any file is written. Dynamic inventory plugins are not created here.")

    def configure_output(self) -> None:
        section("1. Output")
        say("YAML keeps booleans and numbers intact. INI parses values as Python literals on current Ansible, and the inventory guide still recommends YAML when the variable type matters.")
        choice = prompt_choice("Inventory format", ["YAML", "INI"], default=1)
        self.output_format = "yaml" if choice == 1 else "ini"
        default_name = "inventory.yml" if self.output_format == "yaml" else "inventory.ini"
        say("Use a distinct file per environment when you want to avoid mixing them, for example inventory_test.yml and inventory_staging.yml.")
        raw_path = prompt("Output file", default=default_name)
        self.output_path = Path(raw_path).expanduser()

    def configure_defaults(self) -> None:
        section("2. Connection defaults for all hosts")
        say("These become variables on the implicit all group, so every host inherits them. You can override them on a group or a host later. Same-level groups merge in alphabetical order unless you set ansible_group_priority.")
        say(CONNECTION_DOCS)
        if not prompt_yes_no("Set connection defaults for all hosts now?", True):
            return
        answers = interview_profile("all hosts")
        self.inventory.all_variables = dict(answers.variables)
        self.inventory.all_ask_pass = answers.ask_pass
        self.inventory.all_ask_become_pass = answers.ask_become_pass

    def group_loop(self) -> None:
        section("3. Groups")
        say("Name groups like variables: letters, numbers, and underscores, without a leading number or a hyphen. A practical split is what (webservers), where (east), and when (prod).")
        say("Parent groups use children. Hosts in a child are members of the parent. A group may have several parents, and the relationship cannot cycle. Create the child groups first, then name them while creating the parent.")
        if not prompt_yes_no("Add a group now?", True):
            return
        while True:
            self.add_group()
            if not prompt_yes_no("Add another group?", False):
                return

    def add_group(self) -> None:
        while True:
            name = prompt("Group name")
            try:
                group = self.inventory.add_group(name)
            except ValueError as exc:
                print(f"  {exc}")
                continue
            break
        self._link_from_prompt(group.name, "Parent groups (comma-separated, blank if none)", as_parents=True)
        self._link_from_prompt(group.name, "Child groups (comma-separated, blank if none)", as_parents=False)
        self._ask_priority(group)
        if prompt_yes_no(f"Override connection settings for {group.name}?", False):
            answers = interview_overrides(f"group {group.name}")
            apply_answers(group.variables, answers)
            group.ask_pass = group.ask_pass or answers.ask_pass
            group.ask_become_pass = group.ask_become_pass or answers.ask_become_pass
        print()
        say(f"Extra variables for {group.name}. Child group variables override parent group variables.")
        extra = ConnectionAnswers()
        ask_extra(extra)
        apply_answers(group.variables, extra)

    def _ask_priority(self, group: Group) -> None:
        say("ansible_group_priority changes merge order among groups at the same level. A larger number wins. It must live in the inventory file, not in group_vars. Blank leaves the default of 1.")
        while True:
            raw = prompt_optional(f"ansible_group_priority for {group.name}")
            if raw == "":
                return
            if raw.isdigit() and int(raw) >= 1:
                group.priority = int(raw)
                return
            print("  Enter a positive integer, or leave it blank.")

    def _link_from_prompt(self, group_name: str, message: str, *, as_parents: bool) -> None:
        raw = prompt_optional(message)
        for name in split_names(raw):
            self._ensure_group(name)
            try:
                if as_parents:
                    self.inventory.link(group_name, name)
                else:
                    self.inventory.link(name, group_name)
            except ValueError as exc:
                print(f"  {exc}")

    def _ensure_group(self, name: str) -> bool:
        if name in self.inventory.groups:
            return True
        error = group_name_error(name)
        if error:
            print(f"  {error}")
            return False
        if prompt_yes_no(f"Group {name} does not exist yet. Create it?", True):
            self.inventory.add_group(name)
            return True
        return False

    def host_loop(self) -> None:
        section("4. Hosts")
        say("The inventory hostname can be an alias. Set ansible_host when the name you want to type is not the address Ansible should connect to. A host can sit in more than one group.")
        say("Ranges such as www[01:50].example.com, www[01:50:2].example.com, and db-[a:f].example.com are expanded by the YAML and INI inventory plugins. host:port sets ansible_port, as in badwolf.example.com:5309.")
        if not prompt_yes_no("Add hosts now?", True):
            return
        while True:
            self.add_hosts()
            if not prompt_yes_no("Add another batch of hosts?", False):
                return

    def add_hosts(self) -> None:
        print()
        say("Enter hosts, one per line. A blank line finishes the list. A line can also be @path to a text file.")
        print("  web1.example.com")
        print("  web1.example.com:2222")
        print("  alias ansible_host=192.0.2.10")
        print("  alias=192.0.2.10")
        print("  www[01:50].example.com")
        print("  www[01:03].example.com=10.0.0.[1:3]")
        lines: list[str] = []
        while True:
            raw = prompt_optional("Host")
            if raw == "":
                break
            if raw.startswith("@"):
                file_path = Path(raw[1:]).expanduser()
                if not file_path.is_file():
                    print(f"  No file at {file_path}.")
                    continue
                file_lines = file_path.read_text(encoding="utf-8").splitlines()
                lines.extend(line.strip() for line in file_lines if line.strip() and not line.strip().startswith("#"))
                print(f"  Read {len(file_lines)} lines from {file_path}.")
                continue
            lines.append(raw)
        if not lines:
            print("  No hosts entered.")
            return
        expand_ranges = False
        if any("[" in line.split("=", 1)[0] for line in lines):
            say("Range patterns can stay in the inventory so Ansible expands them, which is what the inventory guide shows. Expand them now only when each host needs its own variables.")
            expand_ranges = prompt_yes_no("Expand range patterns into individual hosts?", False)
        parsed: list[tuple[str, dict[str, object]]] = []
        for line in lines:
            try:
                parsed.extend(parse_host_line(line, expand_ranges=expand_ranges))
            except ValueError as exc:
                print(f"  Skipping {line!r}: {exc}")
        if not parsed:
            print("  No usable hosts in that batch.")
            return
        self._describe_parsed_hosts(parsed)
        if not prompt_yes_no("Use these hosts?", True):
            return
        for name, variables in parsed:
            self._note_localhost(name, variables)
            if variables.get("ansible_host") == name:
                variables.pop("ansible_host", None)
                print(f"  ansible_host for {name} matches its inventory name, so it was left unset.")
        group_names = self._prompt_host_groups()
        answers = ConnectionAnswers()
        if prompt_yes_no("Override connection settings for this batch?", False):
            answers = interview_overrides("this batch of hosts")
        print()
        say("Extra variables for this batch. These are host variables, so they override group variables.")
        ask_extra(answers)
        for name, variables in parsed:
            variables.update(answers.variables)
            self._store_host(name, group_names, variables, answers)

    def _describe_parsed_hosts(self, parsed: list[tuple[str, dict[str, object]]]) -> None:
        print()
        shown = 0
        total = 0
        for name, variables in parsed:
            if "[" in name:
                try:
                    expanded = expand_hostname_range(name)
                except ValueError:
                    expanded = [name]
                total += len(expanded)
                preview = ", ".join(expanded[:6])
                suffix = "" if len(expanded) <= 6 else f", ... ({len(expanded)} hosts)"
                print(f"  {name} -> {preview}{suffix}")
            else:
                total += 1
                if shown < 20:
                    address = variables.get("ansible_host")
                    port = variables.get("ansible_port")
                    detail = name
                    if address:
                        detail += f" -> {address}"
                    if port:
                        detail += f" port {port}"
                    print(f"  {detail}")
                    shown += 1
        if total > 20 and shown >= 20:
            print(f"  ... {total} hosts in this batch")
        else:
            print(f"  {total} host(s)")

    def _note_localhost(self, name: str, variables: dict[str, object]) -> None:
        if name not in {"localhost", "127.0.0.1"} or "ansible_connection" in variables:
            return
        say("The connection guide shows localhost with ansible_connection=local when you want an explicit interpreter.")
        if prompt_yes_no(f"Set ansible_connection=local on {name}?", True):
            variables["ansible_connection"] = "local"
            if "ansible_python_interpreter" not in variables and prompt_yes_no("Set ansible_python_interpreter for localhost?", True):
                variables["ansible_python_interpreter"] = prompt("Python interpreter", default="/usr/bin/env python")

    def _prompt_host_groups(self) -> list[str]:
        if self.inventory.groups:
            print("Existing groups: " + ", ".join(self.inventory.groups))
        raw = prompt_optional("Groups for these hosts (comma-separated, blank for ungrouped)")
        names = []
        for name in split_names(raw):
            if self._ensure_group(name):
                names.append(name)
        if not names and not prompt_yes_no("Leave these hosts in the ungrouped group?", False):
            return self._prompt_host_groups()
        return names

    def _store_host(self, name: str, groups: list[str], variables: dict[str, object], answers: ConnectionAnswers) -> None:
        if name in self.inventory.hosts:
            if not prompt_yes_no(f"{name} is already in the inventory. Replace it?", True):
                return
            host = self.inventory.hosts[name]
        else:
            host = Host(name)
            self.inventory.hosts[name] = host
        host.groups = list(groups)
        host.variables = dict(variables)
        host.ask_pass = answers.ask_pass
        host.ask_become_pass = answers.ask_become_pass

    def review_loop(self) -> None:
        section("5. Review")
        if self.inventory.has_secrets():
            self.reveal_secrets = prompt_yes_no("Show passwords in the preview?", False)
        while True:
            self.show_status()
            for warning in self.warnings():
                print(f"Warning: {warning}")
            print()
            print(self.render_preview())
            choice = prompt_choice(
                "What next?",
                [
                    "Write the inventory",
                    "Add a group",
                    "Add hosts",
                    "Change connection defaults for all hosts",
                    "Add or replace extra variables",
                    "Link a child group to a parent",
                    "Remove a host or group",
                    "Quit without writing",
                ],
            )
            if choice == 1:
                if self.write_flow():
                    return
            elif choice == 2:
                self.add_group()
            elif choice == 3:
                self.add_hosts()
            elif choice == 4:
                answers = interview_profile("all hosts")
                self.inventory.all_variables = dict(answers.variables)
                self.inventory.all_ask_pass = answers.ask_pass
                self.inventory.all_ask_become_pass = answers.ask_become_pass
            elif choice == 5:
                self.add_extra_anywhere()
            elif choice == 6:
                self.link_groups()
            elif choice == 7:
                self.remove_something()
            else:
                print("No files were written.")
                return

    def show_status(self) -> None:
        expanded = self.inventory.expanded_host_count()
        entered = len(self.inventory.hosts)
        group_list = ", ".join(self.inventory.groups) if self.inventory.groups else "none"
        host_note = f"{entered} host entries"
        if expanded != entered:
            host_note += f", {expanded} after range expansion"
        print()
        print(f"{host_note}. Groups: {group_list}.")

    def warnings(self) -> list[str]:
        notes = []
        if not self.inventory.hosts:
            notes.append("There are no hosts yet.")
        for group in self.inventory.groups.values():
            if not self.inventory.hosts_in(group.name) and not self.inventory.children_of(group.name):
                notes.append(f"{group.name} has no hosts and no child groups. Ansible drops empty groups when it finishes the inventory source.")
        addresses: dict[str, list[str]] = {}
        for host in self.inventory.hosts.values():
            address = str(host.variables.get("ansible_host", ""))
            if address:
                addresses.setdefault(address, []).append(host.name)
        for address, names in addresses.items():
            if len(names) > 1:
                notes.append(
                    f"{', '.join(names)} all connect to {address}. Ansible can run tasks on those aliases in parallel."
                )
        return notes

    def render_preview(self) -> str:
        header = ["# Preview. Passwords are hidden here." if not self.reveal_secrets and self.inventory.has_secrets() else "# Preview."]
        if self.output_format == "yaml":
            return render_yaml(self.inventory, header, mask=not self.reveal_secrets)
        return render_ini(self.inventory, header, mask=not self.reveal_secrets)

    def add_extra_anywhere(self) -> None:
        target = prompt_choice("Add variables to", ["all hosts", "one group", "one host"], default=1)
        if target == 1:
            bucket = self.inventory.all_variables
            label = "all hosts"
        elif target == 2:
            if not self.inventory.groups:
                print("  There are no groups yet.")
                return
            name = prompt("Group name")
            if name not in self.inventory.groups:
                print(f"  No group named {name}.")
                return
            bucket = self.inventory.groups[name].variables
            label = name
        else:
            if not self.inventory.hosts:
                print("  There are no hosts yet.")
                return
            name = prompt("Inventory hostname")
            if name not in self.inventory.hosts:
                print(f"  No host named {name}.")
                return
            bucket = self.inventory.hosts[name].variables
            label = name
        say(f"Variables for {label}. Entering an existing key replaces it.")
        extra = ConnectionAnswers()
        ask_extra(extra)
        apply_answers(bucket, extra)

    def link_groups(self) -> None:
        if len(self.inventory.groups) < 2:
            print("  Create at least two groups before linking them.")
            return
        print("Groups: " + ", ".join(self.inventory.groups))
        parent = prompt("Parent group")
        child = prompt("Child group")
        if not self._ensure_group(parent) or not self._ensure_group(child):
            return
        try:
            self.inventory.link(child, parent)
        except ValueError as exc:
            print(f"  {exc}")
            return
        print(f"  {child} is now a child of {parent}.")

    def remove_something(self) -> None:
        kind = prompt_choice("Remove", ["a host", "a group"], default=1)
        if kind == 1:
            name = prompt("Inventory hostname")
            if name not in self.inventory.hosts:
                print(f"  No host named {name}.")
                return
            if prompt_yes_no(f"Remove {name}?", False):
                self.inventory.remove_host(name)
        else:
            name = prompt("Group name")
            if name not in self.inventory.groups:
                print(f"  No group named {name}.")
                return
            if prompt_yes_no(f"Remove {name}? Hosts in it stay in their other groups.", False):
                self.inventory.remove_group(name)

    def usage_flags(self) -> list[str]:
        flags = []
        if self.inventory.ask_pass():
            flags.append("--ask-pass")
        if self.inventory.ask_become_pass():
            flags.append("--ask-become-pass")
        if self.encrypted:
            flags.append(f"--vault-id {self.vault_label}@prompt")
        return flags

    def command_suffix(self) -> str:
        flags = self.usage_flags()
        if not flags:
            return ""
        return " " + " ".join(flags)

    def inventory_display(self) -> str:
        path = self.output_path
        try:
            return str(path.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            return str(path)

    def header_lines(self) -> list[str]:
        inventory_arg = self.inventory_display()
        suffix = self.command_suffix()
        return [
            "# Generated by build_inventory.py",
            f"# {DOCS}",
            "#",
            f"# ansible-inventory -i {inventory_arg} --graph",
            f"# ansible-playbook -i {inventory_arg} site.yml{suffix}",
        ]

    def render_inventory_text(self, *, drop_secrets: bool) -> str:
        header = self.header_lines()
        if self.output_format == "yaml":
            return render_yaml(self.inventory, header, drop_secrets=drop_secrets)
        return render_ini(self.inventory, header, drop_secrets=drop_secrets)

    def build_outputs(self, layout: str, secret_mode: str) -> list[OutputFile]:
        drop_secrets = secret_mode == "extract"
        files: list[OutputFile] = []
        inventory_text = self.render_inventory_text(drop_secrets=drop_secrets)
        inventory_has_secrets = secret_mode != "extract" and layout == "inventory" and self.inventory.has_secrets()
        if layout == "dirs":
            inventory_text = self._render_without_exported_vars()
            inventory_has_secrets = False
        files.append(OutputFile(self.output_path, inventory_text, inventory_has_secrets and secret_mode == "inline"))
        if secret_mode == "plaintext" and layout == "inventory":
            files[0].contains_secrets = self.inventory.has_secrets()
        if layout == "dirs" or secret_mode == "extract":
            files.extend(self._var_files(layout, secret_mode))
        if secret_mode == "inline" and layout == "dirs":
            for item in files:
                if item.path != self.output_path and _content_has_secret(item.content):
                    item.contains_secrets = True
        return _dedupe_files(files)

    def _render_without_exported_vars(self) -> str:
        saved_all = dict(self.inventory.all_variables)
        saved_groups = {name: dict(group.variables) for name, group in self.inventory.groups.items()}
        saved_hosts = {name: dict(host.variables) for name, host in self.inventory.hosts.items()}
        try:
            self.inventory.all_variables = {}
            for group in self.inventory.groups.values():
                group.variables = {}
            for host in self.inventory.hosts.values():
                if "[" in host.name:
                    continue
                host.variables = {}
            return self.render_inventory_text(drop_secrets=False)
        finally:
            self.inventory.all_variables = saved_all
            for name, variables in saved_groups.items():
                self.inventory.groups[name].variables = variables
            for name, variables in saved_hosts.items():
                self.inventory.hosts[name].variables = variables

    def _var_files(self, layout: str, secret_mode: str) -> list[OutputFile]:
        files: list[OutputFile] = []
        scopes: list[tuple[str, str, dict[str, object]]] = []
        if layout == "dirs" or secret_mode == "extract":
            scopes.append(("group", "all", dict(self.inventory.all_variables)))
            for group in self.inventory.groups.values():
                scopes.append(("group", group.name, dict(group.variables)))
            for host in self.inventory.hosts.values():
                if "[" in host.name:
                    continue
                if secret_mode == "extract" or layout == "dirs":
                    scopes.append(("host", host.name, dict(host.variables)))
        base = self.output_path.parent
        for kind, name, variables in scopes:
            if kind == "group" and name != "all":
                variables = dict(variables)
                variables.pop("ansible_group_priority", None)
            normal, secret = split_secrets(variables)
            if layout != "dirs":
                normal = {}
            if secret_mode != "extract":
                if secret_mode == "inline":
                    normal = {**normal, **secret}
                elif secret_mode == "plaintext":
                    normal = {**normal, **secret}
                secret = {}
            folder = "group_vars" if kind == "group" else "host_vars"
            if normal and secret:
                files.append(self._vars_output(base / folder / name / "vars.yml", normal, secret=False))
                files.append(self._vars_output(base / folder / name / "vault.yml", secret, secret=True))
            elif normal:
                files.append(self._vars_output(base / folder / f"{name}.yml", normal, secret=False))
            elif secret:
                files.append(self._vars_output(base / folder / name / "vault.yml", secret, secret=True))
        return files

    def _vars_output(self, path: Path, variables: dict[str, object], *, secret: bool) -> OutputFile:
        header = [
            "# Loaded automatically from beside the inventory.",
            "# https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_inventory.html",
        ]
        return OutputFile(path, render_var_yaml(variables, header=header), secret)

    def write_flow(self) -> bool:
        self.encrypted = False
        if not self.inventory.hosts and not prompt_yes_no("The inventory has no hosts. Write it anyway?", False):
            return False
        layout_choice = prompt_choice(
            "Where should variables be stored?",
            [
                "In the inventory file",
                "In group_vars/ and host_vars/ next to the inventory",
            ],
            default=1,
        )
        layout = "inventory" if layout_choice == 1 else "dirs"
        secret_mode = "plaintext"
        if self.inventory.has_secrets():
            say("ansible_password and ansible_become_password are in this inventory. The inventory guide says never to store them in plain text. Use a vault, or do not store them and pass --ask-pass / --ask-become-pass instead.")
            secret_choice = prompt_choice(
                "Secrets",
                [
                    "Move secrets into group_vars/host_vars and encrypt those files with ansible-vault",
                    "Encrypt each whole file that contains a secret",
                    "Write the secrets in plain text",
                ],
                default=1,
            )
            secret_mode = {1: "extract", 2: "inline", 3: "plaintext"}[secret_choice]
            if self.output_format == "ini" and secret_mode == "inline":
                say("INI has no inline vault syntax. Encrypting the whole inventory still works: Ansible decrypts the file before parsing it. A readable INI file plus vaulted YAML group_vars is the layout the network inventory guide shows.")
        elif layout == "dirs":
            say("Host and group variable files must be YAML. They are loaded from beside the inventory file. ansible_group_priority, if you set it, stays in the inventory.")
        vault_password = ""
        if secret_mode in {"extract", "inline"}:
            say("The vault password encrypts secret files. It is not the SSH or become password, and it is not written down. You will type it again later as --vault-id LABEL@prompt.")
            self.vault_label = prompt("Vault identity label", default="dev")
            if not re.fullmatch(r"[A-Za-z0-9_]+", self.vault_label):
                print("  The label must be letters, numbers, and underscores. Using dev.")
                self.vault_label = "dev"
            vault_password = prompt_secret("Vault password")
            if vault_password:
                self.encrypted = True
            else:
                say("No vault password was entered. Secrets will be written in plain text.")
                secret_mode = "plaintext"
                self.encrypted = False
        files = self.build_outputs(layout, secret_mode)
        print()
        print("Files:")
        for item in files:
            marker = " secrets" if _content_has_secret(item.content) else ""
            print(f"  {item.path}{marker}")
        if any("[" in host.name for host in self.inventory.hosts.values()) and (layout == "dirs" or secret_mode == "extract"):
            say("Variables on a host range stay in the inventory. A host_vars file named after the pattern would not apply to the expanded hosts.")
        blocked = _path_problem(files)
        if blocked:
            print(blocked)
            print("Nothing was written.")
            return False
        if not prompt_yes_no("Write these files?", True):
            return False
        existing = [item.path for item in files if item.path.exists()]
        if existing:
            print("These paths already exist:")
            for path in existing:
                print(f"  {path}")
            if not prompt_yes_no("Overwrite them?", False):
                print("Nothing was written.")
                return False
        self._write_files(files)
        verified = self._verify()
        if vault_password:
            secret_files = [item.path for item in files if _content_has_secret(item.content)]
            if secret_files:
                self._encrypt(secret_files, vault_password)
        self._maybe_ansible_cfg()
        print()
        if verified:
            print("ansible-inventory accepted the inventory.")
        print(f"ansible-inventory -i {self.inventory_display()} --graph")
        print(f"ansible-playbook -i {self.inventory_display()} site.yml{self.command_suffix()}")
        if secret_mode == "plaintext" and self.inventory.has_secrets():
            say("Passwords are stored in plain text. Anyone who can read these files can use them. Encrypt them with ansible-vault when you can.")
        return True

    def _write_files(self, files: list[OutputFile]) -> None:
        for item in files:
            item.path.parent.mkdir(parents=True, exist_ok=True)
            write_text(item.path, item.content)
            if item.contains_secrets or _content_has_secret(item.content):
                os.chmod(item.path, 0o600)
            else:
                os.chmod(item.path, 0o644)

    def _verify(self) -> bool:
        program = shutil.which("ansible-inventory")
        if not program:
            say("ansible-inventory is not on PATH, so the file was not checked. Install Ansible and run the command printed below.")
            return False
        result = subprocess.run(
            [program, "-i", str(self.output_path), "--graph"],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(result.stderr.strip() or result.stdout.strip())
            say("Ansible could not parse the inventory. The files are still on disk so you can correct them.")
            return False
        if result.stderr.strip():
            print(result.stderr.strip())
        print(result.stdout.rstrip())
        return True

    def _encrypt(self, paths: list[Path], password: str) -> None:
        if not shutil.which("ansible-vault"):
            self.encrypted = False
            say("ansible-vault is not on PATH. The secret files are still plain text. Encrypt each one with:")
            for path in paths:
                print(f"  ansible-vault encrypt {path}")
            return
        fd, password_path = tempfile.mkstemp(prefix="ansible-vault-pass-")
        encrypted_any = False
        try:
            os.write(fd, password.encode("utf-8") + b"\n")
            os.close(fd)
            fd = -1
            os.chmod(password_path, 0o600)
            program = shutil.which("ansible-vault")
            assert program is not None
            for path in paths:
                result = subprocess.run(
                    [
                        program,
                        "encrypt",
                        "--vault-id",
                        f"{self.vault_label}@{password_path}",
                        "--encrypt-vault-id",
                        self.vault_label,
                        str(path),
                    ],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    print(result.stderr.strip() or result.stdout.strip())
                    say(f"Could not encrypt {path}. It is still plain text.")
                    continue
                os.chmod(path, 0o600)
                print(f"Encrypted {path}")
                encrypted_any = True
            if not encrypted_any:
                self.encrypted = False
        finally:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(password_path):
                os.remove(password_path)

    def _maybe_ansible_cfg(self) -> None:
        say("Host key checking is enabled by default. The connection guide lets you turn it off in ansible.cfg when rebuilt hosts make known_hosts prompts fail automation. That also disables a check against spoofed servers.")
        if not prompt_yes_no("Write ansible.cfg in the current directory for this inventory?", True):
            return
        config_path = Path.cwd() / "ansible.cfg"
        inventory_value = self.inventory_display()
        disable_keys = prompt_yes_no("Disable host_key_checking in that ansible.cfg?", False)
        block = ["[defaults]", f"inventory = {inventory_value}"]
        if disable_keys:
            block.append("# Host key checking was disabled while building this inventory.")
            block.append("host_key_checking = False")
        snippet = "\n".join(block) + "\n"
        if config_path.exists():
            say(f"{config_path} already exists, so it was left unchanged. Add this under [defaults] if inventory is not set:")
            print(f"inventory = {inventory_value}")
            if disable_keys:
                print("host_key_checking = False")
            return
        write_text(config_path, snippet)
        print(f"Wrote {config_path}")
        say("Ansible reads ./ansible.cfg when you run it from this directory.")


def _path_problem(files: list[OutputFile]) -> str | None:
    for item in files:
        if item.path.exists() and item.path.is_dir():
            return f"{item.path} is a directory, so it cannot be replaced with a file."
        if item.path.parent.exists() and item.path.parent.is_file():
            return f"{item.path.parent} is a file, so {item.path} cannot be written."
    return None


def _content_has_secret(content: str) -> bool:
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = stripped.split(":", 1)[0].split("=", 1)[0].strip()
        if is_secret_key(key):
            return True
    return False


def _dedupe_files(files: list[OutputFile]) -> list[OutputFile]:
    merged: dict[Path, OutputFile] = {}
    for item in files:
        if not item.content.strip() or item.content.strip() in {"---", "---\n"}:
            continue
        existing = merged.get(item.path)
        if existing is None:
            merged[item.path] = item
            continue
        existing.contains_secrets = existing.contains_secrets or item.contains_secrets
    return list(merged.values())


def run_self_test() -> int:
    _test_ranges()
    _test_names()
    _test_parsers()
    inventory = _sample_inventory()
    directory = Path(tempfile.mkdtemp(prefix="inventory-builder-", dir=Path.cwd()))
    local_tmp = directory / "local-tmp"
    local_tmp.mkdir()
    env = os.environ.copy()
    env["ANSIBLE_LOCAL_TEMP"] = str(local_tmp)
    try:
        yaml_path = directory / "inventory.yml"
        ini_path = directory / "inventory.ini"
        wizard = Wizard()
        wizard.inventory = inventory
        wizard.output_format = "yaml"
        wizard.output_path = yaml_path
        yaml_path.write_text(wizard.render_inventory_text(drop_secrets=False), encoding="utf-8")
        wizard.output_format = "ini"
        wizard.output_path = ini_path
        ini_path.write_text(wizard.render_inventory_text(drop_secrets=False), encoding="utf-8")
        yaml_data = _load_inventory(yaml_path, env)
        ini_data = _load_inventory(ini_path, env)
        for label, data in (("yaml", yaml_data), ("ini", ini_data)):
            web_hosts = set(data["webservers"]["hosts"])
            if web_hosts != {"foo.example.com", "www01.example.com", "www02.example.com"}:
                raise AssertionError(f"{label} webservers hosts: {web_hosts}")
            if set(data["prod"]["children"]) != {"webservers", "dbservers"}:
                raise AssertionError(f"{label} prod children: {data['prod']}")
            if "bar.example.com" not in data["dbservers"]["hosts"]:
                raise AssertionError(f"{label} missing bar in dbservers")
            if "mail.example.com" not in data.get("ungrouped", {}).get("hosts", []):
                raise AssertionError(f"{label} missing ungrouped mail host")
            foo = data["_meta"]["hostvars"]["foo.example.com"]
            if foo["ansible_user"] != "deploy" or foo["ansible_port"] != 2222 or foo["http_port"] != 80:
                raise AssertionError(f"{label} foo vars: {foo}")
            if foo["ansible_become"] is not True:
                raise AssertionError(f"{label} become was not boolean: {foo['ansible_become']!r}")
            leaf = data["_meta"]["hostvars"]["leaf01"]
            if leaf["ansible_network_os"] != "vyos.vyos.vyos":
                raise AssertionError(f"{label} network os: {leaf}")
            if data["_meta"]["hostvars"]["win01"]["ansible_password"] != "1234":
                raise AssertionError(f"{label} numeric password was not kept as a string")
        print("ansible-inventory accepted the YAML and INI samples.")
        _test_vault_roundtrip(directory, env)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    print("Self-test passed.")
    return 0


def _sample_inventory() -> Inventory:
    inventory = Inventory()
    inventory.all_variables = {
        "ansible_user": "deploy",
        "ansible_become": True,
        "ansible_become_method": "sudo",
        "ansible_become_user": "root",
    }
    inventory.add_group("webservers")
    inventory.add_group("dbservers")
    inventory.add_group("prod")
    inventory.add_group("network")
    inventory.add_group("windows")
    inventory.link("webservers", "prod")
    inventory.link("dbservers", "prod")
    inventory.groups["webservers"].variables["http_port"] = 80
    inventory.groups["prod"].priority = 10
    inventory.groups["network"].variables.update(
        {
            "ansible_connection": "ansible.netcommon.network_cli",
            "ansible_network_os": "vyos.vyos.vyos",
            "ansible_user": "netops",
        }
    )
    inventory.groups["windows"].variables.update(
        {
            "ansible_connection": "ansible.builtin.winrm",
            "ansible_port": 5986,
            "ansible_winrm_scheme": "https",
            "ansible_user": "Administrator",
        }
    )
    inventory.hosts["foo.example.com"] = Host(
        "foo.example.com",
        ["webservers"],
        {"ansible_host": "192.0.2.10", "ansible_port": 2222},
    )
    inventory.hosts["www[01:02].example.com"] = Host("www[01:02].example.com", ["webservers"], {})
    inventory.hosts["bar.example.com"] = Host("bar.example.com", ["dbservers"], {})
    inventory.hosts["mail.example.com"] = Host("mail.example.com", [], {})
    inventory.hosts["leaf01"] = Host("leaf01", ["network"], {"ansible_host": "10.16.10.11"})
    inventory.hosts["win01"] = Host("win01", ["windows"], {"ansible_host": "192.0.2.20", "ansible_password": "1234"})
    return inventory


def _load_inventory(path: Path, env: dict[str, str]) -> dict:
    program = shutil.which("ansible-inventory")
    if not program:
        raise AssertionError("ansible-inventory is required for --self-test")
    result = subprocess.run(
        [program, "-i", str(path), "--list"],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.strip() or result.stdout.strip())
    return json.loads(result.stdout)


def _test_vault_roundtrip(directory: Path, env: dict[str, str]) -> None:
    program = shutil.which("ansible-vault")
    if not program:
        print("ansible-vault is not installed; skipped the vault round trip.")
        return
    inventory = Inventory()
    inventory.add_group("vyos")
    inventory.groups["vyos"].variables.update(
        {
            "ansible_connection": "ansible.netcommon.network_cli",
            "ansible_network_os": "vyos.vyos.vyos",
            "ansible_user": "netops",
            "ansible_password": "VyOS_SSH_password",
        }
    )
    inventory.hosts["leaf01"] = Host("leaf01", ["vyos"], {"ansible_host": "10.16.10.11"})
    wizard = Wizard()
    wizard.inventory = inventory
    wizard.output_format = "yaml"
    wizard.output_path = directory / "vault-inventory.yml"
    files = wizard.build_outputs("inventory", "extract")
    for item in files:
        item.path.parent.mkdir(parents=True, exist_ok=True)
        item.path.write_text(item.content, encoding="utf-8")
    password_file = directory / "vault-pass"
    password_file.write_text("test-vault-password\n", encoding="utf-8")
    os.chmod(password_file, 0o600)
    secret_files = [item.path for item in files if item.contains_secrets]
    if not secret_files:
        raise AssertionError("extract mode did not produce a secret file")
    for path in secret_files:
        result = subprocess.run(
            [program, "encrypt", "--vault-id", f"dev@{password_file}", "--encrypt-vault-id", "dev", str(path)],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or "vault encrypt failed")
    loaded = subprocess.run(
        [
            shutil.which("ansible-inventory") or "ansible-inventory",
            "-i",
            str(wizard.output_path),
            "--list",
            "--vault-id",
            f"dev@{password_file}",
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
    )
    if loaded.returncode != 0:
        raise AssertionError(loaded.stderr.strip() or loaded.stdout.strip())
    data = json.loads(loaded.stdout)
    if data["_meta"]["hostvars"]["leaf01"]["ansible_password"] != "VyOS_SSH_password":
        raise AssertionError("vaulted ansible_password did not decrypt")
    inventory_text = wizard.output_path.read_text(encoding="utf-8")
    if "VyOS_SSH_password" in inventory_text:
        raise AssertionError("the inventory file still contains the plaintext password")
    print("ansible-vault round trip passed.")


def _test_ranges() -> None:
    if expand_hostname_range("www[01:04].example.com") != [
        "www01.example.com",
        "www02.example.com",
        "www03.example.com",
        "www04.example.com",
    ]:
        raise AssertionError("zero-padded range mismatch")
    if expand_hostname_range("www[01:04:2].example.com") != ["www01.example.com", "www03.example.com"]:
        raise AssertionError("stride range mismatch")
    if expand_hostname_range("db-[a:c].example.com") != [
        "db-a.example.com",
        "db-b.example.com",
        "db-c.example.com",
    ]:
        raise AssertionError("alpha range mismatch")
    if expand_hostname_range("a[1:2]b[1:2]") != ["a1b1", "a1b2", "a2b1", "a2b2"]:
        raise AssertionError("multiple range mismatch")
    try:
        expand_hostname_range("www[01:3].example.com")
    except ValueError:
        pass
    else:
        raise AssertionError("unequal zero-padded range should fail")


def _test_names() -> None:
    if group_name_error("web-servers") is None:
        raise AssertionError("hyphenated group names should be rejected")
    if group_name_error("all") is None or group_name_error("ungrouped") is None:
        raise AssertionError("implicit groups should be rejected")
    if variable_name_error("http_port") is not None:
        raise AssertionError("http_port should be valid")
    if variable_name_error("name") is None:
        raise AssertionError("name is reserved")
    inventory = Inventory()
    inventory.add_group("east")
    inventory.add_group("prod")
    inventory.link("east", "prod")
    try:
        inventory.link("prod", "east")
    except ValueError:
        pass
    else:
        raise AssertionError("cycle was accepted")


def _test_parsers() -> None:
    specs = parse_host_line("badwolf.example.com:5309", expand_ranges=False)
    if specs != [("badwolf.example.com", {"ansible_port": 5309})]:
        raise AssertionError(f"port shorthand failed: {specs}")
    specs = parse_host_line("jumper ansible_host=192.0.2.50 ansible_port=5555", expand_ranges=False)
    if specs[0][0] != "jumper" or specs[0][1]["ansible_host"] != "192.0.2.50" or specs[0][1]["ansible_port"] != 5555:
        raise AssertionError(f"alias line failed: {specs}")
    specs = parse_host_line("www[01:02].example.com=10.0.0.[5:6]", expand_ranges=False)
    if [item[0] for item in specs] != ["www01.example.com", "www02.example.com"]:
        raise AssertionError(f"zipped range failed: {specs}")
    if [item[1]["ansible_host"] for item in specs] != ["10.0.0.5", "10.0.0.6"]:
        raise AssertionError(f"zipped addresses failed: {specs}")
    rendered = ini_host_assignment("ansible_password", "1234")
    token = shlex.split("win01 " + rendered)[1]
    parsed = ast.literal_eval(token.split("=", 1)[1])
    if parsed != "1234":
        raise AssertionError("numeric secrets must stay strings in INI host lines")
    vars_line = ini_vars_assignment("ansible_password", "1234")
    if ast.literal_eval(vars_line.split("=", 1)[1]) != "1234":
        raise AssertionError("numeric secrets must stay strings in INI group vars")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ask for hosts, groups, usernames, and connection settings, then write an Ansible inventory.",
        epilog=f"Inventory guide: {DOCS}",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Build sample YAML and INI inventories and check them with ansible-inventory.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        try:
            return run_self_test()
        except (AssertionError, OSError, subprocess.SubprocessError) as exc:
            print(f"Self-test failed: {exc}", file=sys.stderr)
            return 1
    wizard = Wizard()
    try:
        wizard.welcome()
        wizard.configure_output()
        wizard.configure_defaults()
        wizard.group_loop()
        wizard.host_loop()
        wizard.review_loop()
    except Cancelled as exc:
        print(exc)
        print("No files were written.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())