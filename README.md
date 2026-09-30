# Ansible Inventory Builder

An interactive Python script that asks for hosts, groups, users, and connection settings, then writes a static Ansible inventory.

The questions follow the [Ansible inventory guide](https://docs.ansible.com/projects/ansible/latest/inventory_guide/index.html): YAML or INI inventories, parent and child groups, host aliases, host ranges, and behavioral connection variables such as `ansible_user`, `ansible_port`, and `ansible_become`.

## Requirements

- Python 3.9 or newer
- [Ansible](https://docs.ansible.com/projects/ansible/latest/installation_guide/index.html), optional, for `ansible-inventory` checks and `ansible-vault` encryption

The script uses only the Python standard library.

## Run it

```bash
python3 build_inventory.py
```

Press Enter to accept a value shown in `[brackets]`. Press Ctrl+C to stop. Nothing is written until you confirm the file list.

Check the generators without answering the prompts:

```bash
python3 build_inventory.py --self-test
```

`--self-test` needs `ansible-inventory` on your `PATH`. It also runs an `ansible-vault` round trip when `ansible-vault` is installed.

## What it asks

1. **Output.** YAML (default) or INI, and the output path. Separate files such as `inventory_test.yml` and `inventory_staging.yml` keep environments apart.
2. **Defaults for all hosts.** SSH, Paramiko, WinRM, `ansible.netcommon.network_cli`, local, or another connection plugin. Optional remote user, private key or password, port, privilege escalation, jump host, and Python interpreter.
3. **Groups.** Names use letters, numbers, and underscores. You can link parent and child groups, set `ansible_group_priority`, and add variables such as `http_port` or `ntp_server`.
4. **Hosts.** One name per line, `alias ansible_host=192.0.2.10`, `host:port`, or a range such as `www[01:50].example.com`. A host can belong to more than one group.
5. **Review.** Add more groups or hosts, then write the files. Ansible's variable order is host, then child group, then parent group, then `all`.

## What it writes

Variables can stay in the inventory file, or go in `group_vars/` and `host_vars/` next to it. `ansible_group_priority` always stays in the inventory file. Ansible does not read that setting from `group_vars`.

Host ranges stay in the inventory. Ansible expands patterns such as `www[01:02].example.com` when it loads the file. A `host_vars` file named after the pattern would not apply to `www01` and `www02`.

You can also write an `ansible.cfg` in the current directory that sets `inventory` to the new file. Host key checking stays enabled unless you turn it off there.

Check the result:

```bash
ansible-inventory -i inventory.yml --graph
ansible-playbook -i inventory.yml site.yml
```

## Passwords

Ansible's inventory guide says not to store `ansible_password` or `ansible_become_password` in plain text. The script offers three choices:

- Leave the password out and pass `--ask-pass` or `--ask-become-pass` at runtime.
- Move secrets into `group_vars/` or `host_vars/` and encrypt those files with `ansible-vault`.
- Encrypt each whole file that contains a secret.

The vault password is not the SSH password, and the script does not save it. When a file is encrypted, run playbooks with `--vault-id LABEL@prompt`.

INI inventory has no inline vault syntax. A readable INI file plus vaulted YAML variable files is the layout that works for that format. Encrypting the whole INI file also works, because Ansible decrypts it before parsing.

## Further reading

- [How to build your inventory](https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_inventory.html)
- [Connection methods and details](https://docs.ansible.com/projects/ansible/latest/inventory_guide/connection_details.html)
- [Ansible Vault](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault.html)