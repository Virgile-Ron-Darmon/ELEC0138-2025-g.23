# ELEC0138-2025-g.23
Code submission from Group 23 for the ELEC0138: Security & Privacy Coursework.

## Repository Structure
```text
ELEC0138-2025-g.23/
├── attacks/
│   ├── arp.sh
│   ├── arpflood_tool.py
│   ├── ssh.sh
│   ├── syn.sh
│   ├── synflood_tool.py
│   └── teessh.py
├── router_code/
│   ├── config.yaml
│   ├── main.py
│   ├── SP_Log.log
│   └── src/
│       ├── controller.py
│       ├── net_manager/
│       │   ├── arp_protection.py
│       │   ├── buffer.py
│       │   ├── filter.py
│       │   ├── intra_sys_coms.py
│       │   └── rules.py
│       ├── route_setup/
│       │   ├── route_edit.sh
│       │   ├── route_setup.py
│       │   └── route_setup.sh
│       └── tools/
│           └── logger.py
└── README.md
```
## Dependencies

- **Python** 3.7+  
- **scapy**  
- **pexpect**  
- **netifaces**  
- **pyyaml**

Install with pip:

```bash
pip install scapy pexpect netifaces pyyaml
```
## Setup Virtual Environment
### Using Conda:

```bash
conda create -n elec0138 python=3.8
conda activate elec0138
pip install scapy pexpect netifaces pyyaml
```

## Group Members
- Virgile Darmon
- Jiasheng Tee
- Nikhil Babani
- Xiaochen Sang

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for the full text.