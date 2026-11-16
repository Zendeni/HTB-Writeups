# Security Lab Writeups

Technical walkthroughs and working notes from machines, challenges, and lab environments. Each target has its own directory so its writeup, helper scripts, payloads, and reproduction notes stay together.

## Clone the repository

```bash
git clone https://github.com/Zendeni/HTB-Writeups.git
cd HTB-Writeups
```

## Browse by platform

| Collection | Contents |
| --- | --- |
| [Hack The Box machines](Machines/HackTheBox/README.md) | Standalone HTB machine writeups, including the complete Odyssey reproduction bundle |
| [VulnLab machines](Machines/VulnLab/README.md) | Active Directory and standalone VulnLab machine notes |
| [Challenges](Challenges/README.md) | Web and application challenges |
| [Pro Labs](Pro-Labs/README.md) | Multi-host lab walkthroughs |

## Repository layout

```text
HTB-Writeups/
├── Machines/
│   ├── HackTheBox/<Machine>/README.md
│   └── VulnLab/<Machine>/README.md
├── Challenges/<Challenge>/README.md
└── Pro-Labs/<Lab>/README.md
```

Companion files live beside the writeup that uses them. For example:

- [Odyssey](Machines/HackTheBox/Odyssey/README.md) includes scripts, source payloads, runtime directories, and [reproduction requirements](Machines/HackTheBox/Odyssey/REPRODUCTION.md).
- [Optimum](Machines/HackTheBox/Optimum/README.md) includes its HFS exploit helper.

Target addresses, session tokens, and other runtime values can change after a reset. Start in the target's directory, read its setup section, and create generated output only in the paths documented there.

## Publication note

Platform rules can change. Confirm that content is officially eligible for public writeups before publishing or sharing it; an expired machine is not necessarily retired.
