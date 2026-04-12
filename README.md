# packet-tracer-skill

Cisco Packet Tracer 9.x `.pkt` generator and editor for skill-based coding hosts.

Bu repo skill esasli coding host-lar ucun Cisco Packet Tracer 9.x `.pkt`
generatoru ve editorudur.

---

## English

### Overview

This repository is built for one specific job: take a natural-language network
request, plan it explicitly, adapt a compatible local Cisco Packet Tracer donor
lab, and produce a `.pkt` file that opens cleanly in Packet Tracer 9.x.

Design defaults:

- Cisco local samples are the primary donor source
- external labs are reference-only
- prompt parsing happens before generation
- generation uses donor-prune adaptation for compatibility
- unsafe requests return `blocking_gaps` instead of guessed output

### Host Support

Use the same repository, then install it into the skill path your host expects.

| Tool | Install | First Use |
| --- | --- | --- |
| Claude Code | `npx github:20hajiyev/packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx github:20hajiyev/packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx github:20hajiyev/packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx github:20hajiyev/packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx github:20hajiyev/packet-tracer-skill --path <antigravity-skills-dir>` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | Copy this repo into your local prompts/rules/skills docs | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx github:20hajiyev/packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx github:20hajiyev/packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx github:20hajiyev/packet-tracer-skill --path ./my-skills` | Depends on your tool |

### Quick Start

Default install for Codex:

```powershell
npx github:20hajiyev/packet-tracer-skill
```

Common targets:

```powershell
npx github:20hajiyev/packet-tracer-skill --cursor
npx github:20hajiyev/packet-tracer-skill --claude
npx github:20hajiyev/packet-tracer-skill --kiro
```

If you publish this package to npm later, the same commands become:

```powershell
npx packet-tracer-skill
npx packet-tracer-skill --cursor
```

If PowerShell blocks `npx.ps1`, use:

```powershell
cmd /c npx github:20hajiyev/packet-tracer-skill --cursor
```

If you want the local development setup instead:

```powershell
git clone https://github.com/20hajiyev/packet-tracer-skill.git
cd .\packet-tracer-skill
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

### Verify the Install

Check that the skill was installed into the expected target path:

```powershell
npx github:20hajiyev/packet-tracer-skill --verify
npx github:20hajiyev/packet-tracer-skill --verify --cursor
npx github:20hajiyev/packet-tracer-skill --verify --path .agents/skills
```

From a local clone:

```powershell
node .\bin\packet-tracer-skill.js --verify
python .\scripts\install_skill.py --host codex --force
```

### Runtime Configuration

Set the local Packet Tracer environment before real `.pkt` generation:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\labs\campus_donor_9_0.pkt'
$env:PKT_TWOFISH_LIBRARY='C:\tools\pkt-twofish\_twofish.cp314-win_amd64.pyd'
```

Important variables:

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`

### What This Repo Does

- Parses hybrid Azerbaijani + English prompts
- Builds explicit `IntentPlan`, `TopologyPlan`, and `ConfigPlan`
- Ranks Cisco local donors by capability and topology fit
- Uses donor-prune adaptation for Packet Tracer 9.x compatibility
- Edits existing `.pkt` labs
- Supports VLAN, router-on-a-stick, DHCP, DNS, Telnet, ACL, wireless/AP-client, and department/campus layouts
- Explains the plan before generation with `--explain-plan`

### Explain-Plan Output

`--explain-plan` reports:

- `intent_plan`
- `topology_plan`
- `config_plan`
- `estimate_plan`
- `preflight_validation`
- `autofix_summary`
- `validation_report`
- `cisco_sample_candidates`
- `external_reference_patterns`
- `assumptions_used`

This is the main debugging surface for prompt quality.

### External Reference Workflow

External `.pkt` collections must be local first. This tool does not scrape the
internet and does not use GitHub URLs directly as donors.

Workflow:

1. clone or copy the external repo locally
2. pass that folder with `--reference-root`
3. inspect `external_reference_patterns` in `--explain-plan`

Example:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 sobeli sebeke qur, her sobede 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --reference-root C:\labs\external-pkt-samples
```

### Common Commands

Build the Cisco sample catalog:

```powershell
python .\scripts\build_sample_catalog.py
```

Explain a simple prompt:

```powershell
python .\scripts\generate_pkt.py --explain-plan "3 dene switch ve 6 komputer"
```

Explain a donor-prune campus prompt:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 sobeli sebeke qur, her sobede 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerden verilsin, management VLAN ve telnet olsun"
```

Generate a `.pkt`:

```powershell
python .\scripts\generate_pkt.py --prompt "6 sobeli sebeke qur, her sobede 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerden verilsin, management VLAN ve telnet olsun" --output .\output\campus.pkt --xml-out .\output\campus.xml
```

Inspect an existing `.pkt`:

```powershell
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt
```

Decode a `.pkt`:

```powershell
python .\scripts\generate_pkt.py --decode .\output\campus.pkt --xml-out .\output\campus.xml
```

### Requirements

- Windows
- Cisco Packet Tracer 9.x installed locally
- local Cisco Packet Tracer sample saves
- a local Packet Tracer 9.x donor lab
- a local Twofish bridge compatible with your Python runtime

Python setup:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

### Twofish Bridge

This public repo does not ship a prebuilt Twofish bridge binary by default.

That is intentional:

- no machine-specific binary is committed by default
- no unsigned local artifact is published by accident
- no private path or build residue is shared by default

Read `scripts/vendor/README.md` for local setup.

### Screenshot

Generated campus topology opened in Cisco Packet Tracer:

![Packet Tracer topology](docs/screenshots/packet-tracer-topology-cropped.png)

### Security and Privacy

This repo is prepared to avoid accidental sharing of local private material:

- no hardcoded donor path is committed
- no `C:\Users\<name>\...` donor path is baked into config
- generated `.pkt` and `.xml` files are gitignored
- Python cache files are gitignored
- Twofish bridge binaries are gitignored

Before publishing:

- verify your own `PACKET_TRACER_COMPAT_DONOR` path is local-only
- do not commit generated labs unless you intend to share them
- do not commit locally built bridge binaries unless you reviewed them

### Current Limitations

- Packet Tracer 9.x only
- Windows-first workflow
- donor-prune generation is bounded by donor capacity
- external labs are not donors by default
- bundled template coverage is intentionally limited

### License

This project is licensed under the MIT License.

---

## Azerbaycanca

### Umumi baxis

Bu repository bir konkret is ucun qurulub: tebii dilde yazilmis sebeke
isteyini basa dusmek, onu aciq plan sekline salmaq, lokal Cisco Packet Tracer
donor labini uygunlasdirmaq ve Packet Tracer 9.x-de acilan `.pkt` fayli
cixarmaq.

Esas prinsipler:

- Cisco-nun lokal sample-lari esas donor menbeyidir
- xarici lab-lar yalniz reference kimi istifade olunur
- prompt evvel parse olunur, sonra generate edilir
- uygunluq ucun donor-prune yanasmasi istifade olunur
- natamam istekler ucun uydurma netice yox, `blocking_gaps` qaytarilir

### Host desteyi

Eyni repository istifade olunur, sadece host-un gozlediyi skill yoluna
qurasdirilir.

| Alet | Qurasdirma | Ilk istifade |
| --- | --- | --- |
| Claude Code | `npx github:20hajiyev/packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx github:20hajiyev/packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx github:20hajiyev/packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx github:20hajiyev/packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx github:20hajiyev/packet-tracer-skill --path <antigravity-skills-dir>` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | Bu repo-nu lokal prompts/rules/skills docs qovluguna kocur | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx github:20hajiyev/packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx github:20hajiyev/packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx github:20hajiyev/packet-tracer-skill --path ./my-skills` | Host-a gore deyisir |

### Suretli baslangic

Codex ucun default qurasdirma:

```powershell
npx github:20hajiyev/packet-tracer-skill
```

Tez-tez lazim olan diger variantlar:

```powershell
npx github:20hajiyev/packet-tracer-skill --cursor
npx github:20hajiyev/packet-tracer-skill --claude
npx github:20hajiyev/packet-tracer-skill --kiro
```

Eger gelecekde paket npm-e publish olunsa, eyni komandalar bele olacaq:

```powershell
npx packet-tracer-skill
npx packet-tracer-skill --cursor
```

Eger PowerShell `npx.ps1` faylini bloklayirsa:

```powershell
cmd /c npx github:20hajiyev/packet-tracer-skill --cursor
```

Eger repo uzerinde lokal development qurmaq isteyirsen:

```powershell
git clone https://github.com/20hajiyev/packet-tracer-skill.git
cd .\packet-tracer-skill
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

### Qurasdirmayi yoxlama

Skill-in gozlenilen host yoluna yazildigini yoxlamaq ucun:

```powershell
npx github:20hajiyev/packet-tracer-skill --verify
npx github:20hajiyev/packet-tracer-skill --verify --cursor
npx github:20hajiyev/packet-tracer-skill --verify --path .agents/skills
```

Eger lokal clone ile isleyirsen:

```powershell
node .\bin\packet-tracer-skill.js --verify
python .\scripts\install_skill.py --host codex --force
```

### Runtime konfiqurasiyasi

Real `.pkt` generate etmezden evvel lokal Packet Tracer muhitini qur:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\labs\campus_donor_9_0.pkt'
$env:PKT_TWOFISH_LIBRARY='C:\tools\pkt-twofish\_twofish.cp314-win_amd64.pyd'
```

Esas environment deyisenleri:

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`

### Bu repo ne edir

- Azerbaycan dili + Ingilis dili qarisik prompt-lari parse edir
- aciq `IntentPlan`, `TopologyPlan` ve `ConfigPlan` qurur
- Cisco lokal donorlarini capability ve topology uygunluguna gore siralayir
- Packet Tracer 9.x uygunlugu ucun donor-prune adaptasiyasi istifade edir
- movcud `.pkt` lab-lari edit edir
- VLAN, router-on-a-stick, DHCP, DNS, Telnet, ACL, wireless/AP-client ve department/campus layout-larini destekleyir
- generate-den evvel plani `--explain-plan` ile gosterir

### Explain-plan cixisi

`--explain-plan` asagidaki bloklari qaytarir:

- `intent_plan`
- `topology_plan`
- `config_plan`
- `estimate_plan`
- `preflight_validation`
- `autofix_summary`
- `validation_report`
- `cisco_sample_candidates`
- `external_reference_patterns`
- `assumptions_used`

Bu, prompt keyfiyyetini debug etmek ucun esas cixisdir.

### Xarici reference workflow

Xarici `.pkt` kolleksiyalari evvelce lokal qovluqda olmalidir. Tool internetden
scrape etmir ve GitHub URL-lerini birbasa donor kimi istifade etmir.

Workflow:

1. xarici repo-nu lokalda klonla ve ya kopyala
2. hemin qovlugu `--reference-root` ile ver
3. `--explain-plan` neticesinde `external_reference_patterns`-e bax

Numune:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 sobeli sebeke qur, her sobede 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --reference-root C:\labs\external-pkt-samples
```

### Tez-tez istifade olunan komandalar

Cisco sample catalog qurmaq:

```powershell
python .\scripts\build_sample_catalog.py
```

Sade prompt ucun explain-plan:

```powershell
python .\scripts\generate_pkt.py --explain-plan "3 dene switch ve 6 komputer"
```

Campus prompt ucun donor-prune explain-plan:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 sobeli sebeke qur, her sobede 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerden verilsin, management VLAN ve telnet olsun"
```

`.pkt` yaratmaq:

```powershell
python .\scripts\generate_pkt.py --prompt "6 sobeli sebeke qur, her sobede 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerden verilsin, management VLAN ve telnet olsun" --output .\output\campus.pkt --xml-out .\output\campus.xml
```

Movcud `.pkt` haqqinda inventory cixarmaq:

```powershell
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt
```

`.pkt` decode etmek:

```powershell
python .\scripts\generate_pkt.py --decode .\output\campus.pkt --xml-out .\output\campus.xml
```

### Telebler

- Windows
- lokalda qurasdirilmis Cisco Packet Tracer 9.x
- lokal Cisco Packet Tracer sample save-leri
- lokal Packet Tracer 9.x donor labi
- Python runtime ile uygun lokal Twofish bridge

Python setup:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

### Twofish bridge

Bu public repo default olaraq prebuilt Twofish binary ile gelmir.

Bu qesdendir:

- machine-specific binary paylasilmir
- unsigned lokal artefakt tesadufen publish olunmur
- private path ve build izi paylasilmir

Lokal setup ucun `scripts/vendor/README.md` faylina bax.

### Screenshot

Cisco Packet Tracer-de acilmis generated campus topology:

![Packet Tracer topology](docs/screenshots/packet-tracer-topology-cropped.png)

### Tehlukesizlik ve mexfilik

Repo lokal private melumatlarin tesadufen paylasilmamasi ucun hazirlanib:

- hardcoded donor path commit olunmur
- `C:\Users\<name>\...` donor path config-e yazilmir
- generated `.pkt` ve `.xml` fayllari gitignore-dadir
- Python cache fayllari gitignore-dadir
- Twofish bridge binary-leri gitignore-dadir

Public paylasmazdan evvel bunlari yoxla:

- `PACKET_TRACER_COMPAT_DONOR` yalniz senin lokal env-ində olsun
- paylasmaq istemediyin generated lab-lari commit etme
- build etdiyin bridge binary-ni audit etmemisense commit etme

### Cari limitler

- yalniz Packet Tracer 9.x
- Windows-first workflow
- donor-prune generate donor capacity ile mehduddur
- xarici lab-lar donor kimi istifade olunmur
- bundled template coverage qesden limitlidir

### Lisenziya

Bu layihe MIT License ile paylasilir.
