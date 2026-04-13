# packet-tracer-skill 

Cisco Packet Tracer 9.x `.pkt` generator and editor for skill-based coding hosts.

Bu repository skill əsaslı coding host-lar üçün Cisco Packet Tracer 9.x `.pkt`
generatoru və editorudur.

<table>
  <tr>
    <td>
      <strong>Choose your language / Dilinizi seçin</strong><br />
      <a href="#english">🇬🇧 English</a>
      &nbsp;|&nbsp;
      <a href="#azerbaycan-dili">🇦🇿 Azərbaycan dili</a>
    </td>
  </tr>
</table>

---

<a id="english"></a>
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
| Claude Desktop | `npx github:20hajiyev/packet-tracer-skill --path <claude-desktop-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
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

That already installs everything shipped inside this repository.

If you want one command that installs everything this repository can install by
itself, use bootstrap:

```powershell
npx github:20hajiyev/packet-tracer-skill --bootstrap
```

That command:

- installs the skill into the selected host path
- creates a local `.venv` inside the installed skill directory
- installs declared Python requirements from this repository

It still does not install Cisco Packet Tracer itself.

Common targets:

```powershell
npx github:20hajiyev/packet-tracer-skill --path <claude-desktop-skills-dir>
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

### Check Runtime Requirements

Repository install and runtime readiness are different things.

- `install` copies the skill files
- `doctor` checks system prerequisites for real `.pkt` generation

Run:

```powershell
npx github:20hajiyev/packet-tracer-skill --doctor
```

It checks:

- `node`
- `python`
- `python_version`
- `python_support_status`
- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_TARGET_VERSION`
- `PACKET_TRACER_COMPAT_DONOR`
- donor version compatibility with the target Packet Tracer version
- `resolved_twofish_path`
- `twofish_load_status`
- `twofish_sha256`

### Runtime Configuration

Set the local Packet Tracer environment before real `.pkt` generation:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\path\to\your-working-9.0-donor.pkt'
$env:PKT_TWOFISH_LIBRARY="$env:USERPROFILE\.codex\skills\pkt\scripts\vendor\_twofish.cp314-win_amd64.pyd"
```

Important variables:

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`

Donor policy:

- `PACKET_TRACER_COMPAT_DONOR` is an explicit override
- if it is not set, the repo tries to auto-detect a local Packet Tracer 9.0 donor from common local locations
- if it is set and wrong, the repo does not silently fall back to another donor

Required policy:

- keep `PACKET_TRACER_TARGET_VERSION` on `9.0.0.0810`
- do not switch the target version to `5.3.0.0011`
- do not use a legacy `5.3` donor or template fallback to bypass strict 9.0 generation
- if the donor is missing or version-mismatched, stop and fix the donor instead of downgrading the workflow

Host note:

- the host process must inherit the same `PACKET_TRACER_*` and `PKT_TWOFISH_LIBRARY` environment variables
- this applies to every host equally: Codex, Cursor, Claude Code, Claude Desktop, Antigravity, Gemini CLI, Kiro, and similar tools
- if a host wrapper blocks child-process inspection, run `python .\scripts\donor_diagnostics.py` from a local clone to verify the donor directly

Where to place the Twofish binary:

- preferred: put `_twofish.cp314-win_amd64.pyd` next to `scripts/vendor/twofish.py` inside the installed skill folder
- override: set `PKT_TWOFISH_LIBRARY` to the exact local binary path
- do not point `PKT_TWOFISH_LIBRARY` at a placeholder path such as `C:\tools\pkt-twofish\...` unless that file actually exists

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
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --reference-root C:\labs\external-pkt-samples
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
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun"
```

Generate a `.pkt`:

```powershell
python .\scripts\generate_pkt.py --prompt "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun" --output .\output\campus.pkt --xml-out .\output\campus.xml
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

Runtime policy:

- supported Python runtime: `3.14.x` only
- the current bridge filename is ABI-specific: `_twofish.cp314-win_amd64.pyd`
- if you use Python `3.12`, `3.13`, `3.15`, or another ABI-incompatible build, `doctor` should report the runtime as unsupported

Read `scripts/vendor/README.md` for local setup.

### Common Failures

- `PACKET_TRACER_COMPAT_DONOR set but missing`
  - the configured donor path does not exist
  - fix the path or unset it and let the repo auto-detect a donor
- `PACKET_TRACER_COMPAT_DONOR_VERSION version_mismatch`
  - the donor exists, but it is not a `9.0.0.0810` file
  - do not downgrade to `5.3.0.0011`
- `TWOFISH_LOAD_STATUS missing`
  - no local bridge was found
  - put `_twofish.cp314-win_amd64.pyd` next to `scripts/vendor/twofish.py` or set `PKT_TWOFISH_LIBRARY`
- `PYTHON_SUPPORT_STATUS unsupported`
  - your runtime is not Python `3.14.x`
  - install Python 3.14 and rerun `--doctor`

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

<a id="azerbaycan-dili"></a>
## Azərbaycan dili

### Ümumi baxış

Bu repository bir konkret iş üçün qurulub: təbii dildə yazılmış şəbəkə
istəyini başa düşmək, onu açıq plan şəklinə salmaq, lokal Cisco Packet Tracer
donor labını uyğunlaşdırmaq və Packet Tracer 9.x-də açılan `.pkt` faylı
yaratmaq.

Əsas prinsiplər:

- Cisco-nun lokal sample-ları əsas donor mənbəyidir
- xarici lab-lar yalnız reference kimi istifadə olunur
- prompt əvvəl parse olunur, sonra generate edilir
- uyğunluq üçün donor-prune yanaşması istifadə olunur
- natamam istəklər üçün uydurma nəticə yox, `blocking_gaps` qaytarılır

### Host dəstəyi

Eyni repository istifadə olunur, sadəcə host-un gözlədiyi skill yoluna
quraşdırılır.

| Alət | Quraşdırma | İlk istifadə |
| --- | --- | --- |
| Claude Code | `npx github:20hajiyev/packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Claude Desktop | `npx github:20hajiyev/packet-tracer-skill --path <claude-desktop-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx github:20hajiyev/packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx github:20hajiyev/packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx github:20hajiyev/packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx github:20hajiyev/packet-tracer-skill --path <antigravity-skills-dir>` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | Bu repo-nu lokal prompts/rules/skills docs qovluğuna köçür | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx github:20hajiyev/packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx github:20hajiyev/packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx github:20hajiyev/packet-tracer-skill --path ./my-skills` | Host-a görə dəyişir |

### Sürətli başlanğıc

Codex üçün standart quraşdırma:

```powershell
npx github:20hajiyev/packet-tracer-skill
```

Bu komanda repository daxilində olan bütün faylları quraşdırır.

Əgər repository-nin quraşdıra bildiyi hər şeyi bir komandada qurmaq
istəyirsənsə, `bootstrap` istifadə et:

```powershell
npx github:20hajiyev/packet-tracer-skill --bootstrap
```

Bu komanda:

- skill-i seçilmiş host yoluna quraşdırır
- quraşdırılmış skill qovluğunda lokal `.venv` yaradır
- repository-də elan edilmiş Python tələblərini quraşdırır

Amma Cisco Packet Tracer-in özünü quraşdırmır.

Tez-tez lazım olan digər variantlar:

```powershell
npx github:20hajiyev/packet-tracer-skill --path <claude-desktop-skills-dir>
npx github:20hajiyev/packet-tracer-skill --cursor
npx github:20hajiyev/packet-tracer-skill --claude
npx github:20hajiyev/packet-tracer-skill --kiro
```

Əgər gələcəkdə paket npm-ə publish olunsa, eyni komandalar belə olacaq:

```powershell
npx packet-tracer-skill
npx packet-tracer-skill --cursor
```

Əgər PowerShell `npx.ps1` faylını bloklayırsa:

```powershell
cmd /c npx github:20hajiyev/packet-tracer-skill --cursor
```

Əgər repo üzərində lokal development qurmaq istəyirsənsə:

```powershell
git clone https://github.com/20hajiyev/packet-tracer-skill.git
cd .\packet-tracer-skill
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

### Quraşdırmanı yoxlama

Skill-in gözlənilən host yoluna yazıldığını yoxlamaq üçün:

```powershell
npx github:20hajiyev/packet-tracer-skill --verify
npx github:20hajiyev/packet-tracer-skill --verify --cursor
npx github:20hajiyev/packet-tracer-skill --verify --path .agents/skills
```

Əgər lokal clone ilə işləyirsənsə:

```powershell
node .\bin\packet-tracer-skill.js --verify
python .\scripts\install_skill.py --host codex --force
```

### Runtime tələblərini yoxlama

Repository-nin quraşdırılması ilə runtime hazırlığı eyni şey deyil.

- `install` skill fayllarını kopyalayır
- `doctor` real `.pkt` generasiya üçün sistem tələblərini yoxlayır

İşlət:

```powershell
npx github:20hajiyev/packet-tracer-skill --doctor
```

Yoxladığı şeylər:

- `node`
- `python`
- `python_version`
- `python_support_status`
- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_TARGET_VERSION`
- `PACKET_TRACER_COMPAT_DONOR`
- donor faylının target Packet Tracer versiyası ilə uyğun olub-olmaması
- `resolved_twofish_path`
- `twofish_load_status`
- `twofish_sha256`

### Runtime konfiqurasiyası

Real `.pkt` generate etməzdən əvvəl lokal Packet Tracer mühitini qur:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\path\to\your-working-9.0-donor.pkt'
$env:PKT_TWOFISH_LIBRARY="$env:USERPROFILE\.codex\skills\pkt\scripts\vendor\_twofish.cp314-win_amd64.pyd"
```

Əsas environment dəyişənləri:

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`

Donor siyasəti:

- `PACKET_TRACER_COMPAT_DONOR` explicit override kimi qalır
- o verilməyibsə, repo lokal yayğın qovluqlarda uyğun Packet Tracer 9.0 donorunu avtomatik axtarmağa çalışır
- o verilibsə və səhvdirsə, repo səssizcə başqa donora keçmir

Məcburi qayda:

- `PACKET_TRACER_TARGET_VERSION` dəyərini `9.0.0.0810` saxla
- onu `5.3.0.0011`-ə dəyişmə
- strict 9.0 generate axınını keçmək üçün köhnə `5.3` donor və ya template fallback istifadə etmə
- donor yoxdursa və ya versiyası uyğun deyilsə, axını aşağı versiyaya salma; əvvəl donor problemini düzəlt

Host qeydi:

- host prosesi eyni `PACKET_TRACER_*` və `PKT_TWOFISH_LIBRARY` environment dəyişənlərini görməlidir
- bu qayda bütün host-lara aiddir: Codex, Cursor, Claude Code, Claude Desktop, Antigravity, Gemini CLI, Kiro və oxşar alətlər
- əgər host wrapper child-process yoxlamasını bloklayırsa, donorun özünü birbaşa yoxlamaq üçün lokal clone daxilində `python .\scripts\donor_diagnostics.py` işlət

Twofish binary-ni hara qoymaq olar:

- tövsiyə olunan yol: `_twofish.cp314-win_amd64.pyd` faylını quraşdırılmış skill qovluğundakı `scripts/vendor/twofish.py` faylının yanına qoy
- override yolu: `PKT_TWOFISH_LIBRARY` dəyişəni ilə həmin lokal binary-nin dəqiq yolunu göstər
- `C:\tools\pkt-twofish\...` kimi placeholder path yalnız həmin fayl doğrudan da orada olduqda işləyəcək

### Bu repo nə edir

- Azərbaycan dili + İngilis dili qarışıq prompt-ları parse edir
- açıq `IntentPlan`, `TopologyPlan` və `ConfigPlan` qurur
- Cisco lokal donorlarını capability və topology uyğunluğuna görə sıralayır
- Packet Tracer 9.x uyğunluğu üçün donor-prune adaptasiyası istifadə edir
- mövcud `.pkt` lab-ları edit edir
- VLAN, router-on-a-stick, DHCP, DNS, Telnet, ACL, wireless/AP-client və department/campus layout-larını dəstəkləyir
- generate-dən əvvəl planı `--explain-plan` ilə göstərir

### Explain-plan çıxışı

`--explain-plan` aşağıdakı blokları qaytarır:

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

Bu, prompt keyfiyyətini debug etmək üçün əsas çıxışdır.

### Xarici reference workflow

Xarici `.pkt` kolleksiyaları əvvəlcə lokal qovluqda olmalıdır. Tool internetdən
scrape etmir və GitHub URL-lərini birbaşa donor kimi istifadə etmir.

Workflow:

1. xarici repo-nu lokalda klonla və ya kopyala
2. həmin qovluğu `--reference-root` ilə ver
3. `--explain-plan` nəticəsində `external_reference_patterns`-ə bax

Nümunə:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --reference-root C:\labs\external-pkt-samples
```

### Tez-tez istifadə olunan komandalar

Cisco sample catalog qurmaq:

```powershell
python .\scripts\build_sample_catalog.py
```

Sadə prompt üçün explain-plan:

```powershell
python .\scripts\generate_pkt.py --explain-plan "3 dene switch ve 6 komputer"
```

Campus prompt üçün donor-prune explain-plan:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun"
```

`.pkt` yaratmaq:

```powershell
python .\scripts\generate_pkt.py --prompt "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun" --output .\output\campus.pkt --xml-out .\output\campus.xml
```

Mövcud `.pkt` haqqında inventory çıxarmaq:

```powershell
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt
```

`.pkt` decode etmək:

```powershell
python .\scripts\generate_pkt.py --decode .\output\campus.pkt --xml-out .\output\campus.xml
```

### Tələblər

- Windows
- lokalda quraşdırılmış Cisco Packet Tracer 9.x
- lokal Cisco Packet Tracer sample save-ləri
- lokal Packet Tracer 9.x donor labı
- Python runtime ilə uyğun lokal Twofish bridge

Python setup:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

### Twofish bridge

Bu public repo default olaraq prebuilt Twofish binary ilə gəlmir.

Bu qəsdəndir:

- machine-specific binary paylaşılmır
- unsigned lokal artefakt təsadüfən publish olunmur
- private path və build izi paylaşılmır

Lokal setup üçün `scripts/vendor/README.md` faylına bax.

### Tez-tez rast gəlinən xətalar

- `PACKET_TRACER_COMPAT_DONOR set but missing`
  - donor üçün verilmiş yol mövcud deyil
  - ya yolu düzəlt, ya da dəyişəni sil ki, repo donor auto-detect etsin
- `PACKET_TRACER_COMPAT_DONOR_VERSION version_mismatch`
  - donor faylı var, amma `9.0.0.0810` deyil
  - problemi `5.3.0.0011`-ə düşməklə həll etmə
- `TWOFISH_LOAD_STATUS missing`
  - lokal bridge tapılmadı
  - `_twofish.cp314-win_amd64.pyd` faylını `scripts/vendor/twofish.py` yanına qoy və ya `PKT_TWOFISH_LIBRARY` göstər
- `PYTHON_SUPPORT_STATUS unsupported`
  - runtime Python `3.14.x` deyil
  - Python 3.14 qur və `--doctor` yoxlamasını yenidən işlə

### Screenshot

Cisco Packet Tracer-də açılmış generated campus topology:

![Packet Tracer topology](docs/screenshots/packet-tracer-topology-cropped.png)

### Təhlükəsizlik və məxfilik

Repo lokal private məlumatların təsadüfən paylaşılmaması üçün hazırlanıb:

- hardcoded donor path commit olunmur
- `C:\Users\<name>\...` donor path config-ə yazılmır
- generated `.pkt` və `.xml` faylları gitignore-dadır
- Python cache faylları gitignore-dadır
- Twofish bridge binary-ləri gitignore-dadır

Public paylaşmazdan əvvəl bunları yoxla:

- `PACKET_TRACER_COMPAT_DONOR` yalnız sənin lokal env-ində olsun
- paylaşmaq istəmədiyin generated lab-ları commit etmə
- build etdiyin bridge binary-ni audit etməmisənsə commit etmə

### Cari limitlər

- yalnız Packet Tracer 9.x
- Windows-first workflow
- donor-prune generate donor capacity ilə məhduddur
- xarici lab-lar donor kimi istifadə olunmur
- bundled template coverage qəsdən limitlidir

### Lisenziya

Bu layihə MIT License ilə paylaşılır.
