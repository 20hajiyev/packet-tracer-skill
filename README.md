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
- imported external labs are reference-only by default
- curated external donor roots can become donor-eligible after validation
- prompt parsing happens before generation
- generation uses donor-prune adaptation for compatibility
- unsafe requests return `blocking_gaps` instead of guessed output

### Host Support

Use the same repository, then install it into the skill path your host expects.

| Tool | Install | First Use |
| --- | --- | --- |
| Claude Code | `npx packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Claude Desktop | `npx packet-tracer-skill --path <claude-desktop-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx packet-tracer-skill --path <antigravity-skills-dir>` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx packet-tracer-skill --kiro` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | Copy this repo into your local prompts/rules/skills docs | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx packet-tracer-skill --path ./my-skills` | Depends on your tool |

### Platform Support

The installer command can be used on more than one OS, but real Packet Tracer
runtime support is narrower right now.

| Platform | Installer / skill copy | Real `.pkt` decode/generate/edit runtime |
| --- | --- | --- |
| Windows | Supported | Supported |
| macOS | Partially supported | Not supported yet |
| Linux | Partially supported | Not supported yet |

Current reason:

- the current local Twofish bridge is Windows-only: `_twofish.cp314-win_amd64.pyd`
- donor auto-detection and runtime assumptions are still Windows-first
- Packet Tracer runtime validation has only been hardened against the Windows 9.0 workflow so far

If you run this on macOS or Linux today, installation may work, but `doctor`
should be treated as the authority for whether real `.pkt` generation is ready.

### Quick Start

Default install for Codex:

```powershell
npx packet-tracer-skill
```

That already installs everything shipped inside this repository.

If you want one command that installs everything this repository can install by
itself, use bootstrap:

```powershell
npx packet-tracer-skill --bootstrap
```

That command:

- installs the skill into the selected host path
- creates a local `.venv` inside the installed skill directory
- installs declared Python requirements from this repository
- shows runtime doctor output with concrete next-step guidance for donor and Twofish setup

It still does not install Cisco Packet Tracer itself.

Common targets:

```powershell
npx packet-tracer-skill --path <claude-desktop-skills-dir>
npx packet-tracer-skill --cursor
npx packet-tracer-skill --claude
npx packet-tracer-skill --kiro
```

If PowerShell blocks `npx.ps1`, use:

```powershell
cmd /c npx packet-tracer-skill --cursor
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
npx packet-tracer-skill --verify
npx packet-tracer-skill --verify --cursor
npx packet-tracer-skill --verify --path .agents/skills
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
npx packet-tracer-skill --doctor
```

The doctor output also prints recommended next steps when runtime pieces are missing.
On supported hosts it also prints suggested environment variable examples for your OS.

It checks:

- `host_os`
- `installer_support`
- `real_pkt_runtime_support`
- `node`
- `python`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `python_version`
- `python_support_status`
- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_TARGET_VERSION`
- `PACKET_TRACER_COMPAT_DONOR`
- donor version compatibility with the target Packet Tracer version
- `resolved_twofish_path`
- `twofish_load_status`
- `twofish_sha256`
- `twofish_expected_patterns`
- `twofish_search_roots`

Direct Python diagnostic:

```powershell
python .\scripts\runtime_doctor.py
```

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
- `PKT_TWOFISH_SEARCH_ROOTS`

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
- if a host wrapper blocks child-process inspection, run `python .\scripts\runtime_doctor.py` from a local clone to verify runtime readiness directly

Where to place the Twofish binary:

- preferred: put `_twofish.cp314-win_amd64.pyd` next to `scripts/vendor/twofish.py` inside the installed skill folder
- override: set `PKT_TWOFISH_LIBRARY` to the exact local binary path
- optional: set `PKT_TWOFISH_SEARCH_ROOTS` to one or more local directories separated by your OS path separator
- do not point `PKT_TWOFISH_LIBRARY` at a placeholder path such as `C:\tools\pkt-twofish\...` unless that file actually exists

Non-Windows bridge naming contract:

- macOS: `_twofish.cp314-macos*.dylib`
- Linux: `_twofish.cp314-linux*.so`
- run `python .\scripts\runtime_doctor.py` to see the exact expected patterns and current search roots on your machine

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
- `curated_external_donor_candidates`
- `external_reference_patterns`
- `capability_matrix_hits`
- `coverage_gaps`
- `blueprint_plan`
- `remote_search_results`
- `assumptions_used`

This is the main debugging surface for prompt quality.

### External Reference Workflow

External `.pkt` collections must be local first. This tool does not scrape the
internet and does not use GitHub URLs directly as donors.

Workflow:

1. clone or copy the external repo locally
2. pass that folder with `--reference-root`
3. inspect `external_reference_patterns` in `--explain-plan`

Optional remote discovery can search GitHub first, then auto-import matching
repos into a local cache before cataloging them:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 department campus with vlan dhcp dns ap" --search-remote --remote-provider github --import-cache-root .\output\remote-cache
```

Remote discovery is multi-source search only. Final `.pkt` apply still uses one
validated donor.

Example:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --reference-root C:\labs\external-pkt-samples
```

### Curated External Donor Workflow

If you trust a local external lab collection technically, pass it with
`--donor-root`.

Workflow:

1. clone or copy the external repo locally
2. pass that folder with `--donor-root`
3. only validated Packet Tracer `9.0.0.0810` labs become donor-eligible
   - direct `logical_status=ok` and `physical_status=ok` labs pass
   - `legacy_uuid_physical` labs also pass when their only logical warnings are repeated `MEM_ADDR` mismatches
4. Cisco local donors still rank ahead of curated external donors

If no safe donor fits, generation refuses cleanly and can emit a blueprint:

```powershell
python .\scripts\generate_pkt.py --prompt "6 department campus with vlan dns ap" --output .\output\campus.pkt --blueprint-out .\output\campus-blueprint.json
```

Example:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --donor-root C:\labs\curated-pkt-donors --reference-root C:\labs\external-pkt-samples
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

Show the aggregated capability matrix:

```powershell
python .\scripts\generate_pkt.py --coverage-report
python .\scripts\generate_pkt.py --coverage-report --device-family "access points"
```

Generate a `.pkt`:

```powershell
python .\scripts\generate_pkt.py --prompt "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun" --output .\output\campus.pkt --xml-out .\output\campus.xml
```

Inspect an existing `.pkt`:

```powershell
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt --inventory-capabilities
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt --inventory-capabilities --inventory-out .\examples\lab.inventory.json
```

### Curated Examples

The repo keeps public example artifacts as text-first manifests instead of raw `.pkt` binaries.

| Example | Family | What it demonstrates |
| --- | --- | --- |
| `complex_campus_master_edit_v4` | `campus` | Management VLAN, Telnet, ACL, DNS, email, AAA, and wireless SSID edits |
| `home_iot_cli_edit_v1` | `home_iot` | Home gateway and IoT registration state |
| `service_heavy_cli_edit_v1` | `service_heavy` | DNS, DHCP, FTP, email, syslog, AAA service metadata |

Gallery index:

```powershell
Get-Content .\examples\index.json
```

Edit an existing `.pkt` from a prompt:

```powershell
python .\scripts\generate_pkt.py --edit .\input\lab.pkt --prompt "set Wireless Router0 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6 associate PC0 to Wireless Router0 ssid FIN_WIFI dhcp" --output .\output\edited_lab.pkt --xml-out .\output\edited_lab.xml
python .\scripts\generate_pkt.py --edit .\input\lab.pkt --prompt "enable dns on Server0 set Server0 dns A www.example.local 192.168.10.20 set PC0 dns 192.168.10.20" --output .\output\edited_services.pkt
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
- non-Windows custom bridges should follow the runtime doctor pattern contract:
  - macOS: `_twofish.cp314-macos*.dylib`
  - Linux: `_twofish.cp314-linux*.so`
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

![Packet Tracer topology](examples/screenshots/complex_campus_master_edit_v4.png)

### Security and Privacy

This repo is prepared to avoid accidental sharing of local private material:

- no hardcoded donor path is committed
- no `C:\Users\<name>\...` donor path is baked into config
- generated `.pkt` and `.xml` files are gitignored
- public sample labs should be committed as inventory JSON or blueprint JSON, not raw `.pkt` binaries
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
| Claude Code | `npx packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Claude Desktop | `npx packet-tracer-skill --path <claude-desktop-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx packet-tracer-skill --path <antigravity-skills-dir>` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx packet-tracer-skill --kiro` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | Bu repo-nu lokal prompts/rules/skills docs qovluğuna köçür | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx packet-tracer-skill --path ./my-skills` | Host-a görə dəyişir |

### Platforma dəstəyi

Quraşdırma komandası bir neçə əməliyyat sistemində işləyə bilər, amma real
Packet Tracer runtime dəstəyi hələ daha dardır.

| Platforma | Installer / skill copy | Real `.pkt` decode/generate/edit runtime |
| --- | --- | --- |
| Windows | Dəstəklənir | Dəstəklənir |
| macOS | Qismən dəstəklənir | Hələ dəstəklənmir |
| Linux | Qismən dəstəklənir | Hələ dəstəklənmir |

Cari səbəblər:

- indiki lokal Twofish bridge yalnız Windows üçündür: `_twofish.cp314-win_amd64.pyd`
- donor auto-detect və runtime fərziyyələri hələ Windows-first qurulub
- Packet Tracer runtime validation hələ yalnız Windows 9.0 iş axını üçün sərtləşdirilib

Yəni bu repo macOS və ya Linux-da quraşdırıla bilər, amma real `.pkt`
generasiya mühitinin hazır olub-olmadığını əsasən `doctor` nəticəsi göstərir.

### Sürətli başlanğıc

Codex üçün standart quraşdırma:

```powershell
npx packet-tracer-skill
```

Bu komanda repository daxilində olan bütün faylları quraşdırır.

Əgər repository-nin quraşdıra bildiyi hər şeyi bir komandada qurmaq
istəyirsənsə, `bootstrap` istifadə et:

```powershell
npx packet-tracer-skill --bootstrap
```

Bu komanda:

- skill-i seçilmiş host yoluna quraşdırır
- quraşdırılmış skill qovluğunda lokal `.venv` yaradır
- repository-də elan edilmiş Python tələblərini quraşdırır

Amma Cisco Packet Tracer-in özünü quraşdırmır.

Tez-tez lazım olan digər variantlar:

```powershell
npx packet-tracer-skill --path <claude-desktop-skills-dir>
npx packet-tracer-skill --cursor
npx packet-tracer-skill --claude
npx packet-tracer-skill --kiro
```

Əgər PowerShell `npx.ps1` faylını bloklayırsa:

```powershell
cmd /c npx packet-tracer-skill --cursor
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
npx packet-tracer-skill --verify
npx packet-tracer-skill --verify --cursor
npx packet-tracer-skill --verify --path .agents/skills
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
npx packet-tracer-skill --doctor
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

![Packet Tracer topology](examples/screenshots/complex_campus_master_edit_v4.png)

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
- installer/CLI qatını Windows, macOS və Linux üçün saxlaya bilərik
- real `.pkt` generate/edit runtime hazırda yalnız Windows-da acceptance-verified-dir
- macOS və Linux-da real runtime yalnız custom Packet Tracer path və uyğun native Twofish bridge (`.so` / `.dylib`) ilə nəzəri olaraq mümkündür; repo bunu hazır binary kimi vermir
- donor-prune generate donor capacity ilə məhduddur
- xarici lab-lar donor kimi istifadə olunmur
- bundled template coverage qəsdən limitlidir

### Lisenziya

Bu layihə MIT License ilə paylaşılır.
