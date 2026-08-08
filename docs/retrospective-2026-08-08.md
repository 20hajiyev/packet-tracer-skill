# Retrospective — the session that measured, mis-measured, and finally went upstream

Scope: continuous work on `packet-tracer-skill`, ending with a request to build a
wide corporate network **with the skill**. Written 2026-08-08.

## Against the plan

| | planned | actual |
|---|---|---|
| Workstream 1 — topology from the requirement | first | still open, but its real blocker is now named |
| Workstream 2 — arbitrary CLI | second | done and verified earlier |
| Workstream 3 — device and cable coverage | third | wireless labs cabled and pinging; 17 device kinds in one lab |
| Corpus | 33 prompts | 32/33 generated, 32/32 open |
| Tests | 706 at session start | 721, zero failures |
| Connectivity | never measured | 14 of 14 labs verified by live ping |

## What went well — repeat these

**Live measurement over static signals.** Every real defect this session was found
by pinging, never by a check that reads the file. The corpus reported 32/32 for
labs that could not pass a packet.

**Reverting a commit whose evidence collapsed.** The VLAN-declaration pass looked
right, was tested, and shipped. When the A/B pair showed the lab worked without
it, it went back out (`f415dac`). Keeping it "because it is probably harmless"
would have left a false explanation in the code for the next reader.

**Building the missing donor rather than narrowing the request.** The company lab
was blocked because no donor had five populated switch groups. Making one is what
unblocked it, and it turned two skill defects into visible failures.

## What went wrong — root causes, not symptoms

### 1. I shipped a fix built on a broken instrument

Five whys:
1. The VLAN-declaration pass was committed. Why? `corpus_server_lan` went 0/4 → 4/4.
2. Why was that reading wrong? Two Packet Tracer windows were open and the MCP
   bridge kept answering for the first one.
3. Why did that go unnoticed? `pt_open_project` reported the new file correctly;
   only the query channel was stale.
4. Why did I trust it? It had been reliable, so I never checked what document the
   answer described.
5. **Root cause: the measurement protocol had no verification step of its own.**

Fixed: every connectivity reading is now preceded by `pt_query_topology` and
accepted only if the device names and addresses match the intended file; a
warm-up ping is discarded because the first ping after opening always fails.
Recorded as a durable memory.

### 2. I patched four symptoms before asking what produced them

The company lab failed, and each measurement pointed at the next thing to fix:
hosts in the wrong VLAN → router port not a trunk → subinterfaces on an uncabled
interface → gateway address stranded on the physical port. Four passes, each
justified by a measurement, none of them the cause.

The cause took one command to find once I asked a different question — not "what
is wrong now?" but "which pass wrote this?":

```
_router_port({'model': '2911'}) -> 'FastEthernet0/0'
```

A 2911 has `GigabitEthernet0/0` .. `0/2` and no FastEthernet at all. The name is
invalid, so the port repair relocates the cable to the first free valid
interface — `GigabitEthernet0/0`, the WAN uplink — while the router-on-a-stick
subinterfaces stay on `GigabitEthernet0/1`, which no cable reaches. The table
knew `2901` and `ISR` and guessed FastEthernet for everything else.

**Root cause: symptom-driven debugging.** The correct move, after the second
downstream fix failed to produce connectivity, was to walk back to the pass that
wrote the state rather than to write a third repair.

### 3. The same defect shape has now appeared eight times

Cable type vs port names. Catalogue vs saved-file port names. Blueprint names vs
donor names. Interface-name list vs PORT nodes. Socket count vs port names on a
home router. Host IP subnet vs port VLAN. Router subinterface vs cabled port.
Device type spelled `Pc` in files and `PC` in code.

Eight instances is not bad luck. **Root cause: the same fact is derived
independently in more than one place, and nothing compares the derivations.**

## Actions

| # | Action | Why it is the right lever |
|---|---|---|
| 1 | A consistency pass over every generated lab that compares the paired models — host address vs port VLAN, router subinterface vs cabled port, port name vs device ports, cable media vs socket media — and reports disagreements as warnings | Turns the recurring defect shape from something found by luck into something the pipeline states out loud |
| 2 | Add a connectivity stage to the corpus so "works" is a number, not an anecdote | 32/32 open told us nothing about whether any lab functioned |
| 3 | When two repairs in a row fail to produce the measured outcome, stop repairing and find the pass that wrote the state | The rule that would have saved most of this session |
| 4 | Derive router and switch interface names from the device, not from a model-prefix table | The table will keep going stale as models are added |

## Learnings worth keeping

- An unreliable instrument does not announce itself. Verify what the instrument
  is describing before believing what it says.
- A green static check, an opening file, and a correct-looking configuration are
  three different things, and none of them is a working network.
- Two repairs deep without the measured outcome moving is the signal to go
  upstream, not the signal to write a third repair.

## Addendum — the same lesson, a third time

DHCP looked broken twice and was not. Reading a client's address immediately
after opening a lab shows `0.0.0.0`, because the lease has not completed yet;
reading it again a few seconds later shows the address. The control settled
it: `corpus_router_dhcp`, which is known to work, reads `0.0.0.0` on the first
look too.

That is the same shape as the cold-ARP ping and the stuck bridge: **the first
observation after opening a document is not a measurement.** The protocol now
has three parts, not two — verify the document, discard the first reading,
then measure — and it applies to every property, not only to pings.

Measured on the generated company lab once the leases completed: PC9, PC5 and
PC1 on 10.10.10.100/.101/.102, PC10, PC6 and PC2 on 10.10.20.100/.101/.102,
PC8 and PC4 on 10.10.50.100/.101 -- all from the pools, with the servers still
on .50 and the printers on .60 where the exclusions keep them.
