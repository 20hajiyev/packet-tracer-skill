# Donor drop-in directory

Any `.pkt` placed here is searched first when the skill looks for a generation
base, ahead of your Downloads, Documents and Desktop and ahead of the labs
Packet Tracer installs.

It is empty on purpose. `tests/test_release_surface.py` asserts that no `.pkt`
ships in the npm package, so a donor cannot simply be bundled without that
decision being made deliberately -- a `.pkt` is written by Packet Tracer, and
redistributing one is a licensing question rather than a packaging one.

What this directory is for meanwhile: drop a lab here and every generation can
draw on it. A useful one carries a switch with two or three hosts cabled to it
-- donor-prune reuses the hosts attached to a switch, so a lab without that
serves nothing -- plus any device kinds you want prompts to be able to ask for.
