# XML Skeleton Notes

The builder uses a `PACKETTRACER5` root and organizes generated content under a
`NETWORK` node with `DEVICES`, `LINKS`, and `SHAPETESTS`.

## Base Document Shape

```xml
<PACKETTRACER5>
  <VERSION>9.0.0.0810</VERSION>
  <PIXMAPBANK />
  <MOVIEBANK />
  <NETWORK>
    <DEVICES />
    <LINKS />
    <SHAPETESTS />
  </NETWORK>
  <OPTIONS />
  <PHYSICALWORKSPACE />
</PACKETTRACER5>
```

## Template Strategy

This skill does not attempt to synthesize the entire Cisco-internal XML schema from
scratch. Instead, it uses:

- a stable base XML document
- per-device XML templates
- targeted placeholder replacement for names, models, positions, ports, and configs

## Current Supported Device Templates

- `router.xml`
- `switch.xml`
- `pc.xml`

Each template includes:

- a generated device id
- human-readable device name
- type and model fields
- layout coordinates
- a config section appropriate for the device family
