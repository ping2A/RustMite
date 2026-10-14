# Agentless probe/loader ELFs

Place musl-static `rustmite-probe` and `rustmite-loader` here before
`./scripts/share-image.sh` so the appliance image ships all four arches:

```text
docker/share/probes/x86_64/{rustmite-probe,rustmite-loader}
docker/share/probes/i686/{rustmite-probe,rustmite-loader}
docker/share/probes/aarch64/{rustmite-probe,rustmite-loader}
docker/share/probes/armv7/{rustmite-probe,rustmite-loader}
```

Build locally:

```bash
cargo xtask build-probes --all
# then copy from target/<triple>/probe/ into the dirs above
```

If a pair is missing, the Dockerfile `cargo zigbuild`s that target during image build.
The ELFs themselves are gitignored (generated artifacts).
