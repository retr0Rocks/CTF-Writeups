FROM pwn.red/jail

COPY --from=ubuntu@sha256:144e6a778925a0c11c4cd9fe5fce1172e620f215b0410bb43e7fa41bbcfe4522 / /srv

COPY main /srv/app/run

COPY flag.txt /srv/app/

EXPOSE 1337
