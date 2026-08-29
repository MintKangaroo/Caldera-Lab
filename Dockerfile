# Pinned by digest: the lab's isolation claims are only as reproducible as the
# image they run in. Update deliberately, and re-run the CI docker smoke job.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache procps findutils
ENTRYPOINT []
