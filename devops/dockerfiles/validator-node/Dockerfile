FROM mangatasolutions/mangata-node:latest AS node-base

RUN apt-get update && apt-get install -y curl jq

WORKDIR /mangata

RUN echo "====> Installing subkey..."
RUN curl https://mangata-space.fra1.digitaloceanspaces.com/subkey -o /usr/bin/subkey && chmod +x /usr/bin/subkey

RUN echo "====> Preparing image..."
COPY ./scripts/initialize_validator_node.sh .
RUN curl https://mangata-space.fra1.digitaloceanspaces.com/nodekeygen-linux-amd64-lite -o /usr/bin/node-keygen && chmod +x /usr/bin/node-keygen
ENTRYPOINT ["/usr/bin/env", "bash", "/mangata/initialize_validator_node.sh"]