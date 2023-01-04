FROM debian

RUN apt update && apt upgrade -y && \
    apt install -y python libgmp3-dev npm pip && \
    pip3 install cairo-lang==0.8.2 && \
    npm install -g snarkjs

COPY verifier_groth16.cairo  /home
COPY playground.cairo  /home
COPY multiplier2_0001.zkey /home
COPY Makefile /home
COPY proof.json /home
COPY public.json /home

WORKDIR /home
