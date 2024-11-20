FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN echo "==> Upgrading apk and installing system utilities ...." \
  && apt -y update \
  && apt-get install -y wget \
  && apt-get -y install sudo

RUN echo "==> Installing Python3 and pip ...." \  
  && apt-get install python3 -y \
  && apt install python3-pip -y

RUN echo "==> Install dos2unix..." \
  && sudo apt-get install dos2unix -y 

RUN echo "==> Install langchain requirements.." \
  && pip install --break-system-packages langchain_experimental==0.3.3 \
  && pip install --break-system-packages langchain==0.3.7 \
  && pip install --break-system-packages langchain-community==0.3.7 \
  && pip install --break-system-packages langchain-openai==0.2.9 \
  && pip install --break-system-packages langchain-ollama==0.2.0 \
  && pip install --break-system-packages chromadb==0.5.20 \
  && pip install --break-system-packages tiktoken

RUN echo "==> Install jq.." \
  && pip install --break-system-packages jq

RUN echo "==> Install streamlit.." \
  && pip install --break-system-packages streamlit --upgrade

# Other pip install commands similarly updated

# Install tshark
RUN apt-get update && apt-get install -y tshark

RUN echo "==> Adding pyshark ..." \
  && pip install --break-system-packages pyshark

RUN echo "==> Adding requests ..." \
  && pip install --break-system-packages requests==2.32.3

RUN echo "==> Adding InstructorEmbedding ..." \
  && pip install --break-system-packages -U sentence-transformers==3.3.1 

COPY /packet_buddy /packet_buddy/
COPY /scripts /scripts/

RUN echo "==> Convert script..." \
  && dos2unix /scripts/startup.sh\
  && dos2unix /scripts/start.sh

CMD ["/bin/bash", "/scripts/startup.sh"]