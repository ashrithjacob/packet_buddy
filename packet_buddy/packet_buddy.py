import os
import json
import requests
import subprocess
from langchain import hub
import streamlit as st
from langchain_community.embeddings import HuggingFaceInstructEmbeddings
from langchain_openai import OpenAIEmbeddings, OpenAI, ChatOpenAI
from langchain_community.document_loaders import JSONLoader
from langchain_experimental.text_splitter import SemanticChunker
from langchain_community.vectorstores import Chroma
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_ollama.llms import OllamaLLM
from langchain_core.documents import Document
from dotenv import load_dotenv

load_dotenv()


OLLAMA_URL = "http://ollama:11434/"  # Corrected URL


# Message classes
class Message:
    def __init__(self, content):
        self.content = content


class HumanMessage(Message):
    """Represents a message from the user."""

    pass


class AIMessage(Message):
    """Represents a message from the AI."""

    pass


def get_json_path(pcap_file):
    current_path = os.getcwd()
    pcap_path = os.path.join(current_path, pcap_file)
    json_path = pcap_path.split(".")[0] + ".json"
    return pcap_path, json_path


# Function to convert pcap to JSON
def pcap_to_json(pcap_path, json_path):
    command = f"tshark -nlr {pcap_path} -T json > {json_path}"
    subprocess.run(command, shell=True)


def get_ollama_models(base_url):
    try:
        response = requests.get(f"{base_url}api/tags")  # Corrected endpoint
        response.raise_for_status()
        models_data = response.json()

        # Extract just the model names for the dropdown
        models = [model["name"] for model in models_data.get("models", [])]
        return models
    except requests.exceptions.RequestException as e:
        print(f"Failed to get models from Ollama: {e}")
        return []


# Define a class for chatting with pcap data
class ChatWithPCAP:
    def __init__(self, json_path, model):
        self.embedding_model = self.load_model()
        self.json_path = json_path
        self.llm = self.get_llm(model)
        self.conversation_history = []
        self.runner()

    def get_llm(self, model):
        if model.startswith("OPENAI"):
            return ChatOpenAI(model_name="gpt-4o", max_tokens=10000)
        else:
            return OllamaLLM(model=model, url=OLLAMA_URL)

    def runner(self):
        self.load_json()
        self.split_into_chunks()
        self.store_in_chroma()
        self.setup_conversation_retrieval_chain()

    def load_model(self):
        embedding_model = OpenAIEmbeddings(api_key=os.getenv("OPENAI_API_KEY"))
        return embedding_model

    def get_system_prompt(self):
        PACKET_WHISPERER = f"""
        You are a helper assistant specialized in analysing packet captures used for troubleshooting & technical analysis. Use the information present in packet_capture_info to answer all the questions truthfully. If the user asks about a specific application layer protocol, use the following hints to inspect the packet_capture_info to answer the question. Format your response in markdown text with line breaks & emojis.

        hints :
        http means tcp.port = 80
        https means tcp.port = 443
        snmp means udp.port = 161 or udp.port = 162
        ntp means udp.port = 123
        ftp means tcp.port = 21
        ssh means tcp.port = 22
        BGP means tcp.port = 179
        OSPF uses IP protocol 89 (not TCP/UDP port-based, but rather directly on top of IP)
        MPLS doesn't use a TCP/UDP port as it's a data-carrying mechanism for high-performance telecommunications networks
        DNS means udp.port = 53 (also tcp.port = 53 for larger queries or zone transfers)s
        DHCP uses udp.port = 67 for the server and udp.port = 68 for the client
        SMTP means tcp.port = 25 (for email sending)
        POP3 means tcp.port = 110 (for email retrieval)
        IMAP means tcp.port = 143 (for email retrieval, with more features than POP3)
        HTTPS means tcp.port = 443 (secure web browsing)
        LDAP means tcp.port = 389 (for accessing and maintaining distributed directory information services over an IP network)
        LDAPS means tcp.port = 636 (secure version of LDAP)
        SIP means tcp.port = 5060 or udp.port = 5060 (for initiating interactive user sessions involving multimedia elements such as video, voice, chat, gaming, etc.)
        RTP (Real-time Transport Protocol) doesn't have a fixed port but is commonly used in conjunction with SIP for the actual data transfer of audio and video streams.
        """
        # Might be redundant - pcap data - alraedy doing rag - less tokens
        return PACKET_WHISPERER

    def load_json(self):
        self.loader = JSONLoader(
            file_path=self.json_path,
            jq_schema=".[] | ._source.layers",
            text_content=False,
        )
        self.pages = self.loader.load_and_split()

    def split_into_chunks(self):
        self.text_splitter = SemanticChunker(self.embedding_model)
        self.docs = self.text_splitter.split_documents(self.pages)

    def store_in_chroma(self):
        with st.spinner("Storing in Chroma..."):
            self.vectordb = Chroma.from_documents(self.docs, self.embedding_model)

    def format_docs(self, docs):
        return "\n\n".join(doc.page_content for doc in docs)

    def setup_conversation_retrieval_chain(self):
        self.retriever = self.vectordb.as_retriever()
        self.prompt = hub.pull("rlm/rag-prompt")
        rag_chain = (
            {
                "context": self.retriever | self.format_docs,
                "question": RunnablePassthrough(),
            }
            | self.prompt
            | self.llm
            | StrOutputParser()
        )
        # self.qa = ConversationalRetrievalChain.from_llm(self.llm, self.vectordb.as_retriever(search_kwargs={"k": 10}))
        self.qa = rag_chain

    def chat(self, question):
        # Combine the original question with the priming text
        primed_question = self.get_system_prompt() + "\n\n" + question
        response = self.qa.invoke(primed_question)

        if response:
            return {"answer": response}


# Streamlit UI for uploading and converting pcap file
def upload_and_convert_pcap():
    st.title("Packet Buddy - Chat with Packet Captures")
    uploaded_file = st.file_uploader("Choose a PCAP file", type="pcap")
    if uploaded_file:
        if not os.path.exists("temp"):
            os.makedirs("temp")
        pcap_path = os.path.join("temp", uploaded_file.name)
        json_path = pcap_path.split(".")[0] + ".json"
        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        pcap_to_json(pcap_path, json_path)
        st.session_state["json_path"] = json_path
        st.success("PCAP file uploaded and converted to JSON.")
        # Fetch and display the models in a select box
        models = get_ollama_models(OLLAMA_URL)  # Make sure to use the correct base URL
        models.append("OPENAI:gpt-4o")
        if models:
            selected_model = st.selectbox("Select Model", models)
            st.session_state["selected_model"] = selected_model

            if st.button("Proceed to Chat"):
                st.session_state["page"] = 2


# Streamlit UI for chat interface
def chat_interface():
    st.title("Packet Buddy - Chat with Packet Captures")
    json_path = st.session_state.get("json_path")
    if not json_path or not os.path.exists(json_path):
        st.error(
            "PCAP file missing or not converted. Please go back and upload a PCAP file."
        )
        return

    chat_bot = ChatWithPCAP(json_path, st.session_state["selected_model"])

    user_input = st.text_input("Ask a question about the PCAP data:")
    if user_input and st.button("Send"):
        with st.spinner("Thinking..."):
            response = chat_bot.chat(user_input)
            st.markdown("**Synthesized Answer:**")
            if isinstance(response, dict) and "answer" in response:
                st.markdown(response["answer"])
            else:
                st.markdown("No specific answer found.")

            st.markdown("**Chat History:**")
            for message in chat_bot.conversation_history:
                prefix = "*You:* " if isinstance(message, HumanMessage) else "*AI:* "
                st.markdown(f"{prefix}{message.content}")


if __name__ == "__main__":
    if "page" not in st.session_state:
        st.session_state["page"] = 1

    if st.session_state["page"] == 1:
        upload_and_convert_pcap()
    elif st.session_state["page"] == 2:
        chat_interface()
